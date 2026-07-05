package sdjwt

import (
	stdcrypto "crypto"
	"fmt"
)

// reconstruct verifies the disclosures against the issuer payload and returns
// the disclosed claim set (SD-JWT §7-8). It:
//   - indexes disclosures by digest (a duplicate SUPPLIED disclosure raw
//     string → ErrDuplicateDigest);
//   - walks the payload, replacing _sd digests (objects) and "..." wrappers
//     (arrays) with the disclosed values, recursing into disclosed values
//     (recursive disclosures);
//   - rejects any digest string that occurs more than once anywhere in the
//     payload's _sd/"..." positions, whether or not it has a matching
//     disclosure (decoys included) — the digest namespace must stay 1:1
//     payload-wide (ErrDuplicateDigest; see WP-02 README Decisions);
//   - counts digests with no matching disclosure as decoys (silently
//     skipped, SD-JWT privacy feature) — but requires EVERY supplied
//     disclosure to be matched by exactly one digest in the payload
//     (ErrDigestMismatch catches swapped/forged/irrelevant disclosures);
//   - strips _sd/_sd_alg so they never surface as claims;
//   - rejects a disclosed claim name that collides with an existing member
//     or is a reserved key (_sd/...);
//   - rejects a literal "..." object key wherever it is not consumed as a
//     complete {"...": "<digest>"} array-element wrapper — including a plain
//     object member and an array element carrying "..." alongside any other
//     key (SD-JWT §4.2.2 reserves "..." for the wrapper shape only; fail
//     closed, hard rule 7 — see the object() doc comment for the two paths
//     that land here).
func reconstruct(payload map[string]any, disclosures [][]byte, h stdcrypto.Hash) (map[string]any, int, error) {
	w := &walker{
		byDigest: map[string]disclosure{},
		seen:     map[string]bool{},
		used:     map[string]bool{},
	}
	for _, raw := range disclosures {
		d, err := decodeDisclosure(raw)
		if err != nil {
			return nil, 0, err
		}
		dg := digest(raw, h)
		if _, dup := w.byDigest[dg]; dup {
			return nil, 0, fmt.Errorf("%w: duplicate disclosure supplied", ErrDuplicateDigest)
		}
		w.byDigest[dg] = d
	}
	claims, err := w.object(payload)
	if err != nil {
		return nil, 0, err
	}
	for dg := range w.byDigest {
		if !w.used[dg] {
			// A supplied disclosure that no digest in the payload referenced:
			// swapped, forged (salt/value tampered → different digest), or
			// simply irrelevant to this credential.
			return nil, 0, fmt.Errorf("%w", ErrDigestMismatch)
		}
	}
	return claims, w.decoys, nil
}

// walker carries the state threaded through one reconstruction: the supplied
// disclosures indexed by digest, every digest string encountered while
// walking (for duplicate detection), which of the supplied disclosures were
// actually matched, and the decoy count.
type walker struct {
	byDigest map[string]disclosure
	seen     map[string]bool
	used     map[string]bool
	decoys   int
}

// resolve looks up a digest encountered in a _sd array or "..." wrapper. It
// fails closed on a digest seen more than once anywhere in the payload —
// including decoys, since a repeated digest string breaks the 1:1
// digest-to-disclosure mapping the protocol assumes, regardless of whether it
// happens to resolve to a real disclosure (WP-02 README Decisions). found is
// false for a decoy (counted, not an error: SD-JWT §4.2.5 privacy feature).
func (w *walker) resolve(dg string) (d disclosure, found bool, err error) {
	if w.seen[dg] {
		return disclosure{}, false, fmt.Errorf("%w", ErrDuplicateDigest)
	}
	w.seen[dg] = true
	d, found = w.byDigest[dg]
	if found {
		w.used[dg] = true
	} else {
		w.decoys++
	}
	return d, found, nil
}

// value recurses into v if it is a JSON object or array (either may itself
// carry further _sd digests or "..." wrappers); any other JSON type is
// returned unchanged.
func (w *walker) value(v any) (any, error) {
	switch t := v.(type) {
	case map[string]any:
		return w.object(t)
	case []any:
		return w.array(t)
	default:
		return v, nil
	}
}

// object processes one JSON object: copies clear members (recursing into
// each), strips _sd/_sd_alg, and resolves the object's own _sd digests into
// disclosed members (SD-JWT §4.2.1, §7).
func (w *walker) object(m map[string]any) (map[string]any, error) {
	out := make(map[string]any, len(m))
	for k, v := range m {
		if k == claimSD || k == claimSDAlg {
			continue
		}
		if k == claimEllipsis {
			// SD-JWT §4.2.2 reserves "..." exclusively for the array-element
			// digest wrapper ({"...": "<digest>"}), which is consumed entirely
			// inside array() and never reaches this loop. A literal "..." key
			// surviving to here means either (a) it appears directly as a
			// plain object member (not inside an array), or (b) it appeared
			// in an array element alongside another key, so arrayDigest's
			// len(m)==1 check rejected it as a wrapper and array() fell
			// through to recursing into it as ordinary data. Both are
			// ambiguous/adversarial constructs no conformant issuer emits;
			// fail closed rather than surface a claim literally named "..."
			// (hard rule 7).
			return nil, fmt.Errorf("%w: reserved key %q not allowed as an object member", ErrMalformed, claimEllipsis)
		}
		rv, err := w.value(v)
		if err != nil {
			return nil, err
		}
		out[k] = rv
	}
	sd, ok := m[claimSD]
	if !ok {
		return out, nil
	}
	arr, ok := sd.([]any)
	if !ok {
		return nil, fmt.Errorf("%w: _sd must be an array", ErrMalformed)
	}
	for _, e := range arr {
		dg, ok := e.(string)
		if !ok {
			return nil, fmt.Errorf("%w: _sd element must be a string", ErrMalformed)
		}
		d, found, err := w.resolve(dg)
		if err != nil {
			return nil, err
		}
		if !found {
			continue // decoy: accepted silently (SD-JWT §4.2.5), counted
		}
		if len(d.arr) != 3 {
			return nil, fmt.Errorf("%w: object disclosure must have 3 elements", ErrDisclosure)
		}
		name, ok := d.arr[1].(string)
		if !ok {
			return nil, fmt.Errorf("%w: disclosure name must be a string", ErrDisclosure)
		}
		if name == claimSD || name == claimEllipsis {
			return nil, fmt.Errorf("%w: disclosure name is reserved", ErrDisclosure)
		}
		if _, exists := out[name]; exists {
			return nil, fmt.Errorf("%w: %q", ErrClaimCollision, name)
		}
		rv, err := w.value(d.arr[2])
		if err != nil {
			return nil, err
		}
		out[name] = rv
	}
	return out, nil
}

// array processes one JSON array: an element shaped {"...": <digest>} is an
// array-element disclosure wrapper (SD-JWT §4.2.2) — resolved or, for a
// decoy, omitted; every other element is recursed into unchanged.
func (w *walker) array(a []any) ([]any, error) {
	out := make([]any, 0, len(a))
	for _, e := range a {
		if dg, ok := arrayDigest(e); ok {
			d, found, err := w.resolve(dg)
			if err != nil {
				return nil, err
			}
			if !found {
				continue // decoy array element: omitted, counted
			}
			if len(d.arr) != 2 {
				return nil, fmt.Errorf("%w: array disclosure must have 2 elements", ErrDisclosure)
			}
			rv, err := w.value(d.arr[1])
			if err != nil {
				return nil, err
			}
			out = append(out, rv)
			continue
		}
		rv, err := w.value(e)
		if err != nil {
			return nil, err
		}
		out = append(out, rv)
	}
	return out, nil
}

// arrayDigest reports whether e is an array-element disclosure wrapper
// {"...": "<digest>"} (SD-JWT §4.2.2) and, if so, returns its digest.
func arrayDigest(e any) (string, bool) {
	m, ok := e.(map[string]any)
	if !ok || len(m) != 1 {
		return "", false
	}
	v, ok := m[claimEllipsis]
	if !ok {
		return "", false
	}
	dg, ok := v.(string)
	return dg, ok
}
