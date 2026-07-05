package sdjwt

import (
	"context"
	stdcrypto "crypto"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"

	eudicrypto "github.com/gmb-eudi/go-eudi-crypto"
)

// reservedClaims may not appear as top-level keys in CredentialTemplate.Claims
// — they are set by Issue from the template's typed fields (or are SD-JWT
// control members).
var reservedClaims = map[string]bool{
	claimSD: true, claimSDAlg: true, claimISS: true, claimVCT: true,
	claimIAT: true, claimNBF: true, claimEXP: true, claimCNF: true, claimStatus: true,
}

// Issue produces a combined-format SD-JWT (no KB-JWT), signing the issuer JWT
// with the Issuer's key. Claims listed in tmpl.Selective are blinded into
// _sd digests (objects) / "..." wrappers (arrays); everything else is in the
// clear. Disclosures are emitted sorted (order-independent for verification;
// avoids leaking insertion order). SD-JWT §4; SD-JWT VC §3.
func (i *Issuer) Issue(ctx context.Context, tmpl CredentialTemplate) ([]byte, error) {
	if tmpl.VCT == "" || tmpl.Issuer == "" {
		return nil, fmt.Errorf("%w: vct and iss are required", ErrTemplate)
	}
	if tmpl.Claims == nil {
		return nil, fmt.Errorf("%w: claims required", ErrTemplate)
	}
	for k := range tmpl.Claims {
		if reservedClaims[k] {
			return nil, fmt.Errorf("%w: reserved claim %q in template", ErrTemplate, k)
		}
	}
	for _, p := range tmpl.Selective {
		if !p.valid() {
			return nil, fmt.Errorf("%w: invalid selective path", ErrTemplate)
		}
	}
	// The hash used for digests must match what a verifier derives from the
	// persisted _sd_alg (hashForSDAlg: absent claim = policy default). Passing
	// the same name (possibly "") through HashForName keeps the two in lock
	// step without a hash-name literal here (hard rule 4).
	h, err := eudicrypto.ECCG().HashForName(tmpl.HashName)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTemplate, err)
	}

	b := &sdBuilder{sel: map[string]bool{}, used: map[string]bool{}, h: h}
	for _, p := range tmpl.Selective {
		b.sel[pathKey(p)] = true
	}
	built, err := b.build(tmpl.Claims, ClaimPath{})
	if err != nil {
		return nil, err
	}
	// Every selective path must have matched a claim (fail loud on typos).
	for key := range b.sel {
		if !b.used[key] {
			return nil, fmt.Errorf("%w: selective path %s matched no claim", ErrTemplate, key)
		}
	}
	payload, ok := built.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%w: claims must be a JSON object", ErrTemplate)
	}

	// Registered members (in the clear).
	if tmpl.HashName != "" {
		payload[claimSDAlg] = tmpl.HashName
	} // else: omit _sd_alg — SD-JWT §4.1.1 treats absence as the policy default.
	payload[claimISS] = tmpl.Issuer
	payload[claimVCT] = tmpl.VCT
	if !tmpl.IssuedAt.IsZero() {
		payload[claimIAT] = tmpl.IssuedAt.Unix()
	}
	if !tmpl.NotBefore.IsZero() {
		payload[claimNBF] = tmpl.NotBefore.Unix()
	}
	if !tmpl.Expiry.IsZero() {
		payload[claimEXP] = tmpl.Expiry.Unix()
	}
	if tmpl.HolderKey != nil {
		jwk, err := eudicrypto.ECPublicKeyToJWK(tmpl.HolderKey)
		if err != nil {
			return nil, fmt.Errorf("%w: holder key: %v", ErrTemplate, err)
		}
		payload[claimCNF] = map[string]any{claimJWK: jwk}
	}
	if tmpl.Status != nil {
		payload[claimStatus] = map[string]any{
			claimStatusList: map[string]any{claimURI: tmpl.Status.URI, claimIdx: tmpl.Status.Index},
		}
	}

	body, err := json.Marshal(payload)
	if err != nil {
		// Static suffix only: a *json.UnsupportedValueError (e.g. NaN) embeds
		// the offending claim value in its message, and *json.MarshalerError
		// embeds nested error text — never wrap the underlying err
		// (hard rule 3 / GDPR; same discipline as decodeJSONObject in verify.go).
		return nil, fmt.Errorf("%w: payload not JSON-serializable", ErrTemplate)
	}
	issuerJWT, err := eudicrypto.SignJWS(ctx, i.kp, i.keyID, map[string]any{hdrTyp: typSDJWT}, body)
	if err != nil {
		return nil, err
	}
	sort.Strings(b.discs)
	out := append([]byte{}, issuerJWT...)
	out = append(out, '~')
	for _, d := range b.discs {
		out = append(out, d...)
		out = append(out, '~')
	}
	return out, nil
}

// sdBuilder recursively blinds selected claim paths into disclosures.
type sdBuilder struct {
	sel   map[string]bool // pathKey → selected
	used  map[string]bool // pathKey → matched a claim
	h     stdcrypto.Hash
	discs []string
}

// build walks value (a JSON object/array/scalar from CredentialTemplate.Claims)
// blinding any child whose path is in b.sel. Reserved control keys ("_sd",
// "...") may not appear as literal claim names anywhere in the template —
// allowing them would let a template claim silently collide with (and be
// overwritten by) the digest machinery it produces.
func (b *sdBuilder) build(value any, path ClaimPath) (any, error) {
	switch v := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(v))
		var sd []string
		for _, k := range sortedKeys(v) {
			if k == claimSD || k == claimEllipsis {
				return nil, fmt.Errorf("%w: reserved claim name %q in template", ErrTemplate, k)
			}
			cp := appendPath(path, k)
			child, err := b.build(v[k], cp)
			if err != nil {
				return nil, err
			}
			if b.sel[pathKey(cp)] {
				b.used[pathKey(cp)] = true
				enc, dig, err := b.discloseObject(k, child)
				if err != nil {
					return nil, err
				}
				b.discs = append(b.discs, enc)
				sd = append(sd, dig)
			} else {
				out[k] = child
			}
		}
		if len(sd) > 0 {
			sort.Strings(sd)
			out[claimSD] = toAnySlice(sd)
		}
		return out, nil
	case []any:
		out := make([]any, 0, len(v))
		for idx, e := range v {
			cp := appendPath(path, idx)
			child, err := b.build(e, cp)
			if err != nil {
				return nil, err
			}
			if b.sel[pathKey(cp)] {
				b.used[pathKey(cp)] = true
				enc, dig, err := b.discloseArray(child)
				if err != nil {
					return nil, err
				}
				b.discs = append(b.discs, enc)
				out = append(out, map[string]any{claimEllipsis: dig})
			} else {
				out = append(out, child)
			}
		}
		return out, nil
	default:
		return v, nil
	}
}

func (b *sdBuilder) discloseObject(name string, value any) (enc, dig string, err error) {
	salt, err := newSalt()
	if err != nil {
		return "", "", err
	}
	raw, err := json.Marshal([]any{salt, name, value})
	if err != nil {
		// Static suffix only: never wrap the underlying err — it can embed
		// the claim value itself (hard rule 3 / GDPR; see body marshal above).
		return "", "", fmt.Errorf("%w: claim value not JSON-serializable", ErrTemplate)
	}
	enc = base64.RawURLEncoding.EncodeToString(raw)
	return enc, digest([]byte(enc), b.h), nil
}

func (b *sdBuilder) discloseArray(value any) (enc, dig string, err error) {
	salt, err := newSalt()
	if err != nil {
		return "", "", err
	}
	raw, err := json.Marshal([]any{salt, value})
	if err != nil {
		// Static suffix only: never wrap the underlying err — it can embed
		// the claim value itself (hard rule 3 / GDPR; see body marshal above).
		return "", "", fmt.Errorf("%w: claim value not JSON-serializable", ErrTemplate)
	}
	enc = base64.RawURLEncoding.EncodeToString(raw)
	return enc, digest([]byte(enc), b.h), nil
}

// saltBytes is the salt length in bytes (128 bit, SD-JWT §4.2.1 minimum
// recommendation).
const saltBytes = 16

// newSalt returns a fresh base64url-encoded salt read from crypto/rand.
// crypto/rand (never math/rand) is required: insufficient or predictable
// salt entropy breaks the unlinkability selective disclosure depends on.
func newSalt() (string, error) {
	var b [saltBytes]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("%w: salt generation failed", ErrTemplate)
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

func sortedKeys(m map[string]any) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

func toAnySlice(ss []string) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}

// appendPath returns a fresh ClaimPath with e appended (never shares backing
// with p, so branches of the recursive build/walk below can't alias).
func appendPath(p ClaimPath, e any) ClaimPath {
	out := make(ClaimPath, len(p)+1)
	copy(out, p)
	out[len(p)] = e
	return out
}

// pathKey is a stable string key for a ClaimPath (its JSON form), used to
// index selection sets by path.
func pathKey(p ClaimPath) string {
	b, err := json.Marshal([]any(p))
	if err != nil {
		return fmt.Sprintf("%v", []any(p))
	}
	return string(b)
}
