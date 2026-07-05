package sdjwt

import (
	"bytes"
	"fmt"
)

// Hardening caps for untrusted input (hard rule 5). A conformant EUDI
// credential is far smaller; these bound worst-case work before any decode.
const (
	maxPresentationBytes = 256 * 1024 // whole combined format
	maxDisclosures       = 1000       // number of ~-separated disclosures
)

// parsed is the structural decomposition of a combined-format SD-JWT.
type parsed struct {
	issuer      []byte   // compact JWS bytes of the issuer-signed JWT
	disclosures [][]byte // base64url disclosure strings, in presentation order
	kb          []byte   // compact JWS bytes of the KB-JWT, or nil if absent
	sdPart      []byte   // exact bytes hashed for sd_hash: issuer + disclosures + trailing '~'
}

// splitCombined splits a presentation into its parts (SD-JWT §4.1). Layout:
// <issuer-jwt>~<disclosure>~...~<disclosure>~<kb-jwt>, where the KB-JWT slot
// is the final ~-separated segment and is empty when no KB-JWT is present.
// Fail closed: empty segments, oversized input, too many disclosures, a
// non-JWS issuer, disclosures containing '.', or a non-empty non-JWS KB slot
// (trailing garbage) are all rejected.
func splitCombined(pres []byte) (*parsed, error) {
	if len(pres) == 0 {
		return nil, fmt.Errorf("%w: empty presentation", ErrMalformed)
	}
	if len(pres) > maxPresentationBytes {
		return nil, fmt.Errorf("%w: %d bytes", ErrTooLarge, len(pres))
	}
	parts := bytes.Split(pres, []byte("~"))
	if len(parts) < 2 {
		// A conformant SD-JWT always has at least one '~' after the issuer JWT.
		return nil, fmt.Errorf("%w: missing ~ separator", ErrMalformed)
	}
	issuer := parts[0]
	if !isCompactJWS(issuer) {
		return nil, fmt.Errorf("%w: issuer segment is not a compact JWS", ErrMalformed)
	}
	discParts := parts[1 : len(parts)-1]
	if len(discParts) > maxDisclosures {
		return nil, fmt.Errorf("%w: %d", ErrDisclosureLimit, len(discParts))
	}
	disclosures := make([][]byte, 0, len(discParts))
	for _, d := range discParts {
		if len(d) == 0 {
			return nil, fmt.Errorf("%w: empty disclosure segment", ErrMalformed)
		}
		if bytes.IndexByte(d, '.') >= 0 {
			return nil, fmt.Errorf("%w: disclosure contains '.'", ErrMalformed)
		}
		disclosures = append(disclosures, d)
	}
	last := parts[len(parts)-1]
	var kb []byte
	if len(last) > 0 {
		if !isCompactJWS(last) {
			return nil, fmt.Errorf("%w: trailing data after last disclosure is not a KB-JWT", ErrMalformed)
		}
		kb = last
	}
	// sd_hash covers everything up to and including the '~' before the KB-JWT
	// (SD-JWT §4.3): the whole presentation minus the KB-JWT bytes.
	sdPart := pres[:len(pres)-len(kb)]
	return &parsed{issuer: issuer, disclosures: disclosures, kb: kb, sdPart: sdPart}, nil
}

// isCompactJWS reports whether b is a non-empty compact JWS shape: splitting
// on '.' yields exactly three segments, all non-empty. It does NOT validate
// the base64url charset of each segment — only presence/count are checked
// here; charset and signature validity are checked later by go-eudi-crypto's
// VerifyJWS.
func isCompactJWS(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	segs := bytes.Split(b, []byte("."))
	if len(segs) != 3 {
		return false
	}
	for _, s := range segs {
		if len(s) == 0 {
			return false
		}
	}
	return true
}
