package sdjwt

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"

	eudicrypto "github.com/gmb-eudi/go-eudi-crypto"
)

// PeekResult holds structural fields read from a combined-format SD-JWT
// WITHOUT verifying anything — no signature check, no digest check, no expiry
// check. It is what Peek returns. It exists so a caller can resolve the
// issuer's public key (e.g. from the x5c chain, against a trust anchor) BEFORE
// calling Verify, which requires the resolved key as input (ADR-0004: this
// library never does key resolution itself). NEVER use a PeekResult's fields to
// make a trust or authorization decision directly — the header/payload fields
// below are UNVERIFIED; verify with Verify first.
//
// (Named PeekResult rather than Peek because Go forbids a type and the Peek
// function sharing one identifier in this package.)
type PeekResult struct {
	Typ             string              // protected header "typ" (RFC 7515 §4.1), unverified
	X5C             []*x509.Certificate // protected header x5c (RFC 7515 §4.1.6), leaf first; nil if absent; NOT validated against any anchor
	Iss             string              // payload "iss" (SD-JWT VC §3.2), read WITHOUT signature verification
	VCT             string              // payload "vct" (SD-JWT VC §3.2), read WITHOUT signature verification
	DisclosureCount int                 // number of ~-separated disclosure segments
}

// Peek reads the structural fields of a combined-format SD-JWT presentation
// WITHOUT verifying anything (no signature, digest, or validity check). It is a
// pre-trust helper: resolve the issuer key from Peek.X5C against a trust anchor,
// THEN call Verify with the resolved key — Peek's own output must never be
// trusted directly. Reuses the combined-format splitter and the go-eudi-crypto
// header peek; reads only iss/vct from the payload (never the full claim set,
// keeping the "unverified" boundary obvious and avoiding exposing claim values
// pre-verification — hard rule 3 in spirit). Fail closed (ErrMalformed) on any
// decode failure; must not panic on adversarial input (fuzzed: FuzzPeek).
func Peek(presentation []byte) (*PeekResult, error) {
	p, err := splitCombined(presentation)
	if err != nil {
		return nil, err
	}
	// Protected header (typ, x5c) — structural read only, no signature check.
	// Re-wrap go-eudi-crypto's ErrMalformed into this package's ErrMalformed so
	// callers match one sentinel (as verify.go's extractCNF does). The header
	// carries JOSE metadata (typ/alg/x5c), not attribute values, so including
	// the underlying structural message is hard-rule-3 safe — unlike the
	// payload path below, which uses a static suffix.
	hdr, err := eudicrypto.ParseJWSHeader(p.issuer)
	if err != nil {
		return nil, fmt.Errorf("%w: issuer header: %v", ErrMalformed, err)
	}
	x5c, err := eudicrypto.X5CFromHeader(hdr)
	if err != nil {
		return nil, fmt.Errorf("%w: issuer x5c: %v", ErrMalformed, err)
	}
	typ, _ := hdr[hdrTyp].(string)
	iss, vct, err := peekIssVCT(p.issuer)
	if err != nil {
		return nil, err
	}
	return &PeekResult{
		Typ:             typ,
		X5C:             x5c,
		Iss:             iss,
		VCT:             vct,
		DisclosureCount: len(p.disclosures),
	}, nil
}

// peekIssVCT base64url-decodes the issuer JWS payload segment (the middle of
// the three '.'-separated parts) and reads ONLY iss/vct — never the full claim
// set (a peek, not a parse). No signature is checked. Fail closed on an
// undecodable segment or non-JSON payload.
func peekIssVCT(issuerJWS []byte) (iss, vct string, err error) {
	segs := bytes.Split(issuerJWS, []byte("."))
	if len(segs) != 3 {
		// splitCombined already guarantees a 3-segment issuer JWS; this is
		// defense in depth so the payload index below is always valid.
		return "", "", fmt.Errorf("%w: issuer JWT is not a compact JWS", ErrMalformed)
	}
	raw, err := base64.RawURLEncoding.DecodeString(string(segs[1]))
	if err != nil {
		return "", "", fmt.Errorf("%w: issuer payload segment", ErrMalformed)
	}
	// Only iss/vct are extracted; other claim values are intentionally never
	// decoded or exposed pre-verification (hard rule 3 in spirit).
	var body struct {
		Iss string `json:"iss"`
		VCT string `json:"vct"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		// Static suffix only: a *json.SyntaxError can echo bytes of the decoded
		// payload (which carries claim values) — never wrap the underlying err
		// (hard rule 3 / GDPR; same discipline as decodeJSONObject in verify.go).
		return "", "", fmt.Errorf("%w: issuer payload is not valid JSON", ErrMalformed)
	}
	return body.Iss, body.VCT, nil
}
