package sdjwt

import (
	stdcrypto "crypto"
	"fmt"

	eudicrypto "github.com/gmb-eudi/go-eudi-crypto"
)

// verifyKB verifies the Key-Binding JWT (SD-JWT §4.3): typ=kb+jwt, signature
// by the cnf key, aud/nonce match, iat within the freshness window, and
// sd_hash over exactly the presented issuer-JWT+disclosures (parsed.sdPart)
// under the credential hash h. Each failure has a distinct error so services
// can map it precisely (docs/conventions.md err:domain:reason).
func (v *Verifier) verifyKB(p *parsed, holderKey stdcrypto.PublicKey, in VerifyInput, h stdcrypto.Hash) error {
	payloadBytes, hdr, err := eudicrypto.VerifyJWS(p.kb, holderKey)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrKBSignature, err)
	}
	if t, _ := hdr[hdrTyp].(string); t != typKB {
		return fmt.Errorf("%w: %q", ErrKBType, t)
	}
	body, err := decodeJSONObject(payloadBytes)
	if err != nil {
		return err
	}
	// An empty ExpectedAud/ExpectedNonce is a caller misconfiguration, not a
	// wildcard: the comparisons below use != , so an empty expected value
	// would otherwise silently match a KB whose own aud/nonce also happen to
	// be empty (e.g. a malformed or adversarial token). Fail closed whenever
	// a KB is actually being verified (hard rule 7), before comparing to the
	// token's value at all.
	if in.ExpectedAud == "" {
		return fmt.Errorf("%w: expected aud must not be empty", ErrKBAudience)
	}
	if in.ExpectedNonce == "" {
		return fmt.Errorf("%w: expected nonce must not be empty", ErrKBNonce)
	}
	// aud is intentionally read as a single string only (SD-JWT §4.3); an
	// array aud fails the type assertion, yielding "" which never matches
	// in.ExpectedAud, so it fails closed with ErrKBAudience.
	if a, _ := body[claimAUD].(string); a != in.ExpectedAud {
		return fmt.Errorf("%w", ErrKBAudience)
	}
	if n, _ := body[claimNonce].(string); n != in.ExpectedNonce {
		return fmt.Errorf("%w", ErrKBNonce)
	}
	iat, ok := unixTime(body[claimIAT])
	if !ok {
		return fmt.Errorf("%w: KB iat missing", ErrMalformed)
	}
	now := v.clock()
	if iat.After(now.Add(v.skew)) {
		return fmt.Errorf("%w: iat in the future", ErrKBStale)
	}
	if iat.Before(now.Add(-v.kbMaxAge - v.skew)) {
		return fmt.Errorf("%w: iat too old", ErrKBStale)
	}
	want := digest(p.sdPart, h)
	if got, _ := body[claimSDHash].(string); got != want {
		return fmt.Errorf("%w", ErrKBSDHash)
	}
	return nil
}
