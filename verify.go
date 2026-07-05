package sdjwt

import (
	"bytes"
	"context"
	stdcrypto "crypto"
	"encoding/json"
	"fmt"
	"time"

	eudicrypto "github.com/gmb-eudi/go-eudi-crypto"
)

// Verify verifies an SD-JWT / SD-JWT VC presentation (SD-JWT §7; SD-JWT VC
// §3). Pipeline: split combined format → verify issuer JWS (go-eudi-crypto,
// alg derived from IssuerKey) → enforce typ → require iss/vct → check
// validity window → extract cnf holder key → reconstruct disclosed claims by
// digest → compute sd_hash → verify KB-JWT (SD-JWT §4.3, T-02.5) → extract
// the status_list reference (Token Status List §5, T-02.6). Fail closed: any
// failed check returns a distinct typed error and no VerifiedCredential.
func (v *Verifier) Verify(ctx context.Context, in VerifyInput) (*VerifiedCredential, error) {
	_ = ctx // reserved for propagation; this library performs no I/O
	p, err := splitCombined(in.Presentation)
	if err != nil {
		return nil, err
	}
	// Issuer JWS (RFC 7515; key resolved by caller via trust layer).
	payloadBytes, hdr, err := eudicrypto.VerifyJWS(p.issuer, in.IssuerKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrIssuerSignature, err)
	}
	if err := v.checkTyp(hdr); err != nil {
		return nil, err
	}
	payload, err := decodeJSONObject(payloadBytes)
	if err != nil {
		return nil, err
	}
	// SD-JWT VC §3.2: iss and vct are required.
	iss, _ := payload[claimISS].(string)
	if iss == "" {
		return nil, fmt.Errorf("%w", ErrMissingIssuer)
	}
	vct, _ := payload[claimVCT].(string)
	if vct == "" {
		return nil, fmt.Errorf("%w", ErrMissingVCT)
	}
	vc := &VerifiedCredential{VCT: vct}
	if err := v.checkValidity(payload, vc); err != nil {
		return nil, err
	}
	// cnf holder-binding key (RFC 7800; SD-JWT VC §3.5).
	holderKey, err := extractCNF(payload)
	if err != nil {
		return nil, err
	}
	if in.RequireKB && holderKey == nil {
		return nil, fmt.Errorf("%w", ErrMissingCNF)
	}
	vc.CNF = holderKey
	// Reconstruct disclosed claims (SD-JWT §7).
	h, err := hashForSDAlg(v.policy, payload)
	if err != nil {
		return nil, err
	}
	claims, decoys, err := reconstruct(payload, p.disclosures, h)
	if err != nil {
		return nil, err
	}
	vc.Claims = claims
	vc.DecoyDigests = decoys
	// sd_hash over the presented issuer-JWT + disclosures (audit; also the
	// value the KB-JWT must match — SD-JWT §4.3).
	vc.SDHash = digest(p.sdPart, h)

	// KB-JWT (SD-JWT §4.3; HAIP requires it). A present KB is always
	// verified; RequireKB additionally makes its absence an error.
	if in.RequireKB || p.kb != nil {
		if p.kb == nil {
			return nil, fmt.Errorf("%w", ErrKBRequired)
		}
		if holderKey == nil {
			return nil, fmt.Errorf("%w", ErrMissingCNF)
		}
		if err := v.verifyKB(p, holderKey, in, h); err != nil {
			return nil, err
		}
	}

	// Status list reference (IETF Token Status List §5). Malformed = error.
	status, err := extractStatus(payload)
	if err != nil {
		return nil, err
	}
	vc.Status = status

	return vc, nil
}

// checkTyp enforces the SD-JWT VC typ header (SD-JWT VC §3.2.1): dc+sd-jwt,
// or legacy vc+sd-jwt only when WithLegacyVCTyp was set.
func (v *Verifier) checkTyp(hdr eudicrypto.Header) error {
	t, _ := hdr[hdrTyp].(string)
	if t == typSDJWT {
		return nil
	}
	if t == typVCSDJWT && v.allowLegacyVCTyp {
		return nil
	}
	return fmt.Errorf("%w: %q", ErrType, t)
}

// checkValidity applies the exp/nbf window with the configured skew (RFC 7519).
func (v *Verifier) checkValidity(payload map[string]any, vc *VerifiedCredential) error {
	now := v.clock()
	if raw, ok := payload[claimEXP]; ok {
		exp, ok := unixTime(raw)
		if !ok {
			return fmt.Errorf("%w: exp not a number", ErrMalformed)
		}
		if !now.Add(-v.skew).Before(exp) {
			return fmt.Errorf("%w", ErrExpired)
		}
		vc.Expiry = exp
	}
	if raw, ok := payload[claimNBF]; ok {
		nbf, ok := unixTime(raw)
		if !ok {
			return fmt.Errorf("%w: nbf not a number", ErrMalformed)
		}
		if now.Add(v.skew).Before(nbf) {
			return fmt.Errorf("%w", ErrNotYetValid)
		}
		vc.NotBefore = nbf
	}
	return nil
}

// extractCNF resolves cnf.jwk to a public key (RFC 7800; jwk confirmation
// only — the HAIP profile). Absent cnf → (nil, nil). Malformed cnf → error
// (fail closed).
func extractCNF(payload map[string]any) (stdcrypto.PublicKey, error) {
	raw, ok := payload[claimCNF]
	if !ok {
		return nil, nil
	}
	cnf, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%w: cnf must be an object", ErrMalformed)
	}
	jwkVal, ok := cnf[claimJWK]
	if !ok {
		return nil, fmt.Errorf("%w: cnf has no jwk member", ErrMalformed)
	}
	jb, err := json.Marshal(jwkVal)
	if err != nil {
		return nil, fmt.Errorf("%w: cnf jwk: %v", ErrMalformed, err)
	}
	key, err := eudicrypto.ParseECPublicKeyJWK(jb)
	if err != nil {
		return nil, fmt.Errorf("%w: cnf jwk: %v", ErrMalformed, err)
	}
	return key, nil
}

// decodeJSONObject decodes a JWT payload as a JSON object, numbers preserved.
// Trailing bytes after the object are rejected (M-2, mirroring
// decodeDisclosure's dec.More() guard in disclosure.go) — defense in depth
// only, since a JWT payload is signature-bound and so not attacker-mutable
// independent of the signature, but the two decoders should agree.
func decodeJSONObject(b []byte) (map[string]any, error) {
	var m map[string]any
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if err := dec.Decode(&m); err != nil {
		// Static suffix only: a *json.SyntaxError's message can echo a byte of
		// the decoded payload (which carries claim values) — never wrap the
		// underlying err (hard rule 3 / GDPR; same discipline as
		// decodeDisclosure in disclosure.go).
		return nil, fmt.Errorf("%w: payload is not valid JSON", ErrMalformed)
	}
	if dec.More() {
		return nil, fmt.Errorf("%w: trailing data after payload", ErrMalformed)
	}
	if m == nil {
		return nil, fmt.Errorf("%w: payload is not a JSON object", ErrMalformed)
	}
	return m, nil
}

// unixTime coerces a NumericDate claim (json.Number or float64) to time.Time.
func unixTime(v any) (time.Time, bool) {
	switch n := v.(type) {
	case json.Number:
		if i, err := n.Int64(); err == nil {
			return time.Unix(i, 0), true
		}
		if f, err := n.Float64(); err == nil {
			return time.Unix(int64(f), 0), true
		}
		return time.Time{}, false
	case float64:
		return time.Unix(int64(n), 0), true
	default:
		return time.Time{}, false
	}
}
