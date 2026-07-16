package sdjwt

import (
	"context"
	stdcrypto "crypto"
	"errors"
	"testing"
	"time"
)

// basePayload returns a minimal valid SD-JWT VC payload with one disclosable
// claim; the caller appends the returned disclosure string. When holder is
// non-nil it is embedded as cnf.jwk. testing.TB so FuzzVerify's
// seed-construction phase (*testing.F) can call it too.
func basePayload(t testing.TB, holder map[string]any) (map[string]any, string) {
	dGiven, digGiven := mkDisclosure(t, "s0", "given_name", "Arthur")
	p := map[string]any{
		claimSDAlg: "sha-256",
		claimISS:   "https://issuer.example",
		claimVCT:   "urn:eudi:pid:1",
		claimIAT:   time.Date(2026, 7, 4, 10, 0, 0, 0, time.UTC).Unix(),
		claimSD:    []any{digGiven},
	}
	if holder != nil {
		p[claimCNF] = map[string]any{claimJWK: holder}
	}
	return p, dGiven
}

// fixedClock returns a clock pinned to 2026-07-04 12:00 UTC.
func fixedClock() func() time.Time {
	now := time.Date(2026, 7, 4, 12, 0, 0, 0, time.UTC)
	return func() time.Time { return now }
}

func TestVerifyHappyPath(t *testing.T) {
	issKey := newECKey(t)
	kp := staticProvider("iss", issKey)
	payload, disc := basePayload(t, nil)
	pres := assemble(signIssuerJWT(t, kp, "iss", typSDJWT, payload), disc)

	v := NewVerifier(WithClock(fixedClock()))
	vc, err := v.Verify(context.Background(), VerifyInput{
		Presentation: pres,
		IssuerKey:    issKey.Public(),
		RequireKB:    false,
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if vc.VCT != "urn:eudi:pid:1" {
		t.Errorf("VCT = %q", vc.VCT)
	}
	if vc.Claims["given_name"] != "Arthur" {
		t.Errorf("given_name = %v", vc.Claims["given_name"])
	}
	if vc.SDHash == "" {
		t.Error("SDHash empty")
	}
	if vc.DecoyDigests != 0 {
		t.Errorf("DecoyDigests = %d", vc.DecoyDigests)
	}
}

func TestVerifyEnvelopeNegatives(t *testing.T) {
	issKey := newECKey(t)
	kp := staticProvider("iss", issKey)
	v := NewVerifier(WithClock(fixedClock()))

	build := func(mut func(p map[string]any), typ string) []byte {
		p, disc := basePayload(t, nil)
		mut(p)
		return assemble(signIssuerJWT(t, kp, "iss", typ, p), disc)
	}

	tests := []struct {
		name string
		pres []byte
		key  stdcrypto.PublicKey
		req  bool
		want error
	}{
		{"wrong typ", build(func(map[string]any) {}, "JWT"), issKey.Public(), false, ErrType},
		{"legacy typ rejected by default", build(func(map[string]any) {}, typVCSDJWT), issKey.Public(), false, ErrType},
		{"missing iss", build(func(p map[string]any) { delete(p, claimISS) }, typSDJWT), issKey.Public(), false, ErrMissingIssuer},
		{"missing vct", build(func(p map[string]any) { delete(p, claimVCT) }, typSDJWT), issKey.Public(), false, ErrMissingVCT},
		{"expired", build(func(p map[string]any) { p[claimEXP] = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC).Unix() }, typSDJWT), issKey.Public(), false, ErrExpired},
		{"not yet valid", build(func(p map[string]any) { p[claimNBF] = time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC).Unix() }, typSDJWT), issKey.Public(), false, ErrNotYetValid},
		{"RequireKB but no cnf", build(func(map[string]any) {}, typSDJWT), issKey.Public(), true, ErrMissingCNF},
		{"wrong issuer key", build(func(map[string]any) {}, typSDJWT), newECKey(t).Public(), false, ErrIssuerSignature},
		{"malformed cnf: jwk absent", build(func(p map[string]any) { p[claimCNF] = map[string]any{} }, typSDJWT), issKey.Public(), false, ErrMalformed},
		{"malformed cnf: jwk garbage", build(func(p map[string]any) { p[claimCNF] = map[string]any{claimJWK: "not-an-object"} }, typSDJWT), issKey.Public(), false, ErrMalformed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := v.Verify(context.Background(), VerifyInput{
				Presentation: tt.pres,
				IssuerKey:    tt.key,
				RequireKB:    tt.req,
			})
			if !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestVerifyLegacyTypAccepted(t *testing.T) {
	issKey := newECKey(t)
	kp := staticProvider("iss", issKey)
	payload, disc := basePayload(t, nil)
	pres := assemble(signIssuerJWT(t, kp, "iss", typVCSDJWT, payload), disc)

	v := NewVerifier(WithClock(fixedClock()), WithLegacyVCTyp())
	if _, err := v.Verify(context.Background(), VerifyInput{Presentation: pres, IssuerKey: issKey.Public()}); err != nil {
		t.Fatalf("legacy typ with WithLegacyVCTyp: %v", err)
	}
}

// decodeJSONObject must reject trailing bytes after the JSON object,
// mirroring decodeDisclosure's dec.More() guard in disclosure.go. The
// payload is signature-bound so this is not attacker-reachable in practice,
// but the two decoders should apply the same defense-in-depth consistently.
func TestDecodeJSONObjectRejectsTrailingBytes(t *testing.T) {
	if _, err := decodeJSONObject([]byte(`{"a":1}{"b":2}`)); !errors.Is(err, ErrMalformed) {
		t.Fatalf("err = %v, want ErrMalformed", err)
	}
}

func TestVerifyExtractsCNF(t *testing.T) {
	issKey := newECKey(t)
	holderKey := newECKey(t)
	kp := staticProvider("iss", issKey)
	payload, disc := basePayload(t, jwkOf(t, holderKey.Public()))
	pres := assemble(signIssuerJWT(t, kp, "iss", typSDJWT, payload), disc)

	v := NewVerifier(WithClock(fixedClock()))
	vc, err := v.Verify(context.Background(), VerifyInput{Presentation: pres, IssuerKey: issKey.Public(), RequireKB: false})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !holderKey.PublicKey.Equal(vc.CNF) {
		t.Error("VerifiedCredential.CNF is not the holder key")
	}
}
