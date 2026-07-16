package sdjwt

import (
	"context"
	stdcrypto "crypto"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"testing"
	"time"

	eudicrypto "github.com/gmb-eudi/go-eudi-crypto"
)

// signKB signs a KB-JWT (typ=kb+jwt) with the holder key over sdHashPart.
// testing.TB so FuzzVerify's seed-construction phase (*testing.F) can call it.
func signKB(t testing.TB, holder *ecdsa.PrivateKey, sdHashPart []byte, aud, nonce string, iat time.Time, h stdcrypto.Hash) []byte {
	t.Helper()
	kp := staticProvider("h", holder)
	body := map[string]any{
		claimIAT:    iat.Unix(),
		claimAUD:    aud,
		claimNonce:  nonce,
		claimSDHash: digest(sdHashPart, h),
	}
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := eudicrypto.SignJWS(context.Background(), kp, "h", map[string]any{hdrTyp: typKB}, raw)
	if err != nil {
		t.Fatalf("sign KB: %v", err)
	}
	return tok
}

// kbFixture builds a full presentation with a KB-JWT and returns it plus the
// pieces tests need to mutate.
type kbFixture struct {
	pres      []byte
	issKey    *ecdsa.PrivateKey
	holderKey *ecdsa.PrivateKey
	sdPart    []byte
	h         stdcrypto.Hash
}

func newKBFixture(t *testing.T, aud, nonce string, iat time.Time) kbFixture {
	t.Helper()
	issKey := newECKey(t)
	holderKey := newECKey(t)
	kp := staticProvider("iss", issKey)
	payload, disc := basePayload(t, jwkOf(t, holderKey.Public()))
	issuer := signIssuerJWT(t, kp, "iss", typSDJWT, payload)
	sdPart := assemble(issuer, disc) // issuer~disc~  (exact sd_hash input)
	kb := signKB(t, holderKey, sdPart, aud, nonce, iat, stdcrypto.SHA256)
	pres := append(append([]byte{}, sdPart...), kb...)
	return kbFixture{pres: pres, issKey: issKey, holderKey: holderKey, sdPart: sdPart, h: stdcrypto.SHA256}
}

func TestVerifyKBHappyPath(t *testing.T) {
	now := time.Date(2026, 7, 4, 12, 0, 0, 0, time.UTC)
	f := newKBFixture(t, "verifier-client-id", "n0nce", now)
	v := NewVerifier(WithClock(func() time.Time { return now }))
	vc, err := v.Verify(context.Background(), VerifyInput{
		Presentation:  f.pres,
		IssuerKey:     f.issKey.Public(),
		ExpectedAud:   "verifier-client-id",
		ExpectedNonce: "n0nce",
		RequireKB:     true,
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if vc.Claims["given_name"] != "Arthur" {
		t.Errorf("claims lost: %v", vc.Claims)
	}
}

func TestVerifyKBNegatives(t *testing.T) {
	now := time.Date(2026, 7, 4, 12, 0, 0, 0, time.UTC)
	v := NewVerifier(WithClock(func() time.Time { return now }))

	t.Run("required but absent", func(t *testing.T) {
		issKey := newECKey(t)
		holderKey := newECKey(t)
		kp := staticProvider("iss", issKey)
		payload, disc := basePayload(t, jwkOf(t, holderKey.Public()))
		pres := assemble(signIssuerJWT(t, kp, "iss", typSDJWT, payload), disc) // no KB
		_, err := v.Verify(context.Background(), VerifyInput{Presentation: pres, IssuerKey: issKey.Public(), ExpectedAud: "a", ExpectedNonce: "n", RequireKB: true})
		if !errors.Is(err, ErrKBRequired) {
			t.Fatalf("err = %v, want ErrKBRequired", err)
		}
	})

	t.Run("KB present but issuer has no cnf", func(t *testing.T) {
		issKey := newECKey(t)
		holderKey := newECKey(t)
		kp := staticProvider("iss", issKey)
		payload, disc := basePayload(t, nil) // no holder jwk: issuer payload has no cnf
		issuer := signIssuerJWT(t, kp, "iss", typSDJWT, payload)
		sdPart := assemble(issuer, disc)
		kb := signKB(t, holderKey, sdPart, "verifier", "n0nce", now, stdcrypto.SHA256)
		pres := append(append([]byte{}, sdPart...), kb...)
		// RequireKB=false so verify.go:57's `RequireKB && cnf==nil` does not
		// fire; the KB branch is entered solely because a KB is present
		// (verify.go:78's `p.kb != nil`), and its own holderKey==nil gate
		// (verify.go:82) is what returns ErrMissingCNF here.
		_, err := v.Verify(context.Background(), VerifyInput{Presentation: pres, IssuerKey: issKey.Public(), ExpectedAud: "verifier", ExpectedNonce: "n0nce", RequireKB: false})
		if !errors.Is(err, ErrMissingCNF) {
			t.Fatalf("err = %v, want ErrMissingCNF", err)
		}
	})

	t.Run("aud mismatch", func(t *testing.T) {
		f := newKBFixture(t, "wrong-aud", "n0nce", now)
		_, err := v.Verify(context.Background(), VerifyInput{Presentation: f.pres, IssuerKey: f.issKey.Public(), ExpectedAud: "verifier", ExpectedNonce: "n0nce", RequireKB: true})
		if !errors.Is(err, ErrKBAudience) {
			t.Fatalf("err = %v, want ErrKBAudience", err)
		}
	})

	t.Run("nonce mismatch", func(t *testing.T) {
		f := newKBFixture(t, "verifier", "stale-nonce", now)
		_, err := v.Verify(context.Background(), VerifyInput{Presentation: f.pres, IssuerKey: f.issKey.Public(), ExpectedAud: "verifier", ExpectedNonce: "fresh", RequireKB: true})
		if !errors.Is(err, ErrKBNonce) {
			t.Fatalf("err = %v, want ErrKBNonce", err)
		}
	})

	t.Run("replayed KB (stale iat)", func(t *testing.T) {
		f := newKBFixture(t, "verifier", "n0nce", now.Add(-1*time.Hour))
		_, err := v.Verify(context.Background(), VerifyInput{Presentation: f.pres, IssuerKey: f.issKey.Public(), ExpectedAud: "verifier", ExpectedNonce: "n0nce", RequireKB: true})
		if !errors.Is(err, ErrKBStale) {
			t.Fatalf("err = %v, want ErrKBStale", err)
		}
	})

	t.Run("iat in the future", func(t *testing.T) {
		f := newKBFixture(t, "verifier", "n0nce", now.Add(1*time.Hour))
		_, err := v.Verify(context.Background(), VerifyInput{Presentation: f.pres, IssuerKey: f.issKey.Public(), ExpectedAud: "verifier", ExpectedNonce: "n0nce", RequireKB: true})
		if !errors.Is(err, ErrKBStale) {
			t.Fatalf("err = %v, want ErrKBStale", err)
		}
	})

	t.Run("sd_hash over a different disclosure set", func(t *testing.T) {
		// Build a valid presentation, then re-sign the KB over a TAMPERED
		// sdPart (a different byte string), and splice it back on.
		issKey := newECKey(t)
		holderKey := newECKey(t)
		kp := staticProvider("iss", issKey)
		payload, disc := basePayload(t, jwkOf(t, holderKey.Public()))
		issuer := signIssuerJWT(t, kp, "iss", typSDJWT, payload)
		sdPart := assemble(issuer, disc)
		tampered := append(append([]byte{}, sdPart...), []byte("EXTRA~")...)
		kb := signKB(t, holderKey, tampered, "verifier", "n0nce", now, stdcrypto.SHA256)
		pres := append(append([]byte{}, sdPart...), kb...)
		_, err := v.Verify(context.Background(), VerifyInput{Presentation: pres, IssuerKey: issKey.Public(), ExpectedAud: "verifier", ExpectedNonce: "n0nce", RequireKB: true})
		if !errors.Is(err, ErrKBSDHash) {
			t.Fatalf("err = %v, want ErrKBSDHash", err)
		}
	})

	t.Run("KB signed by a non-cnf key", func(t *testing.T) {
		issKey := newECKey(t)
		holderKey := newECKey(t)
		rogue := newECKey(t)
		kp := staticProvider("iss", issKey)
		payload, disc := basePayload(t, jwkOf(t, holderKey.Public()))
		issuer := signIssuerJWT(t, kp, "iss", typSDJWT, payload)
		sdPart := assemble(issuer, disc)
		kb := signKB(t, rogue, sdPart, "verifier", "n0nce", now, stdcrypto.SHA256)
		pres := append(append([]byte{}, sdPart...), kb...)
		_, err := v.Verify(context.Background(), VerifyInput{Presentation: pres, IssuerKey: issKey.Public(), ExpectedAud: "verifier", ExpectedNonce: "n0nce", RequireKB: true})
		if !errors.Is(err, ErrKBSignature) {
			t.Fatalf("err = %v, want ErrKBSignature", err)
		}
	})

	t.Run("KB typ not kb+jwt", func(t *testing.T) {
		issKey := newECKey(t)
		holderKey := newECKey(t)
		kp := staticProvider("iss", issKey)
		payload, disc := basePayload(t, jwkOf(t, holderKey.Public()))
		issuer := signIssuerJWT(t, kp, "iss", typSDJWT, payload)
		sdPart := assemble(issuer, disc)
		hkp := staticProvider("h", holderKey)
		body, _ := json.Marshal(map[string]any{claimIAT: now.Unix(), claimAUD: "verifier", claimNonce: "n0nce", claimSDHash: digest(sdPart, stdcrypto.SHA256)})
		kb, err := eudicrypto.SignJWS(context.Background(), hkp, "h", map[string]any{hdrTyp: "JWT"}, body)
		if err != nil {
			t.Fatal(err)
		}
		pres := append(append([]byte{}, sdPart...), kb...)
		_, err = v.Verify(context.Background(), VerifyInput{Presentation: pres, IssuerKey: issKey.Public(), ExpectedAud: "verifier", ExpectedNonce: "n0nce", RequireKB: true})
		if !errors.Is(err, ErrKBType) {
			t.Fatalf("err = %v, want ErrKBType", err)
		}
	})

	// An empty ExpectedAud/ExpectedNonce is a caller misconfiguration,
	// not a legitimate "match anything" wildcard. verifyKB's aud/nonce checks
	// use != for comparison, so an empty expected value would otherwise match
	// a KB whose own aud/nonce also happen to be empty — fail closed instead
	// regardless of what the token carries.
	t.Run("empty expected aud rejected even if token aud is also empty (misconfiguration)", func(t *testing.T) {
		f := newKBFixture(t, "", "n0nce", now)
		_, err := v.Verify(context.Background(), VerifyInput{Presentation: f.pres, IssuerKey: f.issKey.Public(), ExpectedAud: "", ExpectedNonce: "n0nce", RequireKB: true})
		if !errors.Is(err, ErrKBAudience) {
			t.Fatalf("err = %v, want ErrKBAudience", err)
		}
	})

	t.Run("empty expected nonce rejected even if token nonce is also empty (misconfiguration)", func(t *testing.T) {
		f := newKBFixture(t, "verifier", "", now)
		_, err := v.Verify(context.Background(), VerifyInput{Presentation: f.pres, IssuerKey: f.issKey.Public(), ExpectedAud: "verifier", ExpectedNonce: "", RequireKB: true})
		if !errors.Is(err, ErrKBNonce) {
			t.Fatalf("err = %v, want ErrKBNonce", err)
		}
	})

	// A present KB is verified even when RequireKB is false: a bad nonce fails.
	t.Run("present KB checked despite RequireKB=false", func(t *testing.T) {
		f := newKBFixture(t, "verifier", "stale", now)
		_, err := v.Verify(context.Background(), VerifyInput{Presentation: f.pres, IssuerKey: f.issKey.Public(), ExpectedAud: "verifier", ExpectedNonce: "fresh", RequireKB: false})
		if !errors.Is(err, ErrKBNonce) {
			t.Fatalf("err = %v, want ErrKBNonce", err)
		}
	})
}
