package sdjwt

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// Hard rule 5: Peek must never panic on malformed/adversarial input. Peek is
// pre-trust and unsigned-shape by design, so — unlike FuzzVerify — no signature
// gates the parse: mutation reaches the header/payload decode directly. Seeds
// are real Issue outputs (with/without an x5c chain) plus deliberate negative
// shapes.
func FuzzPeek(f *testing.F) {
	issKey := newECKey(f)
	holder := newECKey(f)
	now := time.Date(2026, 7, 4, 12, 0, 0, 0, time.UTC)
	kp := staticProvider("iss", issKey)

	// A self-signed cert for the with-chain seed.
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "seed"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, issKey.Public(), issKey)
	if err != nil {
		f.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		f.Fatal(err)
	}

	cred := CredentialTemplate{
		VCT:       "urn:eudi:pid:1",
		Issuer:    "https://issuer.example",
		IssuedAt:  now,
		Expiry:    now.Add(24 * time.Hour),
		HolderKey: holder.Public(),
		Claims: map[string]any{
			"given_name": "Arthur",
			"address":    map[string]any{"street_address": "42 Market Street"},
		},
		Selective: []ClaimPath{Path("given_name"), Path("address", "street_address")},
	}
	withChain, err := NewIssuer(kp, "iss", WithChain([]*x509.Certificate{leaf})).Issue(context.Background(), cred)
	if err != nil {
		f.Fatal(err)
	}
	noChain, err := NewIssuer(kp, "iss").Issue(context.Background(), cred)
	if err != nil {
		f.Fatal(err)
	}

	// Structural negatives (b64 is helpers_test.go's base64url encoder).
	sig := b64([]byte("sig"))
	seeds := [][]byte{
		withChain,
		noChain,
		nil,
		[]byte(""),
		[]byte("~"),
		[]byte(jwtShell + "~"),
		[]byte(jwtShell + "~" + d1 + "~"),
		[]byte(jwtShell + "~" + d1 + "~" + d2 + "~" + kbShell),
		[]byte("notajws~" + d1 + "~"),
		[]byte(jwtShell + "~garbage"),                                              // non-JWS KB slot
		[]byte(b64([]byte("{}")) + ".!!!." + sig + "~"),                            // undecodable payload seg
		[]byte(b64([]byte("{}")) + "." + b64([]byte("notjson")) + "." + sig + "~"), // non-JSON payload
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		pk, err := Peek(data) // must not panic
		if err != nil {
			if pk != nil {
				t.Fatalf("err = %v but pk != nil", err)
			}
			return
		}
		if pk == nil {
			t.Fatal("err == nil but pk == nil")
		}
		if pk.DisclosureCount < 0 {
			t.Fatalf("negative DisclosureCount %d", pk.DisclosureCount)
		}
		for i, c := range pk.X5C {
			if c == nil {
				t.Fatalf("X5C[%d] is nil in an accepted peek", i)
			}
		}
	})
}
