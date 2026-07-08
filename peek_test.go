package sdjwt_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"math/big"
	"testing"
	"time"

	eudicrypto "github.com/gmb-eudi/go-eudi-crypto"
	"github.com/gmb-eudi/go-sdjwt"
)

func peekCert(t *testing.T, key *ecdsa.PrivateKey, cn string) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func b64url(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

// mkIssuerJWT builds a structurally-valid (unsigned-shape) compact JWS from a
// raw header/payload JSON — for exercising Peek's structural decode paths
// without needing a real signature (Peek never verifies).
func mkIssuerJWT(headerJSON, payloadJSON string) string {
	return b64url(headerJSON) + "." + b64url(payloadJSON) + "." + b64url("sig")
}

// Peek must surface the embedded x5c chain (leaf first, exact DER) plus
// typ/iss/vct/disclosure-count from a real Issue output — WITHOUT verifying the
// signature. WithChain feeds the chain into the issued JWS header.
func TestPeekWithChain(t *testing.T) {
	now := time.Date(2026, 7, 4, 12, 0, 0, 0, time.UTC)
	issKey := genKey(t)
	holder := genKey(t)
	leaf := peekCert(t, issKey, "leaf.example")
	ca := peekCert(t, issKey, "ca.example")
	chain := []*x509.Certificate{leaf, ca}

	kp := eudicrypto.NewStaticProvider(map[string]*ecdsa.PrivateKey{"iss": issKey})
	iss := sdjwt.NewIssuer(kp, "iss", sdjwt.WithChain(chain))
	sdJWT, err := iss.Issue(context.Background(), pidTemplate(now, holder))
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	pk, err := sdjwt.Peek(sdJWT)
	if err != nil {
		t.Fatalf("Peek: %v", err)
	}
	if pk.Typ != "dc+sd-jwt" {
		t.Errorf("Typ = %q, want dc+sd-jwt", pk.Typ)
	}
	if pk.Iss != "https://issuer.example" {
		t.Errorf("Iss = %q", pk.Iss)
	}
	if pk.VCT != "urn:eudi:pid:1" {
		t.Errorf("VCT = %q", pk.VCT)
	}
	if len(pk.X5C) != len(chain) {
		t.Fatalf("X5C len = %d, want %d", len(pk.X5C), len(chain))
	}
	for i := range chain {
		if !bytes.Equal(pk.X5C[i].Raw, chain[i].Raw) {
			t.Errorf("X5C[%d] DER mismatch (order or bytes wrong)", i)
		}
	}
	// DisclosureCount == number of ~-separated disclosure segments (no KB).
	wantDisc := bytes.Count(sdJWT, []byte("~")) - 1
	if pk.DisclosureCount != wantDisc {
		t.Errorf("DisclosureCount = %d, want %d", pk.DisclosureCount, wantDisc)
	}
}

// Without WithChain, Issue embeds no x5c and Peek.X5C is nil — while typ/iss/
// vct/count are still read. Also proves the 2-arg NewIssuer stays valid.
func TestPeekNoChain(t *testing.T) {
	now := time.Date(2026, 7, 4, 12, 0, 0, 0, time.UTC)
	issKey := genKey(t)
	holder := genKey(t)
	kp := eudicrypto.NewStaticProvider(map[string]*ecdsa.PrivateKey{"iss": issKey})
	sdJWT, err := sdjwt.NewIssuer(kp, "iss").Issue(context.Background(), pidTemplate(now, holder))
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	pk, err := sdjwt.Peek(sdJWT)
	if err != nil {
		t.Fatalf("Peek: %v", err)
	}
	if pk.X5C != nil {
		t.Errorf("X5C = %v, want nil (no chain configured)", pk.X5C)
	}
	if pk.Typ != "dc+sd-jwt" || pk.Iss != "https://issuer.example" || pk.VCT != "urn:eudi:pid:1" {
		t.Errorf("peek = %+v", pk)
	}
	if pk.DisclosureCount != bytes.Count(sdJWT, []byte("~"))-1 {
		t.Errorf("DisclosureCount = %d", pk.DisclosureCount)
	}
}

// The documented contract: Peek does NOT verify the signature. A token whose
// signature has been tampered must still Peek successfully (returning the
// unverified header/payload fields), while Verify rejects it.
func TestPeekDoesNotVerifySignature(t *testing.T) {
	now := time.Date(2026, 7, 4, 12, 0, 0, 0, time.UTC)
	issKey := genKey(t)
	holder := genKey(t)
	kp := eudicrypto.NewStaticProvider(map[string]*ecdsa.PrivateKey{"iss": issKey})
	sdJWT, err := sdjwt.NewIssuer(kp, "iss").Issue(context.Background(), pidTemplate(now, holder))
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// Flip a byte in the issuer JWT's signature segment (3rd '.'-segment of the
	// segment before the first '~'). Header/payload segments are untouched.
	tilde := bytes.IndexByte(sdJWT, '~')
	issuerSeg := sdJWT[:tilde]
	lastDot := bytes.LastIndexByte(issuerSeg, '.')
	tampered := append([]byte{}, sdJWT...)
	sigStart := lastDot + 1
	// Change the first signature char to a different valid base64url char, so
	// the token stays structurally valid but the signature no longer verifies.
	if tampered[sigStart] == 'A' {
		tampered[sigStart] = 'B'
	} else {
		tampered[sigStart] = 'A'
	}

	pk, err := sdjwt.Peek(tampered)
	if err != nil {
		t.Fatalf("Peek on signature-invalid token = %v, want success (Peek must not verify)", err)
	}
	if pk.Iss != "https://issuer.example" || pk.VCT != "urn:eudi:pid:1" {
		t.Errorf("peek fields lost on tampered token: %+v", pk)
	}

	// And Verify MUST reject it — proving Peek's success is not verification.
	v := sdjwt.NewVerifier(sdjwt.WithClock(func() time.Time { return now }))
	if _, verr := v.Verify(context.Background(), sdjwt.VerifyInput{
		Presentation: tampered, IssuerKey: issKey.Public(), RequireKB: false,
	}); !errors.Is(verr, sdjwt.ErrIssuerSignature) {
		t.Fatalf("Verify(tampered) = %v, want ErrIssuerSignature", verr)
	}
}

func TestPeekMalformed(t *testing.T) {
	cases := map[string][]byte{
		"empty":                    []byte(""),
		"no tilde separator":       []byte(mkIssuerJWT("{}", "{}")),
		"issuer not a compact JWS": []byte("notajws~"),
		"undecodable payload seg":  []byte(b64url("{}") + ".!!!not-base64!!!." + b64url("sig") + "~"),
		"non-json payload":         []byte(mkIssuerJWT("{}", "notjson") + "~"),
		"malformed x5c in header":  []byte(mkIssuerJWT(`{"x5c":["!!!not-base64!!!"]}`, "{}") + "~"),
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := sdjwt.Peek(in); !errors.Is(err, sdjwt.ErrMalformed) {
				t.Errorf("err = %v, want ErrMalformed", err)
			}
		})
	}
}

// Missing iss/vct is NOT an error — Peek reports structure, not presence.
func TestPeekMissingIssVCTNotError(t *testing.T) {
	in := []byte(mkIssuerJWT(`{"typ":"dc+sd-jwt"}`, "{}") + "~")
	pk, err := sdjwt.Peek(in)
	if err != nil {
		t.Fatalf("Peek = %v, want no error for missing iss/vct", err)
	}
	if pk.Iss != "" || pk.VCT != "" {
		t.Errorf("expected empty iss/vct, got %+v", pk)
	}
	if pk.Typ != "dc+sd-jwt" {
		t.Errorf("Typ = %q", pk.Typ)
	}
}
