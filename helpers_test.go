package sdjwt

import (
	"context"
	stdcrypto "crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"

	eudicrypto "github.com/gmb-eudi/go-eudi-crypto"
)

// newECKey returns a fresh P-256 key (test fixture; the algorithm literal is
// permitted in tests, as in go-eudi-crypto's own tests). Takes testing.TB
// (not *testing.T) so FuzzVerify's seed-construction phase (*testing.F) can
// call it too.
func newECKey(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// b64 is base64url without padding (SD-JWT §4.2).
func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// mkDisclosure builds an object-property disclosure [salt, name, value] and
// returns (base64url disclosure string, its sha-256 digest string). testing.TB
// so both *testing.T (unit tests) and *testing.F (FuzzVerify seeds) can call it.
func mkDisclosure(t testing.TB, salt, name string, value any) (string, string) {
	t.Helper()
	raw, err := json.Marshal([]any{salt, name, value})
	if err != nil {
		t.Fatal(err)
	}
	enc := b64(raw)
	sum := sha256.Sum256([]byte(enc))
	return enc, b64(sum[:])
}

// mkArrayDisclosure builds an array-element disclosure [salt, value].
func mkArrayDisclosure(t testing.TB, salt string, value any) (string, string) {
	t.Helper()
	raw, err := json.Marshal([]any{salt, value})
	if err != nil {
		t.Fatal(err)
	}
	enc := b64(raw)
	sum := sha256.Sum256([]byte(enc))
	return enc, b64(sum[:])
}

// sha256Hash is the crypto.Hash used by the test vectors.
func sha256Hash() stdcrypto.Hash { return stdcrypto.SHA256 }

// staticProvider wraps one signing key for crypto.SignJWS.
func staticProvider(keyID string, k *ecdsa.PrivateKey) eudicrypto.KeyProvider {
	return eudicrypto.NewStaticProvider(map[string]*ecdsa.PrivateKey{keyID: k})
}

// signIssuerJWT signs payload as an issuer JWT (typ header set; alg derived
// from the key by crypto.SignJWS).
func signIssuerJWT(t testing.TB, kp eudicrypto.KeyProvider, keyID, typ string, payload map[string]any) []byte {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := eudicrypto.SignJWS(context.Background(), kp, keyID, map[string]any{hdrTyp: typ}, body)
	if err != nil {
		t.Fatalf("SignJWS: %v", err)
	}
	return tok
}

// assemble builds a combined-format presentation (issuer JWT + disclosures +
// trailing '~', no KB-JWT).
func assemble(issuer []byte, discs ...string) []byte {
	out := append([]byte{}, issuer...)
	out = append(out, '~')
	for _, d := range discs {
		out = append(out, d...)
		out = append(out, '~')
	}
	return out
}

// jwkOf returns the cnf.jwk map for a public key.
func jwkOf(t testing.TB, pub stdcrypto.PublicKey) map[string]any {
	t.Helper()
	j, err := eudicrypto.ECPublicKeyToJWK(pub)
	if err != nil {
		t.Fatal(err)
	}
	return j
}
