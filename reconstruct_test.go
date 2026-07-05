package sdjwt

import (
	"crypto/sha512"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	eudicrypto "github.com/gmb-eudi/go-eudi-crypto"
)

func TestHashForSDAlg(t *testing.T) {
	pol := eudicrypto.ECCG()
	if _, err := hashForSDAlg(pol, map[string]any{}); err != nil {
		t.Errorf("absent _sd_alg should default to sha-256: %v", err)
	}
	if _, err := hashForSDAlg(pol, map[string]any{claimSDAlg: "sha-512"}); err != nil {
		t.Errorf("sha-512: %v", err)
	}
	if _, err := hashForSDAlg(pol, map[string]any{claimSDAlg: "sha-1"}); !errors.Is(err, ErrHashAlg) {
		t.Errorf("sha-1 err = %v, want ErrHashAlg", err)
	}
	if _, err := hashForSDAlg(pol, map[string]any{claimSDAlg: 256}); !errors.Is(err, ErrHashAlg) {
		t.Errorf("non-string _sd_alg err = %v, want ErrHashAlg", err)
	}
}

// Positive: an object with a nested object and an array reconstructs exactly.
// Mirrors the SD-JWT §7 processing example (synthetic vector; ADR-0007).
func TestReconstructPositive(t *testing.T) {
	dGiven, digGiven := mkDisclosure(t, "s0", "given_name", "Arthur")
	dStreet, digStreet := mkDisclosure(t, "s1", "street_address", "42 Market Street")
	dNat0, digNat0 := mkArrayDisclosure(t, "s2", "British")

	payload := map[string]any{
		claimSDAlg: "sha-256",
		"vct":      "urn:eudi:pid:1",
		claimSD:    []any{digGiven},
		"address": map[string]any{
			claimSD: []any{digStreet},
		},
		"nationalities": []any{
			map[string]any{claimEllipsis: digNat0},
			"Betelgeusian", // always-disclosed array element
		},
	}

	claims, decoys, err := reconstruct(payload, [][]byte{[]byte(dGiven), []byte(dStreet), []byte(dNat0)}, sha256Hash())
	if err != nil {
		t.Fatalf("reconstruct: %v", err)
	}
	if decoys != 0 {
		t.Errorf("decoys = %d, want 0", decoys)
	}
	want := map[string]any{
		"vct":           "urn:eudi:pid:1",
		"given_name":    "Arthur",
		"address":       map[string]any{"street_address": "42 Market Street"},
		"nationalities": []any{"British", "Betelgeusian"},
	}
	if !reflect.DeepEqual(claims, want) {
		t.Errorf("claims =\n%#v\nwant\n%#v", claims, want)
	}
}

// Recursive disclosure: the disclosed "address" object itself carries an _sd
// whose disclosure reveals "street_address".
func TestReconstructRecursive(t *testing.T) {
	dStreet, digStreet := mkDisclosure(t, "s1", "street_address", "42 Market Street")
	addressValue := map[string]any{claimSD: []any{digStreet}}
	dAddr, digAddr := mkDisclosure(t, "s0", "address", addressValue)

	payload := map[string]any{
		claimSDAlg: "sha-256",
		claimSD:    []any{digAddr},
	}
	claims, _, err := reconstruct(payload, [][]byte{[]byte(dAddr), []byte(dStreet)}, sha256Hash())
	if err != nil {
		t.Fatalf("reconstruct: %v", err)
	}
	want := map[string]any{"address": map[string]any{"street_address": "42 Market Street"}}
	if !reflect.DeepEqual(claims, want) {
		t.Errorf("claims = %#v, want %#v", claims, want)
	}
}

// Decoys: digests with no matching disclosure are skipped silently and
// counted; they never surface as claims.
func TestReconstructDecoysCounted(t *testing.T) {
	dGiven, digGiven := mkDisclosure(t, "s0", "given_name", "Arthur")
	payload := map[string]any{
		claimSD: []any{digGiven, "AAAAdecoy1AAAA", "BBBBdecoy2BBBB"},
	}
	claims, decoys, err := reconstruct(payload, [][]byte{[]byte(dGiven)}, sha256Hash())
	if err != nil {
		t.Fatalf("reconstruct: %v", err)
	}
	if decoys != 2 {
		t.Errorf("decoys = %d, want 2", decoys)
	}
	if _, leaked := claims[claimSD]; leaked {
		t.Error("_sd leaked into claims")
	}
	if !reflect.DeepEqual(claims, map[string]any{"given_name": "Arthur"}) {
		t.Errorf("claims = %#v", claims)
	}
}

// Array decoys: an array-element wrapper {"...": <digest>} with no matching
// disclosure is omitted from the reconstructed array and counted, mirroring
// TestReconstructDecoysCounted's coverage of the object _sd decoy path
// (SD-JWT §4.2.5).
func TestReconstructArrayDecoysCounted(t *testing.T) {
	payload := map[string]any{
		"tags": []any{
			"clear",
			map[string]any{claimEllipsis: "AAAAdecoy1AAAA"},
		},
	}
	claims, decoys, err := reconstruct(payload, nil, sha256Hash())
	if err != nil {
		t.Fatalf("reconstruct: %v", err)
	}
	if decoys != 1 {
		t.Errorf("decoys = %d, want 1", decoys)
	}
	want := map[string]any{"tags": []any{"clear"}}
	if !reflect.DeepEqual(claims, want) {
		t.Errorf("claims = %#v, want %#v", claims, want)
	}
}

// Reconstruction is hash-agnostic: hashForSDAlg already resolves "sha-512"
// via the ECCG policy (TestHashForSDAlg above); this drives reconstruct
// itself end to end with that hash, closing the loop between the two.
func TestReconstructSHA512(t *testing.T) {
	pol := eudicrypto.ECCG()
	h, err := hashForSDAlg(pol, map[string]any{claimSDAlg: "sha-512"})
	if err != nil {
		t.Fatalf("hashForSDAlg: %v", err)
	}

	raw, err := json.Marshal([]any{"s0", "given_name", "Arthur"})
	if err != nil {
		t.Fatal(err)
	}
	enc := b64(raw)
	sum := sha512.Sum512([]byte(enc))
	dig := b64(sum[:])

	payload := map[string]any{
		claimSDAlg: "sha-512",
		claimSD:    []any{dig},
	}
	claims, decoys, err := reconstruct(payload, [][]byte{[]byte(enc)}, h)
	if err != nil {
		t.Fatalf("reconstruct: %v", err)
	}
	if decoys != 0 {
		t.Errorf("decoys = %d, want 0", decoys)
	}
	want := map[string]any{"given_name": "Arthur"}
	if !reflect.DeepEqual(claims, want) {
		t.Errorf("claims = %#v, want %#v", claims, want)
	}
}

func TestReconstructNegatives(t *testing.T) {
	dGiven, digGiven := mkDisclosure(t, "s0", "given_name", "Arthur")

	t.Run("swapped/forged disclosure not referenced", func(t *testing.T) {
		// payload references digGiven, but we supply a different disclosure.
		dOther, _ := mkDisclosure(t, "s9", "family_name", "Dent")
		payload := map[string]any{claimSD: []any{digGiven}}
		_, _, err := reconstruct(payload, [][]byte{[]byte(dOther)}, sha256Hash())
		if !errors.Is(err, ErrDigestMismatch) {
			t.Fatalf("err = %v, want ErrDigestMismatch", err)
		}
	})

	t.Run("forged salt changes digest → unused", func(t *testing.T) {
		forged, _ := mkDisclosure(t, "TAMPERED", "given_name", "Arthur")
		payload := map[string]any{claimSD: []any{digGiven}}
		_, _, err := reconstruct(payload, [][]byte{[]byte(forged)}, sha256Hash())
		if !errors.Is(err, ErrDigestMismatch) {
			t.Fatalf("err = %v, want ErrDigestMismatch", err)
		}
	})

	t.Run("digest reuse across two _sd arrays", func(t *testing.T) {
		payload := map[string]any{
			claimSD:  []any{digGiven},
			"nested": map[string]any{claimSD: []any{digGiven}},
		}
		_, _, err := reconstruct(payload, [][]byte{[]byte(dGiven)}, sha256Hash())
		if !errors.Is(err, ErrDuplicateDigest) {
			t.Fatalf("err = %v, want ErrDuplicateDigest", err)
		}
	})

	t.Run("duplicate digest within one _sd array", func(t *testing.T) {
		payload := map[string]any{claimSD: []any{digGiven, digGiven}}
		_, _, err := reconstruct(payload, [][]byte{[]byte(dGiven)}, sha256Hash())
		if !errors.Is(err, ErrDuplicateDigest) {
			t.Fatalf("err = %v, want ErrDuplicateDigest", err)
		}
	})

	// A duplicated digest is rejected even when neither occurrence has a
	// matching disclosure (decoys): the SD-JWT digest namespace must stay
	// 1:1 payload-wide, or a repeated string could be used to smuggle
	// ambiguity into later processing (fail closed, hard rule 7). See
	// WP-02 README Decisions.
	t.Run("duplicate decoy digest (no matching disclosure) rejected", func(t *testing.T) {
		payload := map[string]any{claimSD: []any{"AAAAdecoyAAAA", "AAAAdecoyAAAA"}}
		_, _, err := reconstruct(payload, nil, sha256Hash())
		if !errors.Is(err, ErrDuplicateDigest) {
			t.Fatalf("err = %v, want ErrDuplicateDigest", err)
		}
	})

	t.Run("_sd not an array", func(t *testing.T) {
		payload := map[string]any{claimSD: "not-an-array"}
		if _, _, err := reconstruct(payload, nil, sha256Hash()); !errors.Is(err, ErrMalformed) {
			t.Fatalf("err = %v, want ErrMalformed", err)
		}
	})

	t.Run("_sd element not a string", func(t *testing.T) {
		payload := map[string]any{claimSD: []any{42}}
		if _, _, err := reconstruct(payload, nil, sha256Hash()); !errors.Is(err, ErrMalformed) {
			t.Fatalf("err = %v, want ErrMalformed", err)
		}
	})

	t.Run("disclosed claim collides with a clear claim", func(t *testing.T) {
		dName, digName := mkDisclosure(t, "s0", "given_name", "Arthur")
		payload := map[string]any{
			"given_name": "already here",
			claimSD:      []any{digName},
		}
		_, _, err := reconstruct(payload, [][]byte{[]byte(dName)}, sha256Hash())
		if !errors.Is(err, ErrClaimCollision) {
			t.Fatalf("err = %v, want ErrClaimCollision", err)
		}
	})

	t.Run("object disclosure with wrong element count", func(t *testing.T) {
		bad, digBad := mkArrayDisclosure(t, "s0", "value") // 2-element, used as object digest
		payload := map[string]any{claimSD: []any{digBad}}
		_, _, err := reconstruct(payload, [][]byte{[]byte(bad)}, sha256Hash())
		if !errors.Is(err, ErrDisclosure) {
			t.Fatalf("err = %v, want ErrDisclosure", err)
		}
	})

	t.Run("disclosure name is a reserved key", func(t *testing.T) {
		bad, digBad := mkDisclosure(t, "s0", claimSD, "x")
		payload := map[string]any{claimSD: []any{digBad}}
		_, _, err := reconstruct(payload, [][]byte{[]byte(bad)}, sha256Hash())
		if !errors.Is(err, ErrDisclosure) {
			t.Fatalf("err = %v, want ErrDisclosure", err)
		}
	})

	// SD-JWT §4.2.2 reserves "..." exclusively for the array-element digest
	// wrapper ({"...": "<digest>"}). A literal "..." key in a plain JSON
	// object is not that wrapper — it must be rejected rather than silently
	// surfaced as a claim named "..." (fail closed, hard rule 7). No
	// conformant issuer ever emits this.
	t.Run("literal \"...\" object key rejected", func(t *testing.T) {
		payload := map[string]any{claimEllipsis: "not-a-digest-wrapper"}
		_, _, err := reconstruct(payload, nil, sha256Hash())
		if !errors.Is(err, ErrMalformed) {
			t.Fatalf("err = %v, want ErrMalformed", err)
		}
	})

	// An array-element "..." wrapper must be exactly {"...": "<digest>"}
	// (SD-JWT §4.2.2). An element carrying "..." alongside any other key is
	// ambiguous — neither a clean digest wrapper nor ordinary data — and must
	// be rejected rather than passed through as a regular array element.
	t.Run("array element with \"...\" plus extra key rejected", func(t *testing.T) {
		payload := map[string]any{
			"tags": []any{
				map[string]any{claimEllipsis: "AAAAdecoy1AAAA", "extra": "e"},
			},
		}
		_, _, err := reconstruct(payload, nil, sha256Hash())
		if !errors.Is(err, ErrMalformed) {
			t.Fatalf("err = %v, want ErrMalformed", err)
		}
	})

	t.Run("undecodable base64url disclosure", func(t *testing.T) {
		_, _, err := reconstruct(map[string]any{}, [][]byte{[]byte("!!!not-base64!!!")}, sha256Hash())
		if !errors.Is(err, ErrDisclosure) {
			t.Fatalf("err = %v, want ErrDisclosure", err)
		}
	})

	// hard rule 3 / GDPR: a *json.SyntaxError for this input would read
	// `invalid character 'S' looking for beginning of value` — "S" is the
	// first byte of the decoded disclosure content ([salt, name, value]).
	// That byte (and the sentinel word it starts) must never reach the
	// returned error.
	t.Run("malformed JSON disclosure never echoes decoded content", func(t *testing.T) {
		raw := b64([]byte(`["s0","given_name",SENTINELVALUE]`))
		_, _, err := reconstruct(map[string]any{}, [][]byte{[]byte(raw)}, sha256Hash())
		if !errors.Is(err, ErrDisclosure) {
			t.Fatalf("err = %v, want ErrDisclosure", err)
		}
		if strings.Contains(err.Error(), "SENTINELVALUE") || strings.Contains(err.Error(), "'S'") {
			t.Fatalf("error leaked decoded disclosure content: %q", err.Error())
		}
	})
}
