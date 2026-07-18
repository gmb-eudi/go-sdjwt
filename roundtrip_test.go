package sdjwt_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	eudicrypto "github.com/gmb-eudi/go-eudi-crypto"
	"github.com/gmb-eudi/go-sdjwt"
)

func genKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func pidTemplate(now time.Time, holder *ecdsa.PrivateKey) sdjwt.CredentialTemplate {
	return sdjwt.CredentialTemplate{
		VCT:       "urn:eudi:pid:1",
		Issuer:    "https://issuer.example",
		IssuedAt:  now,
		Expiry:    now.Add(24 * time.Hour),
		HolderKey: holder.Public(),
		Claims: map[string]any{
			"given_name":  "Arthur",
			"family_name": "Dent",
			"address": map[string]any{
				"street_address": "42 Market Street",
				"locality":       "Milliways",
			},
			"nationalities": []any{"British", "Betelgeusian"},
		},
		// address and nationalities are selective at BOTH the container level
		// and the leaf level (recursive disclosure, [SD-JWT §5.9]): hiding only
		// the leaves would still let a verifier see the container shape
		// (an empty {}/[] claim) even when nothing under it is disclosed.
		// Marking the container itself selective means its own presence
		// requires its own disclosure — see the README Decisions section.
		Selective: []sdjwt.ClaimPath{
			sdjwt.Path("given_name"),
			sdjwt.Path("family_name"),
			sdjwt.Path("address"),
			sdjwt.Path("address", "street_address"),
			sdjwt.Path("address", "locality"),
			sdjwt.Path("nationalities"),
			sdjwt.Path("nationalities", 0),
			sdjwt.Path("nationalities", 1),
		},
	}
}

func TestRoundtripSelectiveDisclosure(t *testing.T) {
	now := time.Date(2026, 7, 4, 12, 0, 0, 0, time.UTC)
	issKey := genKey(t)
	holder := genKey(t)
	kp := eudicrypto.NewStaticProvider(map[string]*ecdsa.PrivateKey{"iss": issKey})
	iss := sdjwt.NewIssuer(kp, "iss")

	sdJWT, err := iss.Issue(context.Background(), pidTemplate(now, holder))
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	pres, err := sdjwt.PresentKB(context.Background(), holder, sdJWT,
		[]sdjwt.ClaimPath{
			sdjwt.Path("given_name"),
			sdjwt.Path("address", "street_address"),
			sdjwt.Path("nationalities", 0),
		},
		"verifier-client-id", "n0nce", now)
	if err != nil {
		t.Fatalf("PresentKB: %v", err)
	}

	v := sdjwt.NewVerifier(sdjwt.WithClock(func() time.Time { return now }))
	vc, err := v.Verify(context.Background(), sdjwt.VerifyInput{
		Presentation:  pres,
		IssuerKey:     issKey.Public(),
		ExpectedAud:   "verifier-client-id",
		ExpectedNonce: "n0nce",
		RequireKB:     true,
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if vc.Claims["given_name"] != "Arthur" {
		t.Errorf("given_name = %v", vc.Claims["given_name"])
	}
	if _, ok := vc.Claims["family_name"]; ok {
		t.Error("family_name disclosed but was not requested")
	}
	addr, ok := vc.Claims["address"].(map[string]any)
	if !ok {
		t.Fatalf("address = %v", vc.Claims["address"])
	}
	if addr["street_address"] != "42 Market Street" {
		t.Errorf("street_address = %v", addr["street_address"])
	}
	if _, ok := addr["locality"]; ok {
		t.Error("locality disclosed but was not requested")
	}
	nat, ok := vc.Claims["nationalities"].([]any)
	if !ok || len(nat) != 1 || nat[0] != "British" {
		t.Errorf("nationalities = %v, want [British]", vc.Claims["nationalities"])
	}
}

// A different subset also verifies (selective disclosure subsets).
func TestRoundtripEmptyDisclosure(t *testing.T) {
	now := time.Date(2026, 7, 4, 12, 0, 0, 0, time.UTC)
	issKey := genKey(t)
	holder := genKey(t)
	kp := eudicrypto.NewStaticProvider(map[string]*ecdsa.PrivateKey{"iss": issKey})
	sdJWT, err := sdjwt.NewIssuer(kp, "iss").Issue(context.Background(), pidTemplate(now, holder))
	if err != nil {
		t.Fatal(err)
	}
	pres, err := sdjwt.PresentKB(context.Background(), holder, sdJWT, nil, "aud", "nonce", now)
	if err != nil {
		t.Fatalf("PresentKB(nil): %v", err)
	}
	v := sdjwt.NewVerifier(sdjwt.WithClock(func() time.Time { return now }))
	vc, err := v.Verify(context.Background(), sdjwt.VerifyInput{Presentation: pres, IssuerKey: issKey.Public(), ExpectedAud: "aud", ExpectedNonce: "nonce", RequireKB: true})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	for _, k := range []string{"given_name", "family_name", "address", "nationalities"} {
		if _, ok := vc.Claims[k]; ok {
			t.Errorf("%q disclosed with empty disclose set", k)
		}
	}
	if vc.VCT != "urn:eudi:pid:1" {
		t.Errorf("VCT = %q", vc.VCT)
	}
}

// The issued SD-JWT (no KB) verifies directly when KB is not required.
func TestIssueVerifyNoKB(t *testing.T) {
	now := time.Date(2026, 7, 4, 12, 0, 0, 0, time.UTC)
	issKey := genKey(t)
	holder := genKey(t)
	kp := eudicrypto.NewStaticProvider(map[string]*ecdsa.PrivateKey{"iss": issKey})
	sdJWT, err := sdjwt.NewIssuer(kp, "iss").Issue(context.Background(), pidTemplate(now, holder))
	if err != nil {
		t.Fatal(err)
	}
	v := sdjwt.NewVerifier(sdjwt.WithClock(func() time.Time { return now }))
	if _, err := v.Verify(context.Background(), sdjwt.VerifyInput{Presentation: sdJWT, IssuerKey: issKey.Public(), RequireKB: false}); err != nil {
		t.Fatalf("Verify issued SD-JWT: %v", err)
	}
}

func TestPresentKBRejects(t *testing.T) {
	now := time.Date(2026, 7, 4, 12, 0, 0, 0, time.UTC)
	issKey := genKey(t)
	holder := genKey(t)
	kp := eudicrypto.NewStaticProvider(map[string]*ecdsa.PrivateKey{"iss": issKey})
	sdJWT, err := sdjwt.NewIssuer(kp, "iss").Issue(context.Background(), pidTemplate(now, holder))
	if err != nil {
		t.Fatal(err)
	}
	// A path that is not selectively disclosable / not present.
	_, err = sdjwt.PresentKB(context.Background(), holder, sdJWT, []sdjwt.ClaimPath{sdjwt.Path("tax_id")}, "aud", "nonce", now)
	if !errors.Is(err, sdjwt.ErrClaimPath) {
		t.Fatalf("err = %v, want ErrClaimPath", err)
	}
	// An invalid path (empty).
	if _, err := sdjwt.PresentKB(context.Background(), holder, sdJWT, []sdjwt.ClaimPath{sdjwt.Path()}, "aud", "nonce", now); !errors.Is(err, sdjwt.ErrClaimPath) {
		t.Fatalf("empty path err = %v, want ErrClaimPath", err)
	}
}

// Pins PresentKB's behavior for a requested path that names an existing
// claim which was never made selective (an always-clear claim). This is not
// an error today — see the "Pinned behavior" note on selectDisclosures in
// present.go — it succeeds and simply adds nothing to the disclosure set for
// that path, since the claim is already present in the clear regardless.
func TestPresentKBNonSelectiveExistingPathIsNoop(t *testing.T) {
	now := time.Date(2026, 7, 4, 12, 0, 0, 0, time.UTC)
	issKey := genKey(t)
	holder := genKey(t)
	kp := eudicrypto.NewStaticProvider(map[string]*ecdsa.PrivateKey{"iss": issKey})
	tmpl := sdjwt.CredentialTemplate{
		VCT:       "urn:eudi:pid:1",
		Issuer:    "https://issuer.example",
		IssuedAt:  now,
		HolderKey: holder.Public(), // PresentKB always attaches a KB-JWT; cnf is required to verify it.
		Claims: map[string]any{
			"given_name": "Arthur", // never listed in Selective: always clear.
		},
	}
	sdJWT, err := sdjwt.NewIssuer(kp, "iss").Issue(context.Background(), tmpl)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// Requesting "given_name" — which exists but was never made selective —
	// must NOT error: it is a documented no-op (nothing to add to the
	// disclosure set), not ErrClaimPath.
	pres, err := sdjwt.PresentKB(context.Background(), holder, sdJWT,
		[]sdjwt.ClaimPath{sdjwt.Path("given_name")}, "aud", "nonce", now)
	if err != nil {
		t.Fatalf("PresentKB on an existing non-selective path returned an error (pinned behavior expects none): %v", err)
	}

	// The claim is present regardless — it was never blinded in the first
	// place. PresentKB always attaches a KB-JWT, so it is verified here too
	// ([SD-JWT §4.3]) — ExpectedAud/ExpectedNonce must match what PresentKB
	// signed above (now fails closed on an empty expected value whenever
	// a KB is actually verified).
	v := sdjwt.NewVerifier(sdjwt.WithClock(func() time.Time { return now }))
	vc, err := v.Verify(context.Background(), sdjwt.VerifyInput{
		Presentation: pres, IssuerKey: issKey.Public(),
		ExpectedAud: "aud", ExpectedNonce: "nonce", RequireKB: false,
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if vc.Claims["given_name"] != "Arthur" {
		t.Errorf("given_name = %v", vc.Claims["given_name"])
	}
}

func TestIssueRejectsBadTemplate(t *testing.T) {
	kp := eudicrypto.NewStaticProvider(map[string]*ecdsa.PrivateKey{"iss": genKey(t)})
	iss := sdjwt.NewIssuer(kp, "iss")
	for name, tmpl := range map[string]sdjwt.CredentialTemplate{
		"no vct":              {Issuer: "x", Claims: map[string]any{"a": 1}},
		"no iss":              {VCT: "urn:eudi:pid:1", Claims: map[string]any{"a": 1}},
		"nil claims":          {VCT: "urn:eudi:pid:1", Issuer: "x"},
		"bad hash":            {VCT: "urn:eudi:pid:1", Issuer: "x", Claims: map[string]any{"a": 1}, HashName: "sha-1"},
		"reserved kv":         {VCT: "urn:eudi:pid:1", Issuer: "x", Claims: map[string]any{"iss": "shadow"}},
		"nested reserved key": {VCT: "urn:eudi:pid:1", Issuer: "x", Claims: map[string]any{"address": map[string]any{"_sd": "shadow"}}},
		"unmatched selective": {VCT: "urn:eudi:pid:1", Issuer: "x", Claims: map[string]any{"a": 1}, Selective: []sdjwt.ClaimPath{sdjwt.Path("nope")}},
		"invalid selective":   {VCT: "urn:eudi:pid:1", Issuer: "x", Claims: map[string]any{"a": 1}, Selective: []sdjwt.ClaimPath{sdjwt.Path()}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := iss.Issue(context.Background(), tmpl); !errors.Is(err, sdjwt.ErrTemplate) {
				t.Fatalf("err = %v, want ErrTemplate", err)
			}
		})
	}
}

// GDPR regression (no attribute values in errors): a claim value that fails JSON marshaling
// (math.NaN() — json.Marshal reports it via *json.UnsupportedValueError,
// whose message embeds the offending value verbatim: "json: unsupported
// value: NaN") must not leak that value into the returned error. This
// exercises all three json.Marshal call sites in issue.go: the payload
// marshal (non-selective claim), the object-disclosure marshal (selective
// scalar claim), and the array-disclosure marshal (selective array element).
func TestIssueClaimMarshalErrorDoesNotLeakValue(t *testing.T) {
	kp := eudicrypto.NewStaticProvider(map[string]*ecdsa.PrivateKey{"iss": genKey(t)})
	iss := sdjwt.NewIssuer(kp, "iss")
	for name, tmpl := range map[string]sdjwt.CredentialTemplate{
		"non-selective claim (payload marshal)": {
			VCT: "urn:eudi:pid:1", Issuer: "x",
			Claims: map[string]any{"a": math.NaN()},
		},
		"selective scalar claim (object disclosure marshal)": {
			VCT: "urn:eudi:pid:1", Issuer: "x",
			Claims:    map[string]any{"a": math.NaN()},
			Selective: []sdjwt.ClaimPath{sdjwt.Path("a")},
		},
		"selective array element (array disclosure marshal)": {
			VCT: "urn:eudi:pid:1", Issuer: "x",
			Claims:    map[string]any{"a": []any{math.NaN()}},
			Selective: []sdjwt.ClaimPath{sdjwt.Path("a", 0)},
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := iss.Issue(context.Background(), tmpl)
			if !errors.Is(err, sdjwt.ErrTemplate) {
				t.Fatalf("err = %v, want ErrTemplate", err)
			}
			if strings.Contains(err.Error(), "NaN") {
				t.Fatalf("error leaks claim value: %v", err)
			}
		})
	}
}
