package sdjwt

import (
	"context"
	stdcrypto "crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
	"time"

	eudicrypto "github.com/gmb-eudi/go-eudi-crypto"
)

// Hard rule 5: Verify must never panic on malformed/adversarial input. The
// seed corpus below is STRUCTURED, not random bytes: every seed is either a
// genuinely valid presentation (built via the Issue/PresentKB façade, T-02.7)
// or a deliberate negative shape mirroring a named test from T-02.2
// (combined-format parsing), T-02.3 (disclosure/digest reconstruction),
// T-02.4 (issuer envelope), or T-02.5 (KB-JWT). Every signed seed uses the
// SAME issKey/holder/rogue keys the fuzz Verifier below trusts, so mutation
// explores realistic neighborhoods of both the accept and reject paths
// instead of forever failing at the outermost signature check.
func FuzzVerify(f *testing.F) {
	issKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	holder, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	rogue, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	fixedNow := time.Date(2026, 7, 4, 12, 0, 0, 0, time.UTC)
	kp := staticProvider("iss", issKey)
	holderJWK := jwkOf(f, holder.Public())
	h := stdcrypto.SHA256

	// --- T-02.7: a genuinely valid presentation (accept-path seed), issued
	// and presented through the public façade with the keys this fuzz run's
	// Verifier trusts.
	sdJWT, err := NewIssuer(kp, "iss").Issue(context.Background(), CredentialTemplate{
		VCT:       "urn:eudi:pid:1",
		Issuer:    "https://issuer.example",
		IssuedAt:  fixedNow,
		Expiry:    fixedNow.Add(24 * time.Hour),
		HolderKey: holder.Public(),
		Claims: map[string]any{
			"given_name": "Arthur",
			"address":    map[string]any{"street_address": "42 Market Street"},
		},
		Selective: []ClaimPath{Path("given_name"), Path("address", "street_address")},
	})
	if err != nil {
		f.Fatal(err)
	}
	validPres, err := PresentKB(context.Background(), holder, sdJWT,
		[]ClaimPath{Path("given_name")}, "aud", "nonce", fixedNow)
	if err != nil {
		f.Fatal(err)
	}

	// --- T-02.4 issuer-envelope negatives: basePayload (verify_test.go) is
	// the same minimal "iss/vct/_sd_alg + one disclosable given_name" fixture
	// TestVerifyEnvelopeNegatives itself mutates; buildEnvelope re-signs it
	// with a mutated payload and/or typ header.
	buildEnvelope := func(mut func(p map[string]any), typ string) []byte {
		p, disc := basePayload(f, holderJWK)
		if mut != nil {
			mut(p)
		}
		return assemble(signIssuerJWT(f, kp, "iss", typ, p), disc)
	}

	// --- T-02.3 disclosure/digest negatives: same shapes as
	// TestReconstructNegatives, wrapped in a real issuer JWT signed with
	// issKey so the fuzz Verify pipeline actually reaches reconstruction.
	buildDisclosure := func(payload map[string]any, discs ...string) []byte {
		payload[claimISS] = "https://issuer.example"
		payload[claimVCT] = "urn:eudi:pid:1"
		return assemble(signIssuerJWT(f, kp, "iss", typSDJWT, payload), discs...)
	}
	dGiven, digGiven := mkDisclosure(f, "s0", "given_name", "Arthur")
	dOther, _ := mkDisclosure(f, "s9", "family_name", "Dent")
	dReserved, digReserved := mkDisclosure(f, "s0", claimSD, "x")
	dBadCount, digBadCount := mkArrayDisclosure(f, "s0", "value")

	// --- T-02.5 KB-JWT negatives: one signed issuer JWT WITH cnf (so the KB
	// branch is reached) and one WITHOUT (for the "KB present, no cnf" case),
	// both keyed off the same issKey/holder/rogue as the fuzz Verifier.
	payloadCNF, discCNF := basePayload(f, holderJWK)
	sdPartCNF := assemble(signIssuerJWT(f, kp, "iss", typSDJWT, payloadCNF), discCNF)
	payloadNoCNF, discNoCNF := basePayload(f, nil)
	sdPartNoCNF := assemble(signIssuerJWT(f, kp, "iss", typSDJWT, payloadNoCNF), discNoCNF)
	tamperedSDPart := append(append([]byte{}, sdPartCNF...), []byte("EXTRA~")...)
	wrongTypKB := func() []byte {
		body, err := json.Marshal(map[string]any{
			claimIAT: fixedNow.Unix(), claimAUD: "aud", claimNonce: "nonce",
			claimSDHash: digest(sdPartCNF, h),
		})
		if err != nil {
			f.Fatal(err)
		}
		kb, err := eudicrypto.SignJWS(context.Background(), staticProvider("h", holder), "h", map[string]any{hdrTyp: "JWT"}, body)
		if err != nil {
			f.Fatal(err)
		}
		return kb
	}()

	seeds := [][]byte{
		// --- T-02.7 / accept path ---
		validPres,
		sdJWT, // issued, no KB (accepts when RequireKB=false; ErrKBRequired when true)

		// --- T-02.2: malformed combined format ---
		nil,
		[]byte(""),
		[]byte("~"),
		[]byte(jwtShell + "~"),
		[]byte(jwtShell + "~" + d1 + "~"),
		[]byte(jwtShell + "~~" + d1 + "~"),       // empty disclosure segment
		[]byte(jwtShell + "~" + d1 + "~garbage"), // trailing garbage in KB slot
		[]byte(jwtShell + "~" + d1 + "~" + d2 + "~" + kbShell), // unverifiable KB (right shape, wrong keys)
		[]byte("notajws~" + d1 + "~"),
		append(append([]byte{}, validPres...), []byte("~EXTRA")...),              // tampered tail of a real presentation
		[]byte(jwtShell + "~" + strings.Repeat("A", maxPresentationBytes) + "~"), // oversized
		[]byte(jwtShell + "~" + strings.Repeat(d1+"~", maxDisclosures+1)),        // too many disclosures

		// --- T-02.4: issuer envelope negatives ---
		buildEnvelope(nil, "JWT"),      // wrong typ
		buildEnvelope(nil, typVCSDJWT), // legacy typ rejected by default (no WithLegacyVCTyp)
		buildEnvelope(func(p map[string]any) { delete(p, claimISS) }, typSDJWT),                                              // missing iss
		buildEnvelope(func(p map[string]any) { delete(p, claimVCT) }, typSDJWT),                                              // missing vct
		buildEnvelope(func(p map[string]any) { p[claimEXP] = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC).Unix() }, typSDJWT), // expired
		buildEnvelope(func(p map[string]any) { p[claimNBF] = time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC).Unix() }, typSDJWT), // not yet valid
		buildEnvelope(func(p map[string]any) { delete(p, claimCNF) }, typSDJWT),                                              // no cnf (ErrMissingCNF when RequireKB)
		buildEnvelope(func(p map[string]any) { p[claimCNF] = map[string]any{} }, typSDJWT),                                   // malformed cnf: jwk absent
		buildEnvelope(func(p map[string]any) { p[claimCNF] = map[string]any{claimJWK: "not-an-object"} }, typSDJWT),          // malformed cnf: jwk garbage

		// --- T-02.3: disclosure/digest negatives ---
		buildDisclosure(map[string]any{claimSD: []any{digGiven}}, dOther),                                                     // swapped/forged: referenced digest never matched
		buildDisclosure(map[string]any{claimSD: []any{digGiven}, "nested": map[string]any{claimSD: []any{digGiven}}}, dGiven), // digest reuse across two _sd arrays
		buildDisclosure(map[string]any{claimSD: []any{digReserved}}, dReserved),                                               // disclosure name is reserved ("_sd")
		buildDisclosure(map[string]any{"given_name": "already here", claimSD: []any{digGiven}}, dGiven),                       // disclosed claim collides with a clear claim
		buildDisclosure(map[string]any{claimSD: []any{digBadCount}}, dBadCount),                                               // object disclosure with wrong (2) element count
		buildDisclosure(map[string]any{claimSD: []any{digGiven}}, "!!!not-base64!!!"),                                         // undecodable base64url disclosure

		// --- T-02.5: KB-JWT negatives (all reach verifyKB) ---
		sdPartCNF, // KB required but absent
		append(append([]byte{}, sdPartNoCNF...), signKB(f, holder, sdPartNoCNF, "aud", "nonce", fixedNow, h)...),               // KB present, issuer has no cnf
		append(append([]byte{}, sdPartCNF...), signKB(f, holder, sdPartCNF, "wrong-aud", "nonce", fixedNow, h)...),             // aud mismatch
		append(append([]byte{}, sdPartCNF...), signKB(f, holder, sdPartCNF, "aud", "wrong-nonce", fixedNow, h)...),             // nonce mismatch
		append(append([]byte{}, sdPartCNF...), signKB(f, holder, sdPartCNF, "aud", "nonce", fixedNow.Add(-1*time.Hour), h)...), // stale iat (replay)
		append(append([]byte{}, sdPartCNF...), signKB(f, holder, sdPartCNF, "aud", "nonce", fixedNow.Add(1*time.Hour), h)...),  // iat in the future
		append(append([]byte{}, sdPartCNF...), signKB(f, holder, tamperedSDPart, "aud", "nonce", fixedNow, h)...),              // sd_hash over a different disclosure set
		append(append([]byte{}, sdPartCNF...), signKB(f, rogue, sdPartCNF, "aud", "nonce", fixedNow, h)...),                    // KB signed by a non-cnf key
		append(append([]byte{}, sdPartCNF...), wrongTypKB...),                                                                  // KB typ not kb+jwt
	}
	for _, s := range seeds {
		f.Add(s)
	}

	v := NewVerifier(WithClock(func() time.Time { return fixedNow }))
	f.Fuzz(func(t *testing.T, data []byte) {
		// Invariants that must hold for ANY input, fuzzed or seeded — never a
		// specific error, since the whole point is exploring adversarial byte
		// sequences the named unit tests don't enumerate.
		for _, requireKB := range []bool{false, true} {
			vc, err := v.Verify(context.Background(), VerifyInput{
				Presentation: data, IssuerKey: issKey.Public(),
				ExpectedAud: "aud", ExpectedNonce: "nonce", RequireKB: requireKB,
			})
			if err != nil {
				if vc != nil {
					t.Fatalf("RequireKB=%v: err = %v but vc != nil", requireKB, err)
				}
				continue
			}
			if vc == nil {
				t.Fatalf("RequireKB=%v: err == nil but vc == nil", requireKB)
			}
			if vc.VCT == "" {
				t.Fatalf("RequireKB=%v: accepted credential has empty VCT", requireKB)
			}
			if vc.Claims == nil {
				t.Fatalf("RequireKB=%v: accepted credential has nil Claims", requireKB)
			}
			if vc.SDHash == "" {
				t.Fatalf("RequireKB=%v: accepted credential has empty SDHash", requireKB)
			}
			if requireKB && vc.CNF == nil {
				t.Fatalf("RequireKB=true: accepted credential has no CNF (holder binding)")
			}
		}
	})
}
