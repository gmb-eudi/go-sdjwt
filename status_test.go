package sdjwt

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
)

// decodeStatusPayload runs a raw JSON object through the same json.Number
// decode path Verify uses, so idx type handling matches production.
func decodeStatusPayload(t *testing.T, raw string) map[string]any {
	t.Helper()
	m, err := decodeJSONObject([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestExtractStatusPresent(t *testing.T) {
	p := decodeStatusPayload(t, `{"status":{"status_list":{"idx":42,"uri":"https://status.example/list/1"}}}`)
	ref, err := extractStatus(p)
	if err != nil {
		t.Fatalf("extractStatus: %v", err)
	}
	if ref == nil || ref.Index != 42 || ref.URI != "https://status.example/list/1" {
		t.Fatalf("ref = %+v", ref)
	}
}

func TestExtractStatusAbsent(t *testing.T) {
	ref, err := extractStatus(decodeStatusPayload(t, `{"vct":"urn:eudi:pid:1"}`))
	if err != nil || ref != nil {
		t.Fatalf("ref = %+v, err = %v; want nil, nil", ref, err)
	}
}

func TestExtractStatusMalformed(t *testing.T) {
	for name, raw := range map[string]string{
		"status not object":      `{"status":"revoked"}`,
		"no status_list":         `{"status":{"other":{}}}`,
		"status_list not object": `{"status":{"status_list":[]}}`,
		"uri missing":            `{"status":{"status_list":{"idx":1}}}`,
		"uri empty":              `{"status":{"status_list":{"idx":1,"uri":""}}}`,
		"idx missing":            `{"status":{"status_list":{"uri":"https://x"}}}`,
		"idx negative":           `{"status":{"status_list":{"idx":-1,"uri":"https://x"}}}`,
		"idx not integer":        `{"status":{"status_list":{"idx":1.5,"uri":"https://x"}}}`,
		"idx string":             `{"status":{"status_list":{"idx":"1","uri":"https://x"}}}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := extractStatus(decodeStatusPayload(t, raw)); !errors.Is(err, ErrStatusMalformed) {
				t.Fatalf("err = %v, want ErrStatusMalformed", err)
			}
		})
	}
}

// End-to-end: Verify populates VerifiedCredential.Status.
func TestVerifyPopulatesStatus(t *testing.T) {
	issKey := newECKey(t)
	kp := staticProvider("iss", issKey)
	payload, disc := basePayload(t, nil)
	payload[claimStatus] = map[string]any{"status_list": map[string]any{"idx": 7, "uri": "https://status.example/l/9"}}
	pres := assemble(signIssuerJWT(t, kp, "iss", typSDJWT, payload), disc)

	v := NewVerifier(WithClock(fixedClock()))
	vc, err := v.Verify(context.Background(), VerifyInput{Presentation: pres, IssuerKey: issKey.Public()})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if vc.Status == nil || vc.Status.Index != 7 || vc.Status.URI != "https://status.example/l/9" {
		t.Fatalf("Status = %+v", vc.Status)
	}
}

// A malformed status makes Verify fail (fail closed), not silently drop it.
func TestVerifyRejectsMalformedStatus(t *testing.T) {
	issKey := newECKey(t)
	kp := staticProvider("iss", issKey)
	payload, disc := basePayload(t, nil)
	payload[claimStatus] = map[string]any{"status_list": "not-an-object"}
	pres := assemble(signIssuerJWT(t, kp, "iss", typSDJWT, payload), disc)

	v := NewVerifier(WithClock(fixedClock()))
	if _, err := v.Verify(context.Background(), VerifyInput{Presentation: pres, IssuerKey: issKey.Public()}); !errors.Is(err, ErrStatusMalformed) {
		t.Fatalf("err = %v, want ErrStatusMalformed", err)
	}
	_ = json.Marshal // keep import if trimmed elsewhere
}
