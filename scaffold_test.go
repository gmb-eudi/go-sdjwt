package sdjwt

import (
	"testing"
	"time"

	eudicrypto "github.com/gmb-eudi/go-eudi-crypto"
)

func TestNewVerifierDefaults(t *testing.T) {
	v := NewVerifier()
	if v.clock == nil {
		t.Fatal("default clock is nil")
	}
	if v.policy == nil {
		t.Fatal("default policy is nil")
	}
	if v.kbMaxAge != defaultKBMaxAge {
		t.Errorf("kbMaxAge = %v, want %v", v.kbMaxAge, defaultKBMaxAge)
	}
	if v.allowLegacyVCTyp {
		t.Error("legacy vc+sd-jwt typ accepted by default; must be opt-in")
	}
	// clock defaults to a working wall clock.
	if v.clock().IsZero() {
		t.Error("default clock returned zero time")
	}
}

func TestVerifierOptions(t *testing.T) {
	fixed := time.Date(2026, 7, 4, 12, 0, 0, 0, time.UTC)
	v := NewVerifier(
		WithClock(func() time.Time { return fixed }),
		WithSkew(90*time.Second),
		WithKBMaxAge(10*time.Minute),
		WithLegacyVCTyp(),
	)
	if got := v.clock(); !got.Equal(fixed) {
		t.Errorf("clock = %v, want %v", got, fixed)
	}
	if v.skew != 90*time.Second {
		t.Errorf("skew = %v", v.skew)
	}
	if v.kbMaxAge != 10*time.Minute {
		t.Errorf("kbMaxAge = %v", v.kbMaxAge)
	}
	if !v.allowLegacyVCTyp {
		t.Error("WithLegacyVCTyp not applied")
	}
	// the policy override option threads a Policy through.
	pol := eudicrypto.ECCG()
	v2 := NewVerifier(WithPolicy(pol))
	if v2.policy != pol {
		t.Error("WithPolicy not applied")
	}
}

func TestNewIssuer(t *testing.T) {
	kp := eudicrypto.NewStaticProvider(nil)
	i := NewIssuer(kp, "issuer-key")
	if i.kp == nil || i.keyID != "issuer-key" {
		t.Fatalf("issuer not constructed: %+v", i)
	}
}

func TestClaimPath(t *testing.T) {
	p := Path("address", "street_address")
	if len(p) != 2 || p[0] != "address" || p[1] != "street_address" {
		t.Fatalf("Path = %#v", p)
	}
	for name, cp := range map[string]ClaimPath{
		"string+int": Path("nationalities", 1),
		"single key": Path("family_name"),
	} {
		t.Run(name, func(t *testing.T) {
			if !cp.valid() {
				t.Errorf("valid() = false for %#v", cp)
			}
		})
	}
	for name, cp := range map[string]ClaimPath{
		"empty":       Path(),
		"bad element": {3.14},
		"nil element": {nil},
	} {
		t.Run("invalid/"+name, func(t *testing.T) {
			if cp.valid() {
				t.Errorf("valid() = true for %#v", cp)
			}
		})
	}
}
