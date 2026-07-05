package sdjwt

import (
	"time"

	eudicrypto "github.com/gmb-eudi/go-eudi-crypto"
)

// Default clock-skew and KB-JWT freshness bounds. Services override via
// options; defaults are deliberately conservative.
const (
	defaultKBMaxAge = 5 * time.Minute
	defaultSkew     = 30 * time.Second
)

// Verifier verifies SD-JWT / SD-JWT VC presentations against an ECCG policy
// and an injected clock. Construct with NewVerifier; safe for concurrent use
// (immutable after construction).
type Verifier struct {
	clock            func() time.Time
	policy           eudicrypto.Policy
	skew             time.Duration
	kbMaxAge         time.Duration
	allowLegacyVCTyp bool
}

// Option configures a Verifier.
type Option func(*Verifier)

// WithClock injects the time source (validity windows, KB-JWT iat).
func WithClock(f func() time.Time) Option { return func(v *Verifier) { v.clock = f } }

// WithSkew sets the allowed clock skew for exp/nbf/iat comparisons.
func WithSkew(d time.Duration) Option { return func(v *Verifier) { v.skew = d } }

// WithKBMaxAge sets how old a KB-JWT iat may be before it is rejected as a
// replay.
func WithKBMaxAge(d time.Duration) Option { return func(v *Verifier) { v.kbMaxAge = d } }

// WithLegacyVCTyp additionally accepts the legacy vc+sd-jwt typ header
// (T-02.4 compatibility flag). Off by default: dc+sd-jwt only.
func WithLegacyVCTyp() Option { return func(v *Verifier) { v.allowLegacyVCTyp = true } }

// WithPolicy overrides the ECCG policy singleton (tests / alternative
// deployments).
func WithPolicy(p eudicrypto.Policy) Option { return func(v *Verifier) { v.policy = p } }

// NewVerifier returns a Verifier with a wall clock, the ECCG policy, default
// skew and KB max-age, and dc+sd-jwt-only typ enforcement.
func NewVerifier(opts ...Option) *Verifier {
	v := &Verifier{
		clock:    time.Now,
		policy:   eudicrypto.ECCG(),
		skew:     defaultSkew,
		kbMaxAge: defaultKBMaxAge,
	}
	for _, o := range opts {
		o(v)
	}
	return v
}
