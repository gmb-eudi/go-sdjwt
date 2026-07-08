package sdjwt

import (
	"crypto/x509"

	eudicrypto "github.com/gmb-eudi/go-eudi-crypto"
)

// Issuer signs SD-JWT / SD-JWT VC credentials. It is the counterpart of
// Verifier and is reused by the future OpenID4VCI issuer and by
// internal/testwallet (WP-09). Construct with NewIssuer.
type Issuer struct {
	kp    eudicrypto.KeyProvider
	keyID string
	chain []*x509.Certificate // optional x5c chain (leaf first); nil = none
}

// IssuerOption configures an Issuer at construction time. Options are additive;
// an Issuer built with no options behaves exactly as before this mechanism
// existed.
type IssuerOption func(*Issuer)

// WithChain attaches an x5c certificate chain (leaf first) that Issue embeds in
// every issued credential's JWS protected header (RFC 7515 §4.1.6), so a
// verifier can resolve the issuer key from the chain (against a trust anchor)
// before verifying. Optional — an Issuer with no chain configured issues
// exactly as today (no x5c member).
func WithChain(chain []*x509.Certificate) IssuerOption {
	return func(i *Issuer) { i.chain = chain }
}

// NewIssuer returns an Issuer that signs with the key keyID from kp. Options
// are additive; the two-argument form NewIssuer(kp, keyID) is unchanged.
func NewIssuer(kp eudicrypto.KeyProvider, keyID string, opts ...IssuerOption) *Issuer {
	i := &Issuer{kp: kp, keyID: keyID}
	for _, opt := range opts {
		opt(i)
	}
	return i
}
