package sdjwt

import eudicrypto "github.com/gmb-eudi/go-eudi-crypto"

// Issuer signs SD-JWT / SD-JWT VC credentials. It is the counterpart of
// Verifier and is reused by the future OpenID4VCI issuer and by
// internal/testwallet (WP-09). Construct with NewIssuer.
type Issuer struct {
	kp    eudicrypto.KeyProvider
	keyID string
}

// NewIssuer returns an Issuer that signs with the key keyID from kp.
func NewIssuer(kp eudicrypto.KeyProvider, keyID string) *Issuer {
	return &Issuer{kp: kp, keyID: keyID}
}
