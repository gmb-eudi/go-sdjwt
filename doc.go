// Package sdjwt implements SD-JWT (RFC 9901, finalized from
// draft-ietf-oauth-selective-disclosure-jwt) and SD-JWT VC
// (draft-ietf-oauth-sd-jwt-vc, dc+sd-jwt): combined-format
// parsing, disclosure digest verification, issuer-JWS and Key-Binding-JWT
// verification, status-list reference extraction, and an Issue + PresentKB
// façade for issuers and test wallets.
//
// All cryptography is delegated to github.com/gmb-eudi/go-eudi-crypto: the
// package holds no algorithm string literals; hash algorithms, JOSE
// signatures, and JWK conversions come from the ECCG-pinned policy. Time is
// injected (Verifier clock; PresentKB now parameter). Errors are typed
// sentinels carrying protocol identifiers and claim names only, never claim
// values (hard rule 3).
//
// Import go-eudi-crypto with an alias to avoid clashing with the standard
// library:
//
//	eudicrypto "github.com/gmb-eudi/go-eudi-crypto"
package sdjwt
