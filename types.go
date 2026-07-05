package sdjwt

import (
	stdcrypto "crypto"
	"time"
)

// SD-JWT / SD-JWT VC / JOSE protocol tokens. These are media-type, header,
// and claim-name identifiers — NOT algorithm identifiers (hard rule 4 covers
// algorithms; those come from go-eudi-crypto). Kept as constants so the code
// reads against the spec.
const (
	typSDJWT   = "dc+sd-jwt" // SD-JWT VC §3.2.1 typ
	typVCSDJWT = "vc+sd-jwt" // legacy typ, accepted only behind WithLegacyVCTyp
	typKB      = "kb+jwt"    // SD-JWT §4.3 KB-JWT typ

	hdrTyp = "typ" // JOSE protected header

	claimSD         = "_sd"         // SD-JWT §4.2.4 digest array
	claimSDAlg      = "_sd_alg"     // SD-JWT §4.1.1 hash-name
	claimEllipsis   = "..."         // SD-JWT §4.2.2 array-element digest wrapper
	claimVCT        = "vct"         // SD-JWT VC §3.2.2
	claimISS        = "iss"         // RFC 7519
	claimEXP        = "exp"         // RFC 7519
	claimNBF        = "nbf"         // RFC 7519
	claimIAT        = "iat"         // RFC 7519
	claimCNF        = "cnf"         // RFC 7800 confirmation
	claimJWK        = "jwk"         // RFC 7800 cnf member
	claimStatus     = "status"      // Token Status List §5
	claimStatusList = "status_list" // Token Status List §5 status member
	claimURI        = "uri"         // Token Status List §5 status_list member
	claimIdx        = "idx"         // Token Status List §5 status_list member
	claimAUD        = "aud"         // KB-JWT audience
	claimNonce      = "nonce"       // KB-JWT nonce
	claimSDHash     = "sd_hash"     // SD-JWT §4.3 KB-JWT
)

// VerifyInput is the full input to Verifier.Verify. IssuerKey is resolved by
// the caller through the trust layer (from x5c/iss) — this library never
// dereferences x5u/jku or the system pool (hard rule 6).
type VerifyInput struct {
	Presentation  []byte // <issuer-jwt>~<disclosure>~...~<kb-jwt>
	IssuerKey     stdcrypto.PublicKey
	ExpectedAud   string // verifier client_id; required when a KB-JWT is verified
	ExpectedNonce string // request nonce;      required when a KB-JWT is verified
	RequireKB     bool   // per ARF: callers set true by default
}

// VerifiedCredential is the result of a successful Verify. Claims holds the
// FULL reconstructed claim set: disclosed claims, always-present/cleartext
// claims, AND registered JWT/VC members (iss, vct, iat, exp, nbf, cnf,
// status) — SD-JWT control members (_sd/_sd_alg) are the only thing
// stripped. This is not attributes-only: iss/iat have no dedicated
// VerifiedCredential field, so filtering Claims would lose them (see WP-02
// README Decisions). Registered members that DO have a dedicated field here
// (cnf, status) are ALSO surfaced via that field. DecoyDigests counts decoy
// digests seen (SD-JWT privacy feature; WP-02 Decisions require surfacing
// the count for the verification report). CNF is the holder binding public
// key (README target says jwk.Key; exposed here as crypto.PublicKey for
// ADR-0004 safety — see README corrections).
type VerifiedCredential struct {
	VCT          string
	Claims       map[string]any
	CNF          stdcrypto.PublicKey
	Status       *StatusRef
	NotBefore    time.Time
	Expiry       time.Time
	SDHash       string // base64url digest over the presented issuer-JWT+disclosures (audit)
	DecoyDigests int
}

// StatusRef is the status_list reference of a credential (Token Status List
// §5). Fetch/verify/lookup live in go-statuslist (WP-04); this is extraction
// only.
type StatusRef struct {
	URI   string
	Index int
}

// CredentialTemplate drives Issuer.Issue. Claims is the full claim object;
// Selective lists the claim paths (Path(...)) to make selectively
// disclosable — every other claim is issued in the clear. HolderKey, when
// set, is embedded as cnf.jwk. HashName selects _sd_alg ("" → ECCG baseline,
// sha-256), resolved through go-eudi-crypto (no literal here).
type CredentialTemplate struct {
	VCT       string
	Issuer    string
	IssuedAt  time.Time
	NotBefore time.Time // zero → omit nbf
	Expiry    time.Time // zero → omit exp
	HolderKey stdcrypto.PublicKey
	Status    *StatusRef
	Claims    map[string]any
	Selective []ClaimPath
	HashName  string
}
