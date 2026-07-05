package sdjwt

import "errors"

// Sentinel errors. This library returns typed errors; services map them to
// err:domain:reason problem codes (docs/conventions.md) — the expected
// mapping is noted inline. No message ever carries a claim value, salt,
// disclosure content, or JWK coordinate (hard rule 3).
var (
	// Combined-format parsing (T-02.2).
	ErrMalformed       = errors.New("sdjwt: malformed SD-JWT")              // err:credential:parse
	ErrTooLarge        = errors.New("sdjwt: presentation exceeds size cap") // err:credential:parse
	ErrDisclosureLimit = errors.New("sdjwt: disclosure count exceeds cap")  // err:credential:parse

	// Disclosure / digest reconstruction (T-02.3).
	ErrDisclosure      = errors.New("sdjwt: invalid disclosure")                    // err:credential:parse
	ErrDigestMismatch  = errors.New("sdjwt: disclosure digest not referenced")      // err:credential:integrity
	ErrDuplicateDigest = errors.New("sdjwt: digest referenced more than once")      // err:credential:integrity
	ErrHashAlg         = errors.New("sdjwt: unsupported _sd_alg")                   // err:credential:parse
	ErrClaimCollision  = errors.New("sdjwt: disclosed claim collides with a claim") // err:credential:integrity

	// Issuer JWT + envelope (T-02.4).
	ErrIssuerSignature = errors.New("sdjwt: issuer signature verification failed")   // err:credential:integrity
	ErrType            = errors.New("sdjwt: unexpected typ header")                  // err:credential:parse
	ErrMissingIssuer   = errors.New("sdjwt: iss claim missing")                      // err:credential:parse
	ErrMissingVCT      = errors.New("sdjwt: vct claim missing")                      // err:credential:parse
	ErrExpired         = errors.New("sdjwt: credential outside validity window")     // err:credential:expired
	ErrNotYetValid     = errors.New("sdjwt: credential not yet valid")               // err:credential:expired
	ErrMissingCNF      = errors.New("sdjwt: holder binding required but cnf absent") // err:credential:binding-failed

	// KB-JWT (T-02.5).
	ErrKBRequired  = errors.New("sdjwt: key binding JWT required but absent")                     // err:credential:binding-failed
	ErrKBType      = errors.New("sdjwt: KB-JWT typ must be kb+jwt")                               // err:credential:binding-failed
	ErrKBSignature = errors.New("sdjwt: KB-JWT signature verification failed")                    // err:credential:binding-failed
	ErrKBAudience  = errors.New("sdjwt: KB-JWT aud mismatch")                                     // err:presentation:nonce-mismatch
	ErrKBNonce     = errors.New("sdjwt: KB-JWT nonce mismatch")                                   // err:presentation:nonce-mismatch
	ErrKBStale     = errors.New("sdjwt: KB-JWT iat outside acceptable window")                    // err:credential:binding-failed
	ErrKBSDHash    = errors.New("sdjwt: KB-JWT sd_hash does not match the presented disclosures") // err:credential:binding-failed

	// Status (T-02.6).
	ErrStatusMalformed = errors.New("sdjwt: malformed status claim") // err:credential:parse

	// Issue / PresentKB façade (T-02.7).
	ErrTemplate  = errors.New("sdjwt: invalid credential template")                    // programming error
	ErrClaimPath = errors.New("sdjwt: requested claim is not selectively disclosable") // programming error
)
