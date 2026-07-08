# go-sdjwt

SD-JWT and SD-JWT VC for the EUDI Wallet ecosystem in Go: combined-format
parsing, disclosure digest verification, issuer-JWS and Key-Binding-JWT
verification, status-list reference extraction, and an Issue + PresentKB
façade for issuers and test wallets.

- Framework-free; all cryptography delegated to
  github.com/gmb-eudi/go-eudi-crypto (ECCG-pinned policy; algorithms are
  derived from keys/policy, never chosen by tokens). No algorithm literals.
- Verify: split combined format, verify issuer JWS, enforce typ/iss/vct/
  validity/cnf, reconstruct disclosed claims by digest, verify KB-JWT,
  extract status reference.
- typ dc+sd-jwt enforced; legacy vc+sd-jwt accepted only behind an explicit
  compatibility option.
- Two façades so selective-disclosure logic never forks between issuer and
  verifier.
- `NewIssuer(kp, keyID, WithChain(chain))` embeds an x5c certificate chain
  (leaf first) in every issued credential's JWS header (RFC 7515 §4.1.6); the
  two-argument `NewIssuer(kp, keyID)` is unchanged and embeds no x5c.
- `Peek([]byte) (*PeekResult, error)` is a pre-trust structural read: it
  returns typ / x5c chain / iss / vct / disclosure count WITHOUT verifying the
  signature, digests, or validity, so a caller can resolve the issuer key from
  the x5c chain (against a trust anchor) BEFORE calling Verify with that key
  (ADR-0004: key resolution/trust stays outside this library). NEVER trust a
  PeekResult directly — verify with Verify first.

Implemented specs: SD-JWT (RFC 9901, finalized from
draft-ietf-oauth-selective-disclosure-jwt), draft-ietf-oauth-sd-jwt-vc
(dc+sd-jwt), HAIP 1.0 SD-JWT VC profile, ARF 2.9 §6.6.3.6/6.6.3.8. See
SPECREFS.md for pinned versions.

Status: pre-v1. API frozen no earlier than OIDF conformance pass.
