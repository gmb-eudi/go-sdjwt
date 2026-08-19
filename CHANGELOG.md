# Changelog

Notable changes to this library, newest first. Versions are git tags; this file is written
for whoever bumps the dependency.

## v0.0.6

Additive: existing code compiles and behaves exactly as before.

### Added

- `PeekResult.IAT *time.Time` — the signing time the credential claims, read **without
  verification**, `nil` when absent (`iat` is OPTIONAL, [IETF SD-JWT VC §2.2.2.3]). It exists
  for the same reason `X5C` does: a caller resolving the issuer key from the certificate
  chain may need to know which instant to judge that chain at, and that instant is only
  readable before `Verify` can run. Like every other field on `PeekResult` it is a claim, not
  a fact.
- `VerifiedCredential.IssuedAt time.Time` — the **verified** `iat`, zero when absent. No
  validity rule is applied to it: neither SD-JWT VC nor its ecosystem profiles specify a
  validation time for the `x5c` path, so what a caller does with it is the caller's policy.

A caller that acted on the peeked value should confirm it equals the verified one; the
absence of `iat` is legitimate and must not be treated as an error.
