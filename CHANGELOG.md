# Changelog

Notable changes to this library, newest first. Versions are git tags; this file is written
for whoever bumps the dependency.

## v0.0.8

Dependency maintenance. No source changed here and nothing this library does behaves differently.

### Notes

- **`github.com/gmb-eudi/go-eudi-crypto` → v0.0.8** (was v0.0.7). That release changed no source of
  its own either — it took `github.com/lestrrat-go/jwx/v3` to **v3.3.0** and `golang.org/x/crypto`
  to **v0.57.0**. Both reach this library only through it: **nothing here imports jwx**, it arrives
  as an indirect requirement. The `x/crypto` move crosses the release that fixed **GO-2026-6354**
  and **GO-2026-6355** upstream.

- The gate is green on the new set: `go mod verify`, `go mod tidy -diff`, build, vet, `gofmt`, and
  `go test -race` with **0 races**; `govulncheck` finds nothing.

- Repository hygiene, with no effect on code that uses the library: CI now also runs on pushes to
  `develop`, the pinned GitHub Actions moved to their current commits, and the `setup-go` pin rolled forward.

## v0.0.7

Compatible: no signature changes, no message-text changes, nothing that passed before now
fails.

### Changed

- **Errors now wrap their cause as well as their sentinel — 12 sites** in `disclosure.go`,
  `issue.go`, `kb.go`, `peek.go`, `present.go` and `verify.go`. Each was built as
  `fmt.Errorf("%w: …: %v", ErrSentinel, err)`: the sentinel wrapped, the cause printed into
  the string and then unreachable. Both are now `%w`.

  The sentinels here say *which part* of the credential was at fault; the cause says why. A
  disclosure that is not valid base64url and one whose JSON is malformed are both
  `ErrDisclosure` today, and now they are distinguishable:

  ```go
  var b64 base64.CorruptInputError
  if errors.Is(err, ErrDisclosure) && errors.As(err, &b64) { /* encoding, not structure */ }
  ```

  `errors.Is(err, ErrDisclosure)` / `ErrHashAlg` / `ErrTemplate` / `ErrKBSignature` /
  `ErrMalformed` / `ErrIssuerSignature` all still hold and every rendered message is
  byte-identical (`%v` and `%w` print an error the same way), so no existing caller needs to
  change.

### Dependencies

- `github.com/lestrrat-go/dsig` v1.3.0 → v1.4.0 (indirect).

### Notes

- The `go` directive is now `1.26.6`, which is the minimum Go version a consumer needs. The
  previous `1.26` resolved to whatever patch the toolchain happened to have; the exact patch
  is pinned because earlier 1.26 releases carry standard-library security fixes this library's
  callers should not silently miss.

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

- Dependency update