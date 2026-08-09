# Pinned specification versions

> NORMATIVE-SOURCE GAP, part-closed 2026-08-09: the SD-JWT VC citations in this
> package have now been checked against the primary draft text and re-pointed at
> **draft-18** — see the note below. The `// SD-JWT §…` citations into RFC 9901
> and the reconstruction algorithm have **not** been re-verified against the RFC
> and are still carried from the -22 draft; that pass is still owed.

| Spec | Version pinned | Sections used |
|---|---|---|
| SD-JWT | **RFC 9901** (graduated from draft-ietf-oauth-selective-disclosure-jwt -22; see below) | §4.1.1 (_sd_alg), §4.2 (Disclosures), §4.2.2/§4.2.4.2 (array elements `...`), §4.2.6 (recursive disclosures), §4.3 (KB-JWT, sd_hash), §7.1 (verification / digest reconstruction) |
| SD-JWT VC (draft-ietf-oauth-sd-jwt-vc) | **-18** (was -09; still a draft, not yet an RFC — every citation names the revision it was checked against) | §2 (credential format), §2.2.1 (typ `dc+sd-jwt`, legacy `vc+sd-jwt`), §2.2.2 (vct, iss, cnf, status) |
| x5c issuer chain embed (`WithChain`) + structural header peek (`Peek`) | RFC 7515 | §4.1 (JWS protected header), §4.1.6 (x5c) — structural/pre-trust only, no verification |
| OpenID4VC HAIP | 1.0 (final) | SD-JWT VC profile; KB required |
| OpenID4VP | 1.0 (final) | §7 claims path pointer (ClaimPath shape only) |
| IETF Token Status List (draft-ietf-oauth-status-list) | referenced for the `status.status_list` object shape (`uri`, `idx`) only; verification lives in go-statuslist (WP-04) |
| ARF | 2.9 | §6.6.3.6 / §6.6.3.8 (SD-JWT VC in the EUDI profile) |

## 2026-08-09 SD-JWT VC re-pin: -09 → -18

Every `SD-JWT VC §…` citation in this package was read against the published
draft-18 text. All nine were written against -09, where §3 was the credential
format; in -18 the credential format is §2 and §3 is JWT VC Issuer Metadata —
so all nine still *looked* valid and every one pointed at the wrong section.
They now name the revision they were checked against (`[SD-JWT VC draft-18
§2.2.2]`), because an unversioned citation into a draft silently re-points at
whatever revision is current.

The mapping applied: §3 → §2 (credential format), §3.2 and §3.2.2 → §2.2.2
(the JWT claims set: `vct`, `iss`, `cnf`, `status`), §3.2.1 → §2.2.1 (the JOSE
header and the `typ` value), §3.5 → §2.2.2 for the `cnf` read specifically.
Note that -18's Table of Contents stops at three levels, so §2.2.2 is the
deepest citable section even though the text below it is subdivided further.

**No behaviour changed, and one divergence was found and left in place:** -18
§2.2.2 makes `iss` OPTIONAL when the issuer is conveyed by other means, naming
the x5c end-entity certificate subject as the example — and that x5c path is
exactly what the high-assurance profile mandates. `Verify` still rejects a
credential without `iss` (`ErrMissingIssuer`). That is stricter than the format
requires and is recorded at the error's declaration; changing it is a product
decision, not a citation fix.

The `typ` values were re-confirmed against -18 §2.2.1: `dc+sd-jwt` is the
required value and `vc+sd-jwt` is the legacy one, which is what this package
already implements.

## 2026-07-06 EU cross-check (`docs/sdjwt-eu-gap-report.md`)

**SD-JWT is confirmed finalized as RFC 9901** — the EU's own reference Kotlin
library (`references/sdjwt/eudi-lib-jvm-sdjwt-kt-main`, `Specs.kt`) cites it
directly (`https://www.rfc-editor.org/rfc/rfc9901.html`), and a direct fetch of
the RFC-editor text confirmed the core section numbers this codebase already
cites carried over largely unchanged: §4.1.1 "Hash Function Claim", §4.3 "Key
Binding JWT" (§4.3.1 "Binding to an SD-JWT" for `sd_hash` specifically), §7
"Verification and Processing" all match exactly. One nuance not yet fully
resolved: the "..." array-element digest marker's own claim-processing rule
may sit at §4.2.4.2 rather than §4.2.2 (which covers the *disclosure format*
for array elements, a related but distinct subsection) — the codebase's
`§4.2.2` citations for this are probably fine but not confirmed byte-precise;
do a full citation audit once RFC 9901 is vendored under `references/`.

**x5c issuer-key resolution (gap report §6) — scope closed as x5c-only.**
`WithChain` (issuer-side x5c embed, RFC 7515 §4.1.6) and `Peek` (pre-trust
structural read of typ/x5c/iss/vct) were added so a caller can resolve the
issuer key from the embedded certificate chain against a trust anchor BEFORE
calling `Verify` — the pattern the gap report §6 recommended scoping explicitly
to x5c-only for the ARF-governed issuer set. Key resolution and trust remain
entirely outside this library (ADR-0004): `Peek` verifies nothing, and `Verify`
still takes the resolved `IssuerKey` as input. The general SD-JWT VC
`.well-known/jwt-vc-issuer` metadata-fetch and `did:` discovery mechanisms are
intentionally NOT implemented. (Gap report §5, SD-JWT VC type-metadata
validation, is a separate concern and remains an open WP-09 decision — not
addressed here.)

**The core reconstruction/digest/KB algorithm was independently verified
correct** against both `eudi-lib-jvm-sdjwt-kt-main` (Kotlin) and
`eudi-lib-sdjwt-swift-main` (Swift) — including the subtle "a digest string
may not repeat anywhere in the payload, decoys included" rule (matches
Kotlin's `ensureUnique`/`DiscloseObject`) and the exact `sd_hash` input bytes
(issuer-JWT + disclosures + trailing `~`, excluding the KB-JWT; matches
Kotlin's `SdJwtDigest.digestInternal`/`noKeyBinding()`). Notably, the EU
**Swift** library's SD-JWT VC verifier (`SDJWTVCVerifier`/`KeyBindingVerifier`)
does **not** check `sd_hash` at all in the traced call path — this codebase's
`verifyKB` is correct where that reference appears not to be. Full detail in
the gap report.
