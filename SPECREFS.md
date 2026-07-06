# Pinned specification versions

> NORMATIVE-SOURCE GAP: neither SD-JWT (now RFC 9901) nor the SD-JWT VC draft
> are mirrored in the verifier repo `references/`. Add the RFC 9901 text there
> and re-verify every `// SD-JWT §…` code citation and the reconstruction
> algorithm precisely — see the 2026-07-06 EU cross-check note below for what's
> already been spot-checked vs. what still needs the primary text.

| Spec | Version pinned | Sections used |
|---|---|---|
| SD-JWT | **RFC 9901** (graduated from draft-ietf-oauth-selective-disclosure-jwt -22; see below) | §4.1.1 (_sd_alg), §4.2 (Disclosures), §4.2.2/§4.2.4.2 (array elements `...`), §4.3 (KB-JWT, sd_hash), §7 (verification / digest reconstruction) |
| SD-JWT VC (draft-ietf-oauth-sd-jwt-vc) | -09 pinned here; EU reference (`eudi-lib-jvm-sdjwt-kt-main`) cites -13 — still a draft, not yet an RFC | §3 (vct, iss, cnf, status), typ `dc+sd-jwt` (legacy `vc+sd-jwt`) |
| OpenID4VC HAIP | 1.0 (final) | SD-JWT VC profile; KB required |
| OpenID4VP | 1.0 (final) | §7 claims path pointer (ClaimPath shape only) |
| IETF Token Status List (draft-ietf-oauth-status-list) | referenced for the `status.status_list` object shape (`uri`, `idx`) only; verification lives in go-statuslist (WP-04) |
| ARF | 2.9 | §6.6.3.6 / §6.6.3.8 (SD-JWT VC in the EUDI profile) |

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
