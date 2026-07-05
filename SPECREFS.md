# Pinned specification versions

> NORMATIVE-SOURCE GAP: the SD-JWT drafts below are not yet mirrored in the
> verifier repo `references/`. Add the pinned draft text there and re-verify
> every `// SD-JWT §…` code citation and the reconstruction algorithm before
> the phase gate. If a draft has since become an RFC, pin the RFC number and
> update this table.

| Spec | Version pinned | Sections used |
|---|---|---|
| SD-JWT (draft-ietf-oauth-selective-disclosure-jwt) | -22 (RFC-editor queue; confirm exact version when added to references/) | §4.1 (_sd_alg), §4.2 (Disclosures), §4.2.2 (array elements `...`), §4.3 (KB-JWT, sd_hash), §7 (verification / digest reconstruction) |
| SD-JWT VC (draft-ietf-oauth-sd-jwt-vc) | -09 (confirm exact version when added to references/) | §3 (vct, iss, cnf, status), typ `dc+sd-jwt` (legacy `vc+sd-jwt`) |
| OpenID4VC HAIP | 1.0 (final) | SD-JWT VC profile; KB required |
| OpenID4VP | 1.0 (final) | §7 claims path pointer (ClaimPath shape only) |
| IETF Token Status List (draft-ietf-oauth-status-list) | referenced for the `status.status_list` object shape (`uri`, `idx`) only; verification lives in go-statuslist (WP-04) |
| ARF | 2.9 | §6.6.3.6 / §6.6.3.8 (SD-JWT VC in the EUDI profile) |
