# Accepted non-LTE checkpoint - 2026-11-15

Historical v74 checkpoint. The [later v75 runtime acceptance](runtime-acceptance-20261115.md)
supersedes runtime delivery and integration status below; earlier checks remain
evidence for their stated source versions.

This checkpoint records specific source, CI and physical evidence. Full M1-M5,
version1.0 and production acceptance remain open. The normative specification's
292 requirements and98 acceptance scenarios are unchanged. LTE, restricted LTE,
natural Doze, unplugged battery and long endurance were not tested in this round.

| Component | Accepted source | Exact GitHub Actions evidence |
| --- | --- | --- |
| Android v74 /0.9.46-journal-bounds | [`65fa804e015397f260f9f2015100f123ca1c1e21`](https://github.com/nd4y/syn443-android/commit/65fa804e015397f260f9f2015100f123ca1c1e21) | [43663104984](https://github.com/nd4y/syn443-android/actions/runs/43663104984): all8 jobs;228 mandatory outcomes on each API29/35/37, zero skips/errors/failures |
| Control Plane | [`4189e4750cb62881d83367e724e4fae1ff87f0f2`](https://github.com/nd4y/syn443-control-plane/commit/4189e4750cb62881d83367e724e4fae1ff87f0f2) | [43655979806](https://github.com/nd4y/syn443-control-plane/actions/runs/43655979806): all8 jobs;59 required browser outcomes and actual temporary Keycloak OTP |

## Android delivery and device checks

The exact Actions archive, manifest, APK hashes and both native ABI libraries were
verified. The AAR uses Go1.26.11; the synthetic Go/Kotlin fixture uses Go1.27.4.
Engine source/patch pins are unchanged. All four serialization consumers use
1.13.0. Strict wire and journal recovery checks remain required.

The USB Xperia XQ-CT72 received the APK with its existing private development
signer. Re-signing preserved every non-signature APK member. Upgrade retained the
Keystore identity, registration, intent and configuration, then recovered Online.
The v73-to-v74 upgrade also read its existing encrypted assignment. On v74 an
actual native SIGABRT/exit6 recovered in9.94s, controller process death in8.58s
and Wi-Fi loss/return in14.38s. Each check retained identity/configuration/generation,
confirmed an active Android VPN and independently received HTTPS204. Original
Wi-Fi and stay-awake settings were restored; airplane mode stayed enabled.

This round used a direct-only signed pilot policy. It verifies lifecycle,
identity and connectivity recovery; it does not prove encryption, the complete
proxy matrix, NetBird or LTE on this new binary. Earlier protocol/device evidence
remains dated evidence, not a new acceptance of every route.

## Control console and pilot

The actual PatternFly React console discovers only devices allowed by the live
scoped read grant. Pagination, malformed metadata, expiry/revocation and keyboard
focus have mandatory browser coverage. The selected card shows desired settings,
issued policy and the last activation report separately. Lease renewal does not
invent a new activation event, and an old report is visibly historical.

Scoped sensitive operations can ask for explicit fresh MFA without erasing the
original tab's edit and exact pending request. The callback pins the original live
session and verified owner, requires configured ACR/AMR/authentication time and
cannot win a logout race. Retry remains manual. SQL preflight cannot mutate or
publish, and withdrawn rights still erase private UI data. The actual disposable
Keycloak fixture verifies password-only denial followed by real OTP and signed
assurance claims; browser fixtures alone are not used as identity evidence.

The private pilot received the exact verified control/web/publisher binaries and
the matching optional BFF assurance setting. Database, gateway, owner/device
services and grants were preserved. Real personal Keycloak SSO, authorized Xperia
discovery and card/settings readback passed after deployment. Personal sensitive
write/MFA acceptance remains open: the account currently has read-scoped grants.
No additional personal privileges were granted during this checkpoint.

## Integration and remaining scope

The initial integration candidates preserved the accepted executable source and
added only the evidence/roadmap/register refresh. Their repeated Android run
reproduced a journal allocation defect on API29 and an API37 hierarchy-read
failure. The [corrective work](journal-memory-bounds.md) then passed its own exact
CI and physical upgrade/recovery acceptance. PR60 merged as
[`06d7661`](https://github.com/nd4y/syn443-android/commit/06d7661ffbc3788d01eff4bc2f54e7d915cbd527)
with a tree identical to the accepted v74 source. The following main
[run43667967673](https://github.com/nd4y/syn443-android/actions/runs/43667967673)
stopped at the all-refs secret gate: a concurrently published runtime branch
introduced two independently verified public contract digests absent from the
older main configuration. Exact path/field/value exceptions retain the full
history scan and negative gates. Corrected main CI remains a separate open check.
Merge state and main CI are separate GitHub observations; a pinned feature run
is not a claim that main or an installed APK has a different source revision.
Unverified dependency and side branches remain separate.

The runtime-observation server candidate
[`f05dcd9`](https://github.com/nd4y/syn443-control-plane/commit/f05dcd94dc0ab650f7058216cc1ae5cf809c35f7)
passed [all8 jobs and64 browser outcomes](https://github.com/nd4y/syn443-control-plane/actions/runs/43663317952).
Its pilot rollout preserved device/account/grant/activation fingerprints and the
database, gateway and publisher containers. Personal SSO discovers the device
and opens its settings; the new card correctly says no report before client
delivery. The optional Android sender, consent and physical end-to-end runtime
readback are still pending. A historical activation is never an online heartbeat.

Native administration, complete application settings/provenance, full protocol
and chain acceptance, live managed overlays, complete four-mode discovery and
route scoring, telemetry/retention operations and the remaining release gates
stay required. Multiple Remnawave/x-ui/3x-ui and Tailscale/ZeroTier remain extension
contracts by explicit scope. Raw device, credential, user and provider evidence
stays outside public GitHub source, discussions and artifacts.
