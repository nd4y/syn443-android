# Implementation and acceptance snapshot

Snapshot: 2026-11-16. Specification0.9 contains292 requirements and98 acceptance
scenarios. Those numbers describe scope, not completed work or test counts.
This document supersedes repository-wide readiness claims in historical stage notes.

The v83 [signed admin metadata foundation](mobile-admin-bootstrap.md) passed
source and actual-main CI. The v84 [separate administrative OAuth core](mobile-admin-auth.md)
source `110f817ca42dbabb9afe648c465809551a95c9db` passed all eight jobs in
[Actions43876233986](https://github.com/nd4y/syn443-android/actions/runs/43876233986)
and was protected-merged as `d4dd7565a836ec4d31672e6c07aa3d336e462635`.
Its actual-main run is pending at this source snapshot. The three emulator
matrices each contain287 unique passing Android outcomes;23 new administrative
JVM methods and all eight handwritten security classes meet the existing90%
coverage gate. Neither newer APK is installed at this snapshot.

Current v85 / `0.9.57-admin-trust` adds [current signed administrative admission](mobile-admin-discovery.md)
and a [controller-owned adaptive RAM budget](probe-budget-owner.md). A credential
operation requires the unchanged, current signed trust snapshot and a fresh
trusted clock; device Bootstrap authority remains separate. The adaptive budget
survives native/service/coordinator recreation in the same controller process.
Eleven new JVM and six new Android outcomes are mandatory in Actions; this
candidate has not yet passed CI. Durable admin controller/key/journal/callback,
Control API/UI, controller-process-death admission and the common energy
governor remain open. This is not real mobile-admin login/MFA or managed-chain
acceptance.

## Current accepted checkpoint

The [v82 USB/Wi-Fi checkpoint](non-lte-acceptance-20261116.md) records the latest
installed APK and its exact eight-job source CI:284 actual Android outcomes per
API and53 native roots in ordinary/race suites. The phone's final observed-window
batch has20 outcomes, including11 virtual coordinator cases, plus two real
six-second Wi-Fi cycles and native-process recovery. Identity/configuration,
consent, authentication method and empty outbox were preserved and original settings/radios
restored. The receipt preserves the original sleeping-screen chat failures, a
guarded precondition stop and the later cleanup RuntimeError with its cause
`NOT_VERIFIED`. Three subsequent read-only samples over28 seconds establish the
actual owned TUN/HTTPS204/Online restoration separately from that exception.

The same checkpoint pins v83 source CI at287 actual Android outcomes per API,
53 native roots and20 newly affected mandatory JVM outcomes, not the total JVM
count. Signed managed-chain acceptance, normal configuration publication,
authenticated administrator readback and full adaptive routing remain open.
Earlier v79 and pilot Control Plane binary rollout evidence stays historical.
The [v77 chat/source checkpoint](chat-acceptance-20261115.md) retains its earlier
device-only chat scope.

See the [2026-11-15 source, CI and USB/Wi-Fi checkpoint](non-lte-acceptance-20261115.md)
for the earlier Android v73 and Control Plane snapshots, delivery provenance,
physical recovery, live console readback and remaining scope. This refresh does
not promote a broad requirement from a component test or merge status.
The [v75 runtime checkpoint](runtime-acceptance-20261115.md) supersedes runtime
delivery and integration status without closing the remaining milestones.

## Historical foundation integration - 2026-11-01

The following table and counts document the earlier accepted foundation.
Current source and acceptance are pinned in the checkpoint above.



| Component | Accepted implementation | Integration into main |
| --- | --- | --- |
| Android | `e2291a71fa8491497f342fe26fbdf36788e2b59a`; [Actions41284851623](https://github.com/nd4y/syn443-android/actions/runs/41284851623) | [PR25](https://github.com/nd4y/syn443-android/pull/25), merge57038f4249b71766f5146af0d3298210192afab5 |
| Control plane | `c1fae966a2a0030a2d6e949b35716d767ea79e4c`; [Actions40510900456](https://github.com/nd4y/syn443-control-plane/actions/runs/40510900456) | [PR11](https://github.com/nd4y/syn443-control-plane/pull/11), merge3d7763ac39f445d52e8ae32c102143fae2d88d2e |

Each integration preserved the exact accepted source tree and commit ancestry.
Superseded stack PRs are closed with integration links; this does not turn a
historical failed/intermediate CI run into a passed run. Unverified side branches
and dependency updates are separate. Subsequent main/PR CI validates integration
and documentation commits independently. A merge is not a production deployment.

The accepted Android snapshot passed159 JVM methods and138 mandatory outcomes on
each API29/35/37, with zero skips/errors/failures. It retained the previous122 cases.
The exact Actions APK v26/0.7.0 also passed57 physical UI/storage/media/Keystore
checks on USB Xperia. Real public HTTPS, NetBird/internal SSH, independent optional
failure, visible route outcomes, Wi-Fi loss/return with fresh evidence, controller
death, reboot Off/On, update Off, Force stop/update/foreground and actual Android
Always-on/lockdown were checked. Newer Stop wins; a saved engineActive checkpoint
cannot claim a currently owned process. Configuration, two SDK identity fields
and original system/mobile-data settings were preserved/restored; main APK was
retained, test APK removed, Wi-Fi validated and VPN Off at final device readback.
Full status readiness after Wi-Fi return took73.12s including the probe interval;
this is not packet-outage latency. Device records/screenshots/configuration stay
private. This historical receipt covers the version installed at that test.

Control-plane acceptance includes Go/race, PostgreSQL process/role/transaction,
temporary Keycloak and browser support-chat checks. Prior isolated synthetic
deployment/phone evidence covers SQL history and complete25MiB files, user/admin
reply, role withdrawal and device image/video compression. Production deployment
and physical browser download persistence are not implied by browser CI.

## Milestone boundaries

| Milestone | Implemented scope | Remaining gate |
| --- | --- | --- |
| M0 | Shared bounded Go/Kotlin reference ranking, coordinator and contracts | Foundation only; not full route exploration |
| M1 | Real TUN/native host, durable intent, bounded recovery, direct/two-hop/NetBird paths, per-outbound evidence and reproducible Android lifecycle | LTE/restricted LTE, natural Doze, unplugged battery and endurance; full OS/routing predicate matrix |
| M2 | Keycloak/OIDC/PKCE/DPoP pilot, Keystore identities, SQL device sessions, signed assignments, refresh/cache/lease/revoke, transactional activation and rollback | Release invitations/QR/manual binding and live acceptance for full enrollment, managed overlays and root rotation |
| M3 | Embedded engines, a scoped Remnawave API resource, subscription normalization and addressed Wi-Fi fetch, separate API/worker/web processes | Live provider and complete protocol acceptance, native mobile edit/publish, all managed settings and administration workflows |
| M4 | Reference comparator, bounded graph planner, managed target checks, partial diagnostics, internal Wi-Fi failover candidate, [technical telemetry pilot](technical-telemetry.md) and basic SQL support chat | Runtime graph exploration/quarantine across all four modes, cohort policy rollout, full telemetry/incident pipeline and retention controls |
| M5 | Reproducible CI and scoped physical evidence | Complete version1.0 security/reliability/update/migration/restore and production acceptance |

HTTP/SOCKS/VLESS/SSH/selector/url-test and NetBird are accepted configuration
types in the embedded adapter. Full physical protocol/transport/chain acceptance,
including XHTTP and restrictive-cellular emergency VLESS paths, is still separate.
NetBird direct mode attempts P2P before relay fallback; VLESS mode has a dedicated
detour with no hidden direct fallback. Direct home access was physically checked;
that is not restricted-LTE acceptance or managed overlay enrollment acceptance.

The completion branch adds signed route-check activation and the managed overlay
vault/controller/private-host protocol; see managed-overlay.md for exact accepted
components and still-pending integration/device evidence. Inline overlay secrets
or paths remain rejected. A source implementation is not milestone acceptance.
Multiple Remnawave resources, x-ui/3x-ui and Tailscale/ZeroTier remain extension
contracts by design, not implemented version1.0 requirements.

## Evidence index and register semantics

The registers track product requirements, including cross-component contributions.
Evidence may point to this pinned cross-repository inventory when implementation
lives in the other component. Local evidence links are also retained. No normative
register text, ID, acceptance row or specification hash is changed by this update.
Targeted evidence/scope notes retain their existing partial or planned status;
a candidate core is not a full requirement pass.

- `planned`: no accepted implementation contribution recorded for that row.
- `partial`: concrete code/tests cover a subset; the full requirement is open.
- `implemented`: all clauses are implemented, but required acceptance is incomplete.
- `verified`: every clause and its required acceptance are proved for the declared scope.

Test counts, line coverage and existing file paths alone never promote a broad
requirement. New partial rows contain implementationScope and remainingScope.
Existing partial evidence remains historical unless a new snapshot says otherwise.
No full M1-M5 or production-readiness claim is made by these statuses.

| Requirements | Concrete contribution | Unaccepted remainder |
| --- | --- | --- |
| ARC-02/03/04/07, REC-01..06, ENG-01/02/08, AC82..90 | Durable controller, Stop/generation fences, bounded crash/hang recovery, actual per-outbound target evidence and USB Wi-Fi/OS cases | Full cross-mode/admission/budget matrix, LTE, natural Doze, energy/endurance and every OS/routing predicate |
| MOD-01..10, ENG-05 | Isolated host/TUN adapter, source/patch/toolchain locks, built-in modules, native alignment and ordinary/race tests | Complete capability/version matrix, signed release inventory/SBOM, all update/retirement acceptance |
| NB-01/02/05/06/07 | Direct-first/deferred SDK, strict VLESS detour, local identity, bounded cached roster/diagnostics and home traffic proof | Managed account credential retirement, backend peer lifecycle, DNS/route conflict and full handover matrix |
| CHK-01..12, CHECK requirements | Bounded TCP/SSH/TLS/strictHTTPS all-of checks through selected outbound with fresh scoped samples and check/cancel/status | Full rule/class/template plan model, any/quorum/stages, exit attribution, scheduling/dedup and visual profile editor |
| LOG-01..04, ADB-01..04 | Bounded redacted lifecycle/exit/resource snapshots and [debug ADB client](adb-control.md) | Full log channels/retention, configuration operations, release opt-in and server audit |
| AUTH/PROV/SEC partial rows | Pilot protocol/Keystore/journals, signed device-key policy and SQL authorization/publication | Full release onboarding, invitation trust, rotation, managed overlays and operational acceptance |
| CHAT partial rows | SQL message/file integrity and atomicity, Android user/admin and web chat, compression/retry/withdrawal | Complete retention/quota administration, production operations and restricted-network acceptance |
| ARC-03/05, REC-01/02/04 | Bounded continuity/recovery source CI and v82 Direct-policy USB/Wi-Fi/native recovery; coordinator phone cases remain virtual | Activated managed adaptive chains, full mode/lifecycle matrix and shared global energy/admission remain open |
| MOB-01/03/06 | Trusted Custom Tab URL/intent source and phone checks; v83 separately signed metadata/encrypted cache accepted in emulator CI | Actual browser/Keycloak/MFA/device-card acceptance, native API screens, local edit/push and complete one-hand workflows |
| AUTH-02, MOB-04 | v83 metadata preserves device identity; v84 separate admin OAuth source and23 mandatory test methods remain pending CI and app wiring | Atomic current-trust ticket, separate durable key/session, actual native login, server ACL/capability recovery and native administration |

Source/test inventories for review:
- [Android controller and UI](https://github.com/nd4y/syn443-android/tree/e2291a71fa8491497f342fe26fbdf36788e2b59a/app/src/main/kotlin/io/syn443/android/vpn)
- [Android acceptance drivers](https://github.com/nd4y/syn443-android/tree/e2291a71fa8491497f342fe26fbdf36788e2b59a/tools)
- [Native engine adapters and tests](https://github.com/nd4y/syn443-android/tree/e2291a71fa8491497f342fe26fbdf36788e2b59a/native)
- [Enrollment/SQL/worker/chat code](https://github.com/nd4y/syn443-control-plane/tree/c1fae966a2a0030a2d6e949b35716d767ea79e4c/internal)
- [Control-plane acceptance](https://github.com/nd4y/syn443-control-plane/tree/c1fae966a2a0030a2d6e949b35716d767ea79e4c/docs/TESTING.md)

An earlier isolated API29 policy-bootstrap unavailable/rollback event has no
proved root cause and did not recur in the final three-API snapshot. Bounded
DEBUG worker diagnostics remain available; unrelated changes are not called its fix.
All builds run in GitHub Actions. Physical USB/Wi-Fi and privacy/cleanup evidence
remain separate. No production secret, provider URL, identity file or raw device
log belongs in source, fixtures, Issues, Actions artifacts or releases.
