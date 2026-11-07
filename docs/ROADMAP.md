# Implementation roadmap

Current evidence and remaining scope: [implementation snapshot](implementation-status.md).
The normative specification remains0.9; all292 requirements and98 scenarios are retained.

## M0 - contracts and executable reference core (foundation implemented)
Bounded shared Go/Kotlin inputs/results, deterministic reference ranking, context
generations and Stop/cancellation precedence are implemented. This is a foundation,
not complete path discovery or a production service. See the historical M0 note.

## M1 - physical Android vertical gate (partial)
Real isolated native/TUN ownership, direct/two-hop/NetBird forwarding, durable
intent, bounded recovery, route evidence and reproducible OS scenarios are implemented.
Accepted snapshot:159 JVM methods,138 Android outcomes per API29/35/37 and57
physical UI/storage cases plus actual USB Xperia Wi-Fi/route/controller/OS checks.
Physical LTE/restricted LTE, natural Doze, unplugged battery and endurance remain
open. Resource snapshots and emulator passes do not close these gates.
The complete REC-01..06 / AC82..90 scope is retained; no remote policy can disable
local Stop, hard limits, ownership fences or authorization checks.

## M2 - identity and provisioning (pilot implemented, milestone open)
OIDC/PKCE/DPoP, Keystore identity, SQL device sessions, separate API/publisher,
signed assignments, cache/lease/refresh/revoke and transactional rollback have
pilot code and tests. Manual links and QR use the same installation trust and
independent administrator approval. The candidate supports a managed
[first launch and HTTPS App Links](bootstrap-trust.md) and
[reports the outcome](activation-reporting.md) of signed activation or rollback.
Physical camera and HTTPS domain association, full typed overlay acceptance,
root rotation and managed first launch with the configured APK remain open.

The [signed route-profile pilot](assigned-route-activation.md) adds independent
native route gates and final storage fencing; physical acceptance remains separate.

## M3 - engines, sources and administration (partial foundation)
Embedded engine adapters exist. The control plane has one scoped Remnawave API
resource and can compile approved network layers into device policy. Device
subscription fetch, complete protocol/chain acceptance, full managed settings,
native editing and full administration remain open. Multiple Remnawave/x-ui/3x-ui
remain extension contracts.

## M4 - autonomous routing and support (partial)
Reference ranking, bounded per-target checks and a lazy graph frontier exist.
The frontier is a JVM planner and is not wired into runtime route selection.
Basic SQL user/admin chat,
Android/web UI and device media compression have scoped acceptance. Full contextual
quarantine/graph exploration for four network modes, cohort rollout, central
telemetry/incident analysis and operational retention controls remain open.

## M5 - version1.0 acceptance (open)
Complete security, update/migration/restore, real network, battery and endurance
evidence plus production operations are required. Continuing independently testable
M2/M3 work does not waive the remaining M1 or release gates. Production deployment
and enrolling real users are separate operations. Every implementation PR updates
the register with concrete scope and evidence; no percentage is inferred from CI.
