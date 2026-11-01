# Signed route-profile activation pilot

The enrolled runtime accepts the same bounded `route_checks` metadata as an
operator configuration. It is stripped before native configuration compilation.
Managed NetBird remains rejected until account-specific credential storage and
retirement are implemented. This slice does not complete M2 or the full health
profile language in the specification.

## Independent gates

The signed activation checks and native per-outbound checks are separate gates.
A passing global Internet HTTPS check cannot confirm a failing required outbound.
Every required route must have a complete, successful and fresh native result for
the candidate's exact content hash, intent, network epoch, activation generation
and native session. Optional failure does not prevent independent routes from
committing. An unconfigured route is never described as measured success.

Beginning an apply invalidates previous route receipts, including same-config
renewal that keeps its native process and staged activation generation. A new
request UUID and an observation at or after the durable apply start are required.
Late callbacks for previous requests, owners or networks cannot supply proof.
Unverified, stale, cancelled and incomplete observations wait within the original
signed activation deadline; they cannot become false failure or success samples.

A complete required-route failure triggers durable `required_route_failed`
rollback, even when `allowDegraded` is true. A publisher should mark an optional
home service optional when its outage must not veto activation. Only the still
authorized last-known-good policy can return. Failed candidates stay poisoned;
lease expiry and revocation continue to take precedence over rollback.

The identity worker rechecks the local proof before preparing a transition and
again after encrypted preparation, immediately before durable commit. Intent and
network publication share the outer state lock with this final commit fence.
Proof lost while queued or encrypting cannot confirm the candidate. Stop,
account-generation and native-session fences remain local invariants.

## Bounds and acceptance

The native runner retains two workers, one admitted batch and its existing
deadline. Ordinary checks keep their 60-second interval. During an apply only,
completed/incomplete admission may be retried at most once per ten seconds; a
pending batch cannot be replaced or grow the worker count. The original signed
30-120 second apply deadline is never extended. A stuck probe therefore causes
bounded timeout/rollback, not unlimited retries.

Actions requires the pure recovery gate test, Android snapshot/final-storage
fence tests, and three real enrolled/TUN scenarios:

- A required working route commits while an optional route fails.
- Healthy global Internet and `allowDegraded` cannot hide a required route failure.
- Stop during an in-flight candidate route probe prevents a late success commit.

All 144 Android outcomes are required on API 29, 35 and 37, together with 160 JVM
methods and existing coverage gates. Tests use only synthetic proxies, peers and
ephemeral signing/identity material. Device acceptance uses the exact Actions APK,
the existing private development signer and USB Xperia on validated Wi-Fi, with
the original configuration/identity/intent/OS flags restored afterward. It remains
a separate check and cannot be inferred from emulator or CI success.

Remaining M2 scope includes managed-overlay namespaces, release QR/manual invite
flows, key rotation and full user/operational acceptance. Full route discovery,
arbitrary health-expression composition, LTE, natural Doze, unplugged energy and
endurance remain separate open work.
