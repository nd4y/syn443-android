# Adaptive native owner recovery

This component repairs a source-proven readiness and scheduling gap. It does
not establish the cause of a historical phone crash or physical reproduction of
the same-native-owner transition. Actual managed-chain acceptance is separate.

## Revocation without resetting debt

The native adaptive owner increments its epoch on invalidation. Its scope also
binds a private nonce, policy, wire hash and mode. Invalidation/configuration
revokes selectors, selected flows and one-use receipts. It does not promise that
a cancelled probe has finished releasing its resources.

The Android coordinator previously retained its selected path, measurement and
next maintenance time after accepting a different native epoch or scope under
the same Java RouteScope. A positive row could remain visible until its evidence
TTL expired, and recovery could wait for the old routine cadence.

The coordinator now tracks the last observed native scope separately from the
configured ready scope. An accepted owner transition immediately retracts:

- selected paths, positive measurements, latency and selection/hint tokens;
- improvement candidates, cursors and local failure confirmations belonging to
  the old native owner;
- observations and associated diagnostics only for the bound adaptive rows.

Groups become recovery-due without waiting for their previous routine deadline.
The existing shared admission ledger, group fairness cursor, hard limits,
recovery reserve and compatible negative health history remain unchanged.
RouteHealthMemory.revokeVerified admits only the same context and valid monotonic
time; it removes positive entries while retaining failure ordinals, permanent
configuration fences, original cooldowns, half-open deadlines and replay fences.
This is RAM continuity within an unchanged Java context, not persistent BAD-08
history or cross-network evidence transfer.

## Actual worker completion

An old pending native command becomes a tombstone. A separate draining barrier
blocks new starts until the current native epoch/scope and current policy report
both literal Boolean ready=true and running=false. Missing fields, strings,
configure dispatch, a ready-but-busy report, stale epoch or foreign policy do not
prove worker completion. Dropping a logical asynchronous admission callback does
not release its real storage worker or refund its reserved quantum.

The native snapshot exports the actual busy owner. That flag clears only after
workerDone closes following cleanup and admission release. This proves probe
worker completion; it does not replace the separate stopped/resource-retirement
proof required to replace a physical engine owner.

The barrier retains the original pending start time, or the first transition
time when there was no pending command. Further transitions cannot restart that
deadline. More than35 seconds requests the existing retirement procedure. A
timeout never admits a second probe or constructs a replacement owner. Old
receipts cannot settle or restore the retracted selection.

A syntactically valid previously unseen scope at the same epoch is treated
conservatively as another owner transition. There is no new remote authority or
invented scope-history protocol. Initial epoch0-to1 discovery has no old owner
to drain. Java-context changes still use their existing complete reset path.

## Evidence boundaries

Three required JVM roots exercise positive-only revocation, cooldown/half-open
boundaries, configuration and replay fences, context/clock rejection and the
64-entry bound. Six Android roots exercise the actual coordinator and route
projection using synthetic reports, including typed idle completion, old
receipts, immediate recovery, malformed/foreign reports and retirement timeout.
The expected source matrix is519 JVM and470 unique outcomes per API29/35/37,
with212 affected Android outcomes and an independent90% RouteHealthMemory gate.
Existing native ordinary/race worker-cancellation proofs remain mandatory.

Source, Actions, protected-main, installed APK and real Wi-Fi/native-process
checks are separate acceptance stages. These fixtures do not activate managed
routes, create a new capability, change rights, test LTE, measure battery or
prove natural Doze/endurance behavior.
