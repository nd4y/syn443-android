# Durable adaptive admission design

This component extends the existing adaptive start budget across controller
process death. It is part of ARC-06 / AUTO-07 / REC-06 / CHK-11. It does not
implement a common socket, byte or CPU governor for ordinary route checks,
activation checks, telemetry or NetBird diagnostics. Those remain separate work.
Source, Actions, integration and physical acceptance are separate gates.

## Invariants

The existing eight starts per rolling minute,128 per rolling hour, five-second
spacing, six routine starts per minute and96 routine starts per hour stay fixed.
The remaining capacity remains available for recovery. Force, policy, context,
coordinator/service/native recreation and controller recreation do not clear
admission debt. Candidate enumeration consumes no network admission.

One admitted attempt remains one existing bounded candidate execution, with its
unchanged native time/leaf/hop/worker limits. It is not an accounting unit for
all sockets or bytes across the application. This ledger creates no route proof,
proxy failure witness, permission or readiness.

## Owned checkpoint and time

The pure core exposes a validated, copied checkpoint: a monotonic observation
anchor, a clock-seal flag and at most128 ordered start ages with routine flags.
Ages are integers from-1000 through3599999 milliseconds. A negative age is a
bounded reservation for the latest permitted dispatch, described below; it is
not a future clock observation. Export never exposes the
mutable deque. Restoring in the same boot adds only the actual nonnegative
BOOTTIME difference and expires records normally. A backwards clock keeps the
owner sealed. A new boot carries each saved age without advancing it by wall
time. This conservatively ignores powered-off time rather than forgiving debt.
It preserves the spacing and remaining windows, without imposing an unrelated
blanket hour-long ban after every normal reboot. Only the new boot's clock seal
can be cleared; saved start debt cannot be cleared.

The Android envelope is closed version1 JSON containing the actual BOOT_COUNT
and that checkpoint. It contains no network, proxy, user, peer or target IDs,
credentials, addresses or configuration. It lives only in noBackupFilesDir;
export/import of a VPN configuration must not reset it. Missing, malformed,
oversized, duplicate-key, fractional, foreign-version or unreadable existing
state never becomes a fresh empty budget. First creation is distinguished from
an interrupted or damaged existing store. No wall-clock timestamp is trusted.

## Asynchronous storage before dispatch

One process-owned serial worker and bounded request slot own the file and live
budget. Main-thread callbacks never read, write, lock, sync or wait for that file.
An explicit owner lock prevents competing storage writers. A successful start
is charged in RAM, then its complete checkpoint is written with explicit file
sync, atomic replacement, directory sync and bounded exact readback. Only after
those operations succeed may the controller receive admission. A crash after
the durable write but before dispatch burns one quantum, which is safe. A write
failure grants no dispatch and never replenishes the live ledger.

A reservation charges its latest permitted dispatch time, at most1000ms beyond
the actual observation. The callback must emit its command no later than that
time, or burn the charge without dispatch. Subsequent admission waits at least
five seconds beyond the prior latest time; minute/hour expiry also uses that
conservative time. A delayed sync therefore cannot compress actual command
starts or sliding windows. Old synchronous starts retain their exact behavior.
The persisted negative age also survives process death and conservative reboot
restoration, so neither event bypasses the handoff fence.

An actual worker clock-seal transition is durably recorded even when admission
is denied. Successful reservations and committed seals define the durable clock
high-water mark. Ordinary monotonic denials do not require a disk write on every
tick: losing their observation changes no admitted effect, and restoring the
older checkpoint retains debt conservatively. A live sealed owner stays sealed;
failed seal persistence grants no dispatch. Immutable previews do not observe
or mutate the worker's clock.

Cancellation or a deadline does not replace a still-running storage worker.
An old request may finish its write, but its stale callback grants no effect.
Only actual completion makes the worker available again. No timer or force
request starts extra workers to bypass a blocked file operation.

The main-thread preview uses an immutable snapshot rather than concurrently
calling observe on the live worker-owned budget with a previously sampled time.
Preview denial and storage failure are local UNKNOWN/admission-wait states,
not negative proxy evidence.

## Coordinator fence

Admission waiting is distinct from a dispatched native probe. The coordinator
captures its candidate, context, native owner and original deadline, and allows
only one admission request. The completion returns to the existing serialized
controller context. Before creating native pending work it rechecks ownership,
current policy/network/lease, original monotonic deadline, latest permitted
handoff time and current candidate
health. A changed scope, cancellation, retirement, expired deadline or failed
storage burns any already committed quantum but sends no native command.
Half-open retry ownership is taken only after admission is confirmed.

Current authority checks may themselves take time. The controller samples its
actual monotonic clock again after those checks and immediately before effects.
The private start envelope carries a deadline clamped to the granted handoff,
the captured original lease and the original probe deadline. The actual engine
host worker checks that envelope again after its queue delay and before JNI;
the native command format and native proof/lease guards remain unchanged.

A closed host rejection identifies only the exact unstarted request and native
owner. It cannot act as a measurement, selection receipt or proxy failure. The
coordinator clears only matching unstarted pending work and preserves any
selected path. A failed final handoff burns its durable charge. An already taken
half-open retry keeps its existing bounded 15-second fence; local cancellation
does not erase cooldown or authorize an overlapping retry.

Native one-owner and final proof fences remain in force. The old physical path
is not withdrawn merely because admission storage is delayed. Cached status
reads and UI recomposition create no storage or network work.

## Required evidence

Actions must exercise copied checkpoints, same-boot/process restoration,
conservative reboot restoration, minute/hour/spacing/reserve boundaries, clock
rollback/sealing, malformed persisted data, crash before and after durable
reservation, slow-sync handoff/spacing, sync/readback failures, durable denial
seals, stale delayed callbacks, cancellation with
a still-busy worker and sixteen-group progress. Existing ordinary/race, legacy,
coverage, Android lifecycle and recovery gates stay required.

After exact source/main acceptance, separate Xperia USB/Wi-Fi checks must retain
the previous installed identity/configuration/settings, prior scoped cases,
two real Wi-Fi interruptions and native-process recovery. LTE, unplugged battery,
natural Doze, full common governor and activated managed-chain acceptance are
not established by these checks.
