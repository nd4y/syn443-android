# Activation check diagnostics

An activation deadline alone cannot identify which required check failed.
`status.policyChecks` exposes the last controller-fenced activation batch in RAM.
It retains at most eight positional rows with `index`, fixed `outcome`, `stage`
and `failure` enums. It never retains the check name, target, address, exception
message, certificate or response. A mismatch can be `FAIL` without an exception.
Checks that never started have a null stage and no inherited network failure.
`WORKER_REJECTED` and `WORKER_START_TIMEOUT` distinguish rejected admission
from a queued check that could not start within its budget. Both remain
`UNAVAILABLE`. The worker start marker and cancellation use the same lock.

`lastBatch` includes the observation's monotonic time, intent generation, network
epoch and activation generation. `current` requires the same scope, an active
engine, a nonnegative age of at most30 seconds and no intervening native owner
retirement. Stop, replacement and clock reversal cannot relabel historical
evidence as current. Controller death clears the RAM sample. Reads return copies
and do not schedule probes, change configuration, relax activation, clear failed
snapshot quarantine, extend authorization or reset restart limits.

Only the existing fenced result callback records a batch. Cancelled/stale owner
callbacks still fail their original identity checks before recording. Collection
adds no worker, socket, timer or persistent log. Same-UID access works through
the existing provider; shell access remains debug-only. A diagnostic collection
that already captures `status` includes this bounded snapshot.

Actions must run two required health JVM cases and three Android cases on each
API29/35/37. They cover mixed DNS failure/success/mismatch, cancellation and
deadline attribution, bounded positional output, defensive copies, invalid
input, owner/intent/network/activation changes, stopped engines and stale clocks.
The emulator activation driver captures this snapshot alongside existing worker
counts when setup reports unavailability or a scenario fails. The offline
scenario still requires a verified committed baseline before disconnecting.
Physical reproduction of a failed activation remains required; this feature
does not itself prove a route or diagnose an earlier unsampled failure.
