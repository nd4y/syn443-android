# NetBird diagnostic lifecycle

Connection to management and signal does not establish peer or private-route
health. An empty roster, stale evidence and an unavailable SDK read must remain
distinct from successful probes.

The local diagnostic cache has its own single publisher at the existing
five-second observation interval. It reads only the exact outbound's local job
state. A stalled SDK roster reader cannot prevent publication of completed,
cancelled or unavailable diagnostic work. Host control reads atomics; it performs
neither an SDK call nor a local diagnostic-state lock.

Explicit checks first publish `preparing`. The SDK roster stage has a local
maximum of ten seconds. A timeout publishes `unavailable` without inventing probe
results. The single admission slot stays occupied until that SDK call actually
returns; timeout never creates another uninterruptible reader. Cancellation and
network-generation changes still fence late snapshots and probes. This deadline
does not restart a VPN, rotate an identity, change relay preference or grant any
network access.

Five native regression cases cover cached progress while the SDK is blocked,
exact outbound ownership, cancellation during a local read, a roster timeout
without replacement workers or late success, and cancellation before a roster
returns. They run with the existing full/race native suites in Actions. These
source changes still require a successful complete matrix and affected physical
acceptance.

A bounded physical test of v35 with the SQL resource catalog reached direct
Cloud management and signal, then failed to observe a fresh terminal diagnostic
within its deadline. Its initial roster was empty. That observation does not
identify the physical cause: command admission, a network-generation change and
an SDK stall remain hypotheses. Intermediate diagnostic snapshots were not
retained by that test driver; the missing evidence is not reconstructed. The
device was restored and its one owned Cloud key/peer automatically retired with
independent baseline checks. The cache dependency described here is a separately
verified source-level risk, not a claim that the physical incident is resolved.

## Cancel a peer check

While a roster lookup or peer check runs, Android shows an action to cancel that job.
The debug CLI exposes the same action as `netbird-cancel --job-id <id>`.
Read `netbird.diagnostics.job_id` from `netbird-status` for the current job.
A pending response acknowledges dispatch. Read the diagnostic state again for the
terminal result. A new job has a fresh ID even on the same network. Older reports
without a job ID still show results. Cancellation signals the local context and
the worker releases its admission slot after it exits.
