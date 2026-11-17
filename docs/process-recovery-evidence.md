# Recovery fault evidence

Main run44115155327 on b7689dc failed the retained API29
`controllerDeathRetiresFrozenNativeAndPreservesIntent` case. The unchanged110s
deadline expired with Recovering/tcp_timeout. The other seven jobs passed.
The preceding ingress, egress, UI-death and force-stop recovery cases passed;
that does not establish fixture or Android data-path liveness at failure time.
The original cause remains unverified. No timeout, fault command or PASS
predicate is relaxed, and a later green run does not erase this failure.

The synthetic external driver now captures at most eight changed observations
from its existing polls and a final bounded report before cleanup. It reports
closed controller enums/booleans/counts, native PID relation without publishing
the PID, actual ingress/egress handler counters, existing server-thread liveness
and presence of the exact owned ADB reverse mapping. Missing or malformed
observations stay unknown. Mapping presence is configuration evidence, not a
successful TCP check. READY and PID are separate observations, not an atomic
owner binding; no owned-TUN witness exists in this status API.

Normal polling adds no ADB requests, probes, sockets or workers. Final failure
capture uses at most three read-only calls, each with a two-second timeout.
Counters retain handler exceptions without addresses, exception text or stack
dumps. Raw device output remains excluded from uploaded artifacts. Eight pure
synthetic helper/driver tests run in the existing Actions documents job.

This closes an evidence gap. It is not a production recovery fix, a proven
transport RCA, physical phone acceptance, LTE, natural Doze, battery or endurance
evidence. Exact changed-source CI and protected resulting-main checks remain
separate acceptance stages.
