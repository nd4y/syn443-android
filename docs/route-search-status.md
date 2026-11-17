# Bounded managed route search status

This source-stage M4 slice adds read-only progress to each configured managed
adaptive row in the existing `routeHealth.routes` response. It does not create
route evidence, select paths, authorize traffic, change activation or introduce
an admission budget. At most16 configured groups receive the closed additive
object `search: {state: ...}`. It contains no graph/path/profile IDs, native
scope, receipt, endpoint or proxy credentials. Existing route fields retain
their existing meaning.

| State | Meaning |
| --- | --- |
| `WAITING_CONTEXT` | The current native/policy/route context is unavailable or retired. |
| `SEARCHING` | A bounded owned group check or its selection acknowledgement is pending. |
| `BUDGET_WAIT` | Existing admission limits deferred another check. Continuation remains possible. |
| `SEARCH_INCOMPLETE` | No fresh confirmed selection is available in this projection; coverage is incomplete. |
| `VERIFIED` | A selected native acknowledgement was received and existing route evidence is still `WORKING` in the current live scope. |

`VERIFIED` requires both the coordinator's selected acknowledgement and the
unchanged `RouteEvidence.classify` result. The existing120000ms freshness
boundary, future-sample rejection, scope, desired state and owner readiness
still apply. A verified-but-uncommitted receipt or cached plan cannot produce
that state. Network/native scope changes and retirement remove the projection;
ordinary reset/owner/invalidate clears its RAM state. Failure of one group does
not erase another group's fresh confirmed selection.

The coordinator publishes prepared enum values without initiating diagnostic
I/O. Reading status or recomposing the UI does not call admission or dispatch
commands. The production snapshot clock remains `SystemClock.elapsedRealtime()`;
an internal `readAt` seam exists only for deterministic boundary tests and is
not exposed by the Provider/UI API.

The first slice deliberately does not emit `COMPLETE_NO_CANDIDATE`. Exhausting
one static metadata frontier, skipping a cooling candidate, reaching a64-slot
CPU quantum or consuming a probe budget cannot establish that no usable route
exists. Counters, confidence, full negative coverage and all four network-mode
classification remain separate M4 work. The existing independently bounded
selection, quarantine and RAM probe-ledger semantics are unchanged.

Ten exact Android roots are mandatory in Actions: six coordinator simulations
and four snapshot/presentation cases. They cover selected acknowledgement,
budget continuation, CPU/exhaustion uncertainty,16 groups, independent failure,
scope/lease/clock retirement, exact TTL boundaries and side-effect-free UI.
The per-API floor is437; identity remains249. Source preparation is not executed
CI, physical Wi-Fi/LTE, battery or full autonomous-routing acceptance. Version90
delivery and its earlier evidence remain separate; this slice has no version
bump or device changes.
