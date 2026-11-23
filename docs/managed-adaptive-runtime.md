# Managed adaptive TCP runtime

The negotiated `route.adaptive-tcp.v1` primitive accepts key-bound configure
policies using compiled algorithm `m4-graph-tcp-v1`. The closed protected wire is
specified by [`adaptive-runtime.schema.json`](../contracts/v1/adaptive-runtime.schema.json).
Graph metadata describes eligibility; only a fresh actual native check receipt
can authorize a data path. A caller cannot replace the signed `route_checks`.

A managed policy can require checks on both adaptive groups and ordinary
outbounds. Each concrete outbound is checked through its own signed plan.
Both kinds share the device's start budget. A required route needs its own
fresh observation after activation begins. On a mode change the client discards
obsolete results and pending ordinary checks. Manual single-route checks use
the same admission rules.

Go and Kotlin use dedicated duplicate/presence/canonical decoders. The original
wire's UTF-8 bytes and number lexemes are retained before JSON normalization.
Limits remain196608 wire bytes,262144 assigned engine bytes,500 normalized
profiles,16 managed TCP groups, four hops,32768 shared decoded tokens and depth16.
The rendered native config has a separate524288 bound for owned TUN/DNS/overlay
material; this does not broaden the assigned policy or wire limits.

The actual native box registers the managed outbound before options decoding,
then binds its catalogue/hub to that exact registry, router and manager before
Start. No uninitialized adapter or missing selection may borrow a default route.
Configured adapters, dynamic paths, socket holds and unknown constructors retain
their resource reservation until actual retirement. Dynamic UDP/ICMP and NetBird
SDK underlays through a managed group are rejected explicitly.

The local owner derives an opaque scope from a random nonce, native network
epoch, policy/runtime context, wire hash and physical mode. A synchronous bounded
own-UID Binder call invalidates it on every Java network epoch, including loss,
captive and validation-only changes, before publishing the new context. SDK work
runs on one separately owned worker. Cancellation never frees a blocked worker.
BOOTTIME fences apply before subsequent I/O as well as receipt publication.

The Android coordinator scans the bounded frontier, confirms actual native
receipts and commits/discards them once. Lost acknowledgements retry the same
receipt, then request real isolated host retirement; no timer pretends resources
were freed. Fresh exit contradictions withdraw only the affected group's active
flows. An uncertain target/reserve result cannot overwrite another healthy path.
Context-specific negative memory never classifies an unattributed timeout as a
confirmed bad proxy.

When checking a policy change from the app or ADB, read `routeHealth` in the
current lifecycle status. `measurementRevision` identifies the configuration
that owns the observed route. While the lifecycle revision is missing or changing,
wait for the new policy's measurements before using its status or latency.
A matching revision allows the app to display measurements from its current
owner again. [Route status implementation](../app/src/main/kotlin/io/syn443/android/vpn/RouteSnapshot.kt)

A failed check is a separate observation with a compiled finite reason and an
actual native BOOTTIME completion timestamp. Local admission/operation limits,
constructor failures, cancellation, expired budgets and panic remain uncertain.
Only a fresh independently checked replacement for the same group and native
context may trigger immediate recovery. The old path enters context-specific
negative memory after the native selection acknowledgement, and only within30s
of the actual failed check completion; delayed delivery cannot refresh it. A
failed reserve never degrades an independently healthy active path. Backward or
out-of-range coordinator clocks require actual host retirement.

Initial recovery takes priority over maintenance. The coordinator bounds attempts
to8/minute and128/hour across its groups and context rebinds. Healthy metered
maintenance confirms the current route. Optional unmetered exploration requires
adequate battery and no power-saving mode. The active path stays selected for at least 60 seconds during voluntary optimization.
The coordinator timestamps successful observations when the native payload check
finishes on the Android boot clock. Waiting for the selection acknowledgement does
not extend the freshness window in route status or defer the next routine check.
A receipt without a timestamp uses its request start. A receipt with a malformed
or out-of-window timestamp is discarded. The hold time for a newly selected path
still starts when the selection is acknowledged.

A reserve must improve latency by at least 20% and more than 15 ms on three consecutive
checks against a fresh baseline. A stale baseline schedules a check of the current path.
An independently confirmed outage can use a freshly verified replacement immediately. Native
`probeMs` excludes adapter construction time. These are local coordinator bounds,
not a claim that all SDK/telemetry/diagnostic work already shares one governor.

Actual mode classification currently supplies Wi-Fi or ordinary cellular; home
identity and restricted-cellular detection remain separate work. Availability of
this TCP primitive does not claim all four application modes or physical LTE
acceptance. No LTE device test is authorized in this stage.

Actions must exercise45 required native roots in ordinary/race suites, the public
candidate graph case, eight new codec JVM cases, three new signed policy cases
and16 new Android config/controller cases. Android matrices require259 actual
outcomes each on API29/35/37; all prior lifecycle/privacy/coverage gates remain.
Exact-source CI, signed-policy deployment and real Xperia TUN/chain/recovery
acceptance remain distinct release gates. All fixtures are synthetic.

## Lease renewal and bounded search continuity

A normal five-minute signed lease renewal must not restart a still-authorized
search or discard a healthy selected path. The identity worker prepares an
execution-authority stamp after the existing signature, assignment and engine
checks. Only revision and the four signed lease timestamps are excluded. The
complete remaining payload, exact engine, signer, full pinned root set,
bootstrap authority and installation trust anchor participate. The parent
assignment renewal predicate is shared without relaxing its phase, epoch,
revision, capability, gate or key-binding checks.

The VPN handler reads this prepared metadata under the current assignment
ticket, exact envelope, boot and deadline. An equal stamp may update the policy
revision label while preserving the same native scope, pending one-use receipt,
selection, failure memory and search position. It does not acknowledge a native
lease extension. An expired old owner, a changed boot or a backward clock
requires actual host retirement; a newer signed lease cannot revive that owner.
Other authority, content, mode or runtime-context changes retain the hard reset.
Missing installation-trust evidence permits only strict per-envelope identity,
so it cannot establish continuity across renewals.

Frontier expiry can resume from an opaque, RAM-only mixed-radix position bound
to the exact graph instance, immutable metadata, group, full context and effective
warm hints. This position carries no metric, lease, path authorization or native
receipt and is neither serialized nor accepted over an API. Restoring scans at
most64 template bounds and four digits; subsequent candidates still pass current
eligibility and fresh native checks. Context or clock invalidation permanently
disables that cursor's resume. A64-candidate CPU quantum yields to the next group
even when it finds no eligible candidate. Total8/minute and128/hour admission
limits survive force and context changes.

These changes require named signed-policy, cursor and Android continuity outcomes
in Actions. They do not by themselves establish actual managed-chain acceptance,
unlimited search under changing network conditions, a common energy governor or
a recovery reserve after routine checks consume the hourly budget.

## Recovery capacity and passive symptoms

The next candidate keeps the hard8/minute,128/hour and five-second start spacing.
Routine maintenance/exploration has an additional6/minute and96/hour ceiling.
No-route and confirmed recovery work may use the remaining capacity; routine
work cannot consume it. Due recovery groups precede routine groups. The same
bounded128-record ledger survives force and context changes, and an invalid or
backward clock seals admission. Maintenance is spread over the group count:
max(60s, ceil(groups * 3600s / 96)), giving600s for16 groups. These are local TCP
coordinator limits, not a common SDK/diagnostic/telemetry governor.

A group that spends a CPU quantum without starting I/O yields to other due
groups before competing again, even if it needs recovery. This fair-round state
is bounded by16 groups and cannot be erased by force. A manual refresh requests
a routine current-path check without discarding its actual measurement time or
borrowing recovery capacity.

Actual admitted TCP read/write failures can request a fresh check through the
existing heartbeat. A selector has one bounded hint slot. Three independent
owned flows must complete with a finite recognized network error inside30s;
each flow counts once. EOF, cancellation, caller deadlines, local refusal,
panic and unknown errors contribute no evidence. There is no destination history,
traffic content, extra timer, worker or I/O. Dial failures and silent blackholes
are deliberately outside this passive signal; paced active checks remain needed.

Every actual native commit captures a safe-integer selection token in its exact
consumed proof. The selected acknowledgement echoes that token and the consumed
receipt; the latter is diagnostic data and cannot authorize a replay. Captures
from draining A or an earlier A->B->A selection cannot affect the current path.
Read/write observation takes only the existing pool mutex and retains real
operation/flow ownership. The stream lifetime, not its initial30s dial budget,
controls eligibility. Token/sequence exhaustion disables only the hint lane.

The controller accepts at most16 closed hint records, under the current native
epoch/scope and matching acknowledged selection token. A newer sequence and a
fresh actual BOOTTIME completion are required. Duplicate heartbeats do not refresh
the timestamp or mint work. A hint changes no verdict, quarantine, selection or
readiness: it schedules a budgeted current-path check. Any replacement still
requires fresh native proof and the exact matching selected acknowledgement.
Busy or pending work keeps its admission until actual completion/retirement.

Actions requires eight additional actual native roots in both ordinary/race
suites (53 total), six budget JVM roots and seven Android controller roots.
Each API29/35/37 matrix requires279 unique actual outcomes without failures or
skips. Synthetic controller reports do not establish packet or physical proof;
signed managed-policy deployment and actual USB/Wi-Fi chain recovery stay separate.

### Rolling stability in the live coordinator

Each comparison group retains at most five attributable outcomes per path over ten minutes. Three failures in that window mark the path degraded. Three consecutive fresh successes clear the degradation. The coordinator accepts a failure from an explicit exit mismatch or a failed incumbent check corroborated by a working replacement and its native selection acknowledgement. Common target failures and passive traffic hints alone supply no path-quality sample.

For a voluntary switch, the reserve needs three consecutive fresh successful measurements and the existing hold time. A confirmed stable reserve can replace a degraded incumbent even when that reserve is slower. A sole usable path and corroborated hard failure still use the existing recovery rules. Samples belong to the current physical, policy and native execution context. Up to 64 paths retain history. The ten-minute pilot window uses elapsed time and consumes no extra background probes on its own.

## Setup cost for a common exit path

When a healthy route and a candidate use the same ordered exit profiles, each extra upstream proxy adds a session to establish. The coordinator uses this structural estimate to prefer the shorter path after three independent successful checks, even if its application probe took longer. A lower latency alone cannot promote a longer prefix to that same healthy exit. Comparable paths with unknown relative setup cost keep the existing latency thresholds. Confirmed path degradation and recovery take priority. The device still requires a live native receipt from the authorized path to switch.
