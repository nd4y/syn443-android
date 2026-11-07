# Route search frontier

The planner scans an explicit directed graph for one network mode and traffic
class. A candidate must have an allowed physical entry, the required exit, and
the required capabilities on every hop and transition. Templates define ordered
hop slots. Repeated hops and duplicate paths are not emitted. No implicit
direct route is added.

The planner checks a conservative upper bound before allocating the cursor:
the sum of template slot products must not exceed 4,096, even if eligibility
will rule out many combinations. The cursor stores one position per hop. A step
examines at most 256 positions and returns at most 16 paths. Eligible warm
hints come first, then shorter templates, then a stable lexical order. Coverage
distinguishes examined positions from usable candidates and invalidation from
exhaustion. A changed context or expired monotonic deadline retires the cursor.

The JVM tests exercise complete enumeration of a sparse fixture across steps,
mode and capability fences, separate RU and NON_RU exits, warm hints and bounds.
The accompanying in-memory health table accepts only ordered evidence for the
exact context, path, traffic class and check group. Two confirmed failures
quarantine a path. The initial cooldown is 30 seconds. It grows exponentially,
with jitter and a ten-minute cap. After cooldown, one half-open probe is allowed.
Failures of a shared network or target, cancellation, exhaustion and unknown
errors do not affect that path's history. A confirmed authorization or config
failure waits for a new context. The table holds at most 64 records.

The planner does not establish tunnels or treat eligibility as evidence of
reachability. Signed graph delivery, runtime probe admission, fault attribution
and application of a freshly verified path are separate gates.

The native bridge has a guarded selector operation for a configured
noninterrupting group. It requires a current successful check on the exact
concrete member path, a matching previous member, and an unused receipt.
Network changes invalidate receipts and restore the original selected member.
The wire fixture exercises an existing and a new connection across a switch.

For signed provisioning, `route.health.v1` advertises support for the
per-outbound `route_checks` metadata that the client already consumes.
The control plane compiler checks scope, bounds, method and TCP capability
before signing it. Required checks are part of activation; an optional
outbound failure does not block an otherwise authorized configuration.

An enrolled client can use `route.failover.v1` for an explicitly configured
internal rule on validated Wi-Fi. The active member and reserves share the same
signed probe plan. Two different batches must show an active path failure and
a fresh successful reserve. Comparison uses recent successful checks, a cost
class estimated from the number of hops, and then latency. Confirmed failures
quarantine a member in the current network and activation context. It can
rejoin only with a fresh check sampled after its cooldown. The selector
changes new connections and requests a fresh check. No implicit direct path
is allowed. This pilot does not enable failover for RU or NON_RU, cellular
modes, or dynamic graph discovery.

Failover evidence carries the exit class from the authorized plan. A batch
labelled for a different exit cannot influence selection, failure count, or
quarantine, even when its probe target and latency are otherwise comparable.
This is a decision boundary for future traffic classes. It is not proof of the
geographic exit and does not enable a new class in the managed runtime.

An imported route profile can set `method: "https_exit_ip"` with an HTTPS
target and `expected_ip`. The approved target must return the current peer IP
as plain text in a noncached HTTP 200 response with a bounded content length.
The client dials through the configured outbound, verifies TLS and checks the
literal IPv4 or IPv6 address. Status keeps a mismatched address separate from
an invalid response and omits both addresses. The result depends on the
approved endpoint reporting the peer address correctly.
