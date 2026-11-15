# Private path construction - unactivated M4 primitive

The construction helper clones the pinned service registry before substituting a
private outbound manager. It cannot look up a parent default or endpoint, mutate
the active manager, or add more than four adapters. Only HTTP, SOCKS, VLESS and
SSH are admitted here. NetBird identity and its active SDK are never cloned.

Generated private tags replace configured tags. Each hop may depend only on its
previous hop. Construction/start proceeds from ingress to egress. Every returned
object, including an object returned alongside a constructor error, is owned
before validation and retired in reverse dependency order on failure. Constructor
and lifecycle panics become a generic candidate failure; a close panic cannot
prevent retirement of earlier owned objects. Retiring a candidate cancels only
its child context and never closes or resets the configured parent manager.
If cleanup itself fails, the helper returns a separate retained owner and no
usable path. Its handles and resource reservation must remain held until
confirmed recovery; a failed close is never counted as released capacity.

Native tests use real loopback SOCKS and HTTP handshakes and payloads, check both
hop counters, reject parent/default borrowing and external mutations, exercise
concurrent registry reads, preserve a working parent connection after retirement,
and inject partial construction, invalid dependencies/tags and lifecycle panics.
All three named cases must actually start and pass in ordinary and race JSON
evidence. An unrelated package, omitted outcome or skip cannot satisfy the gate.

The candidate owner pool additionally reserves all in-flight, usable, draining
and retained adapters together with the immutable configured adapters. Its local
cap is at most128 adapters, eight resident candidates and128 held references.
Only one constructor may run; a blocked constructor cannot be replaced after a
context change. Closing uses one permanent worker with a bounded queue. A blocked
or failed close retains capacity, while Stop and scope changes return promptly
and reject stale work. Graceful retirement rejects new references and lets old
holders finish before closing the private adapters. Real SOCKS/HTTP traffic and
configured-parent survival are tested under this ownership model; separate cases
cover blocked construction, late completion, failed/blocked retirement and caps.
Actual TCP/UDP handles now retain their reference through confirmed socket close
and completion of every in-flight dial/read/write. Even a successful adapter
close cannot release capacity while a late dial or read is pending. A bounded
per-flow and pool operation admission prevents unlimited concurrent work. The
pool requires a live managed lease; zero/unmanaged or expired leases are rejected.
Each socket operation checks current context/lease, and a late read cannot publish
bytes after withdrawal. Panics and failed cleanup preserve an uncertain owner
reservation. Pool/candidate/flow diagnostic formatting redacts route details.
Real SOCKS/HTTP TCP payloads, local UDP socket ownership, late positive reads,
partial/panicking dials and close failures are mandatory test cases. Local UDP
ownership tests are not proof of SOCKS/VLESS UDP protocol acceptance.
All nine constructor/pool/traffic cases must pass in ordinary and race JSON evidence.

This primitive is not exposed through the Java API, accepted configuration or a
signed device capability. Socket ownership grants no route selection authority.
It still needs an independently authorized immutable catalogue resolver, graph
eligibility, shared priority/probe admission, fresh proof-bound atomic selection,
drain deadlines and client integration. Those gates must be implemented and
accepted before runtime use. Source and executable tests
remain pending exact-head GitHub Actions acceptance; no physical path is claimed.

The earlier construction primitive and ordinary/race cases passed [exact c43 Actions43715523260](https://github.com/nd4y/syn443-android/actions/runs/43715523260).
The added pool/traffic lifecycle requires its own complete Actions acceptance.

