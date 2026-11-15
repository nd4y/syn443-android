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

This primitive is not exposed through the Java API, accepted configuration or a
signed device capability. Its callback still needs an independently authorized
immutable catalogue resolver. It does not grant graph eligibility, resource or
probe admission, fresh selection proof, active/draining ownership, connection
pinning, bounded asynchronous retirement or an atomic route switch. Those gates
must be implemented and accepted before runtime use. Source and executable tests
remain pending exact-head GitHub Actions acceptance; no physical path is claimed.
