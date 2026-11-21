# Device runtime observations

The optional sender uses the existing technical-telemetry consent and the
identity worker. The notice lists VPN state, application version and coarse
network type, and explains the administrator's view. Disabling consent cancels
both telemetry transports and removes the pending observation. Logout erases
the queue key. No site, endpoint, profile name, user identity or traffic content
is part of this report.

The existing supervisor may submit one observation per60 seconds on an
unmetered physical network and per300 seconds on a metered network. There is
no additional timer, wake lock or network probe. The current native handshake,
controller generation and worker-verified active policy determine the report.
A cached Online string or an unbound engine cannot become positive evidence.
Transport uses one captured physical network and refuses substitution or loss.
Stop, consent withdrawal, session changes and retirement fence late results.

While VPN operation is requested, the controller's `Connecting` phase is
reported as `starting` and `BlockedByPolicy` as `blocked`. The phone shows
working or partially working only when the current engine has confirmed
readiness. A pending stop can therefore show that the engine is still
stopping. If a phase is unfamiliar or evidence is missing, the home screen
shows that it is checking the VPN state. The last server observation retains
its own timestamp when reporting is paused.

A no-backup Keystore/AES-GCM AtomicFile holds one pending body and its per-key
monotonic cursor and next-attempt deadline, in at most4096 encrypted bytes. Retries retain the exact
body and sample time; a different state or a sample at least90 seconds old
reserves a newer sequence before dispatch. The sequence is the larger of the
previous cursor plus one and the conservative server-time sample. It is an
ordering token, not a count or a phone-clock reading. A new proof cannot make
an old sample fresh. Receipt loss leaves the queue intact. Acknowledgment
clears only its exact pending report. Consent withdrawal keeps the cursor and
budget. Attempt deadlines are committed before any dispatch, using the trusted
upper time bound plus the interval; a retry requires the new lower bound to
reach that deadline. Controller death, reboot, clock uncertainty, a lost reply
or toggling consent cannot buy additional radio work. Failure backoffs are
durable too. The RAM elapsed timer is only a cheap admission hint. A new
authority/device/key scope starts its own queue; login never reuses another
scope's pending body or RAM delay.

`POST /v1/device/runtime` uses the existing DPoP session, body hash and nonce
retry. The closed nine-field body is at most1024 bytes. Only an empty204 is
acknowledged. An older server backs off for an hour; sequence conflicts and
rate limits back off for five minutes without changing VPN or login state.
The server keeps one SQL row per device. Its console separately attributes
the report to the client and expires freshness at the earlier of sample and
receipt plus180 seconds. Thus metered or suspended clients can become stale;
there is no guarantee of a final Off report or continuous background delivery.
The activation receipt remains a historical record and is never rewritten.

Actions must retain the existing gates and all nine named identity wire/queue
cases, seven additional Android cases and the three-API lifecycle matrix.
The runtime core has an independently checked90% line gate. Actual SQL and
browser cases belong to the shared server contract. Exact-source CI, upgrade,
queue/cancellation and private Xperia USB/Wi-Fi report/readback acceptance
remain pending until recorded; cellular and energy acceptance remain open.

Rollback installs the prior verified APK with the same private development
signer. The additive queue can remain unused. Device key, assignment format,
binding, Stop and policy authority are unchanged by this reporting feature.
