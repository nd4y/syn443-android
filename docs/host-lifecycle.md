# M1 host ownership fence

The pure JVM `:core:host-lifecycle` module implements only the single-owner fence required by MOD-08/MOD-09. It does not create a process, own a real TUN, kill a PID, connect a VPN, or prove the physical ARC-02 gate. The diagnostic app is unchanged. M0 PR/release sources remain unchanged on their existing branch.

The Android supervisor will execute typed `Launch`, `GracefulStop` and `TerminateOwned` effects. Each effect is bound to a supervisor instance ID and monotonic host generation. The instance ID must be a fresh cryptographically random 128-bit value for each supervisor lifetime. A PID alone is never an ownership identity. The future adapter must match the token to its own authenticated process/Binder handle, UID and identity lock before acting; it must never signal a foreign process.

| Current state | Event | Result |
|---|---|---|
| Idle | Reserve start | Reserve the next generation, emit one launch, start a bounded deadline |
| Any reserved state | Reserve start | Reject as busy; no second host |
| Starting | Ready before deadline | Running |
| Starting | Ready at/after deadline or expired tick | Request termination of the same owned host, await death |
| Starting/Running | Stop | Request one graceful stop with a fixed deadline |
| Stopping | Repeated stop | Keep the original deadline; no duplicate command |
| Stopping | Late ready | Reject; never return to Running |
| Stopping | Deadline expires | Request termination, await death |
| Starting/Running/Stopping | Hang | Request termination of the exact owned token, await death |
| Awaiting death | Any start | Reject until exit/release is proven |
| Any reserved state | Verified exit without released identity | Await release; keep ownership reserved |
| Awaiting release | Verified identity release | Idle |
| Any reserved state | Verified exit with released identity | Idle |
| Any state | Foreign/old callback | Reject; preserve the current owner |

`confirmedExit` and `confirmedRelease` are trusted supervisor inputs, not native IPC acknowledgements. A JVM timeout, a native `stop` ACK, an interrupted coroutine, or an untrusted PID report does not establish death or released descriptor/identity ownership. The proof must also include cancellation/draining of every pending launch effect: no queued fork may still create an old host after release. Effect dispatch and ownership validation must be serialized with lifecycle events. The Android adapter and instrumentation fault injection must prove these facts before using either method.

All methods serialize mutations. Time inputs are monotonic **processing** timestamps in milliseconds, read inside the future supervisor's serialized dispatch, not timestamps captured earlier by asynchronous callbacks. Regressing/negative time on ordinary events is rejected without changing ownership. Stop has precedence: an invalid clock requests owned termination rather than throwing or extending a deadline. Deadline arithmetic and generations never wrap. At clock exhaustion a running host can still be stopped by requesting owned termination. At generation exhaustion new starts fail closed. No method queues an automatic replacement after an exit callback.

The fence token does not replace M0's six-field configuration/network context. The adapter must carry both identities, preserve Stop intent in the activation coordinator, block traffic while ownership is uncertain, and admit any recovery through bounded retry/resource scheduling. This module does not implement persistent retry budgets, consent/unlock handling, foreground service/TUN management, Binder/FD transfer, physical Network protection, health probes, native kill confirmation, engine adapters or real traffic recovery.

Validation: eleven JUnit methods cover overlapping starts, Stop/late-ready races, exact deadline boundaries, crash/release ordering, stale/foreign tokens, clock/generation exhaustion, invalid inputs including Stop during clock regression, 100 concurrent start/stop requests and 10,000 deterministic randomized events. CI requires actual successful JUnit evidence and JaCoCo minimums of 95% lines / 90% branches. Native crash/hang/PID reuse, TUN retention and RF/battery acceptance remain M1 pending.
