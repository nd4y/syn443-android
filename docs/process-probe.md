# M1 Android process fault harness

Debug builds now include a non-exported bound service in a dedicated `:host_probe`
process. Release builds contain no probe service or fault injection endpoints.
The synthetic worker has no engine, TUN, network access, user configuration or secrets.

Three Android instrumentation tests prove actual remote PID separation, Binder death
after a worker stop, termination of a blocked worker through its responsive control
looper, successful rebinding, and rejection of commands bearing another session.
Every command carries a per-binding random session and replies preserve the request ID.
Only the dedicated service terminates its own process; tests never kill arbitrary PIDs.
The final unbind also terminates the dedicated process. Tests cancel automatic rebinding
before launching a replacement. CI runs these tests alongside the three diagnostic UI tests
on API 29, 35 and 37; physical results are recorded separately without device identifiers.

This is a fault harness, not the production ownership supervisor. A responsive control
looper does not establish recovery from a fully frozen process or native Binder failure.
The JVM HostFence is not wired to these callbacks: trusted identity locks, draining queued
launches, hostile PID reuse, persistent retry budgets, isolated native runtime, FD/TUN
ownership, foreground service lifecycle and real Wi-Fi/LTE traffic remain pending.
No VPN permission is requested and an existing VPN is not replaced.

The diagnostic screen respects system bars/cutouts and scrolls on small viewports.
UI tests bring controls into view before interacting, including after the bottom Stop.
