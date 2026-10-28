# Native fatal-crash diagnostics and recovery

SIGKILL/SIGSTOP injection does not prove behavior after an uncaught runtime failure. Android may account for Java/native crashes and suppress rapid restarts. This stage exercises uncaught Java exceptions and asynchronous Go panics with SIGABRT, while retaining the durable restart budget and Stop fence.

`engine-exits` is an on-demand read-only command. API30+ requests at most32 ApplicationExitInfo records for this package, filters the engine role, and emits at most4 sorted records. Fields are limited to a fixed category, timestamp and bounded status where meaningful. API29 reports unsupported. A failed source reports unavailable; an empty history invents neither a crash nor a successful connection. No description, trace, tombstone, PID, process name, endpoint or traffic is returned. The UI offers the same history on request. There is no background collector.

The optional PID filter is DEBUG/ADB-shell only and never appears in output. Fault commands require DEBUG, shell UID and an existing On owner. Private Binder injection additionally requires same UID, current session and a fixed kind allowlist. It cannot start an Off VPN, accept an arbitrary signal or expose a release external API. The Go panic entry point is admitted only through this private DEBUG host path; managed policy cannot invoke it.

CI requires actual fatal evidence, replacement ownership, synthetic HTTP through the real TUN and retained intent generation. API30+ checks OS exit metadata; Android may report a Go abort as native_crash or signal/SIGABRT. API29 uses the exact crashed PID and OS crash output. A Java crash series consumes the three-start window, preserves the exhausted budget across controller death and cannot resurrect after Stop. No budget is reset within a scenario.

Seven harmless Android cases cover filtering, limits, categories, failed/empty history, PID/time boundaries, real platform reads without intent mutation, and visible controls. Four external fatal cases are mandatory on every emulator API. All121 outcomes are required, retaining the prior110. Published reports include only method identities and outcomes; raw phone crash output stays private.

Physical acceptance separately verifies Wi-Fi HTTPS/internal reachability, OS exit metadata, competing VPN permission transfer and restoration of the original encrypted configuration/settings. LTE, natural unplugged Doze/battery, endurance and full per-route readiness remain separate. Compilation or a command acknowledgement is not acceptance.

References: [Android exit metadata](https://developer.android.com/reference/android/app/ApplicationExitInfo), [Go traceback configuration](https://pkg.go.dev/runtime/debug#SetTraceback).
