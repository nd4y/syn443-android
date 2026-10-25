# M1 resource observation

`adb shell content call --uri content://io.syn443.control --method resources`
returns a versioned JSON snapshot. Same-UID access works in all builds; ADB shell
access remains debug-only. The UI button **Измерить ресурсы** calls the same API
on an IO dispatcher. Opening the UI does not collect resource counters.

There are two fixed roles, controller and engine, with no caller-supplied PID,
path, command, destination or process name. Each reading verifies the process
name, all four proc UIDs and start-time identity before/after reading. No engine
Binder call, native worker, network request, wake lock, alarm, background timer,
durable state write or new process is introduced. The controller cache admits at
most one pair of readings every 30 seconds, shared by UI and ADB callers. It
does not survive controller death; each new controller starts with a baseline.

Fields:

| Field | Meaning |
| --- | --- |
| sampledElapsedMs / sampledUptimeMs | Local monotonic observation times, with / without suspend |
| sampleAgeMs / cached / minIntervalMs | Age at the request, cache admission and minimum spacing |
| processes[].role / state | Fixed role; available, not_running, unavailable or process_changed |
| cpuTimeMs | Process user + system CPU time from proc ticks; excludes child processes |
| rssBytes | RSS from VmRSS in KiB, not PSS or Go heap |
| threads / fileDescriptors | Count; null means unavailable, not zero |
| window.state | baseline, measured, process_changed, counter_reset, clock_reset or unavailable |
| window.elapsedMs / awakeMs / cpuMs | Deltas between admitted observations |
| window.cpuPermille | CPU time / elapsed time * 1000; 1000 is one logical CPU |

Counters include measurement overhead. Proc input is bounded to 16 KiB per file,
command identity to 256 bytes and descriptor enumeration to 4096 entries. The
descriptor count can include the sampler's directory descriptor. Denied proc
access, races, malformed units, overflow and truncation return unknown; no raw
exception, process name, PID, file name, command line or credentials are returned.
Separate-role failure does not discard the other role. CPU uses an elapsed-time
denominator that includes suspend; awake time is exposed separately. Multicore
usage may exceed 100%. Replacement, decreasing counters or clock reset prevent
comparison across incompatible samples. A cached sample is explicitly historical
and may refer to a previous engine; it is never a connectivity/health verdict.

The UI renders a manual snapshot and instructs the user to take two readings at
least 30 seconds apart. Values stay historical until another explicit request.
No automatic upload, resource history, diagnostic bundle, native Go heap metrics,
remote retention or fleet telemetry pipeline is implemented in this increment.

Acceptance: nine JVM cases cover admission, exact spacing, suspend/multicore math,
replacement/reset, unknown sources, PID/UID/parser bounds and arithmetic overflow;
the module has a 90% line-coverage gate. Android tests check the real proc source,
strict field allowlists, shared cache, unchanged intent/config and the manual UI.
All run in Actions, including Android API 29/35/37. Configured-device tests use no
imports, connection commands or fault injection. Physical evidence remains
private. Short USB/charging observations do not establish NFR-05 battery targets,
natural Doze, RF handover or long endurance.
