# Bounded NetBird reports and local views

This change addresses report loss and misleading presentation for a large peer
roster. It does not establish a tunnel crash or out-of-memory root cause. The
SDK still creates its complete connection snapshot before our projection; that
SDK allocation is outside this wrapper's bound.

## Profile without NetBird

When an active VPN profile has no NetBird outbound, route diagnostics say so
and omit peer checks. The local `netbird-status` result then reports
`configuredInRunningProfile: false` and carries no peer rows. A configured
module can separately be connecting, disconnected, or missing a fresh report.
The controller derives profile presence from the configuration of the running
engine for the same VPN intent generation. An unavailable or conflicting
observation leaves the field unknown.

## Owned memory and coverage

Our connection projection contains at most16 peer rows. The diagnostic job
retains at most1024 results and independently owned valid probe targets; it
does not retain the complete SDK peer slice for its worker lifetime. Display
strings and numeric fields are bounded before serialization.
Already redacted local startup errors retain readable text within512 UTF-8
bytes, with an explicit limitation marker; they are not silently treated as
enumerated codes or written to durable logs by this view.
A diagnostic
snapshot projects at most16 results before JSON encoding. The combined overlay
report remains within64KiB without discarding the connection header because of
an oversized roster. Failed component projection is explicitly unavailable.

Each peer/result section has `view` metadata: `page`, `page_size` (16), `total`,
`retained` (at most1024), `shown`, `omitted`, `pages` (at most64), and `request`.
Counts are integral and nonnegative; `omitted=total-retained`. Empty views have
page0 and pages0. Requested pages are clamped if the roster changes. A short
page never silently skips the remaining rows.

Diagnostic `coverage` reports `total`, `planned`, `checked`, `unprobed`, and
`omitted`. Planned counts valid admitted targets, checked counts actual reply
or no_reply outcomes, and `unprobed=total-checked` includes omitted and invalid
targets. Only a full check can be completed. Incomplete coverage is partial or
cancelled; a missing ICMP reply does not establish that a peer or tunnel is down.
The existing four workers, per-peer and whole-job deadlines, cancellation,
network epochs and actual-worker admission ownership remain in force.
An epoch change immediately after snapshot-watcher retirement now terminalizes
only the captured preparing job. It cannot leave diagnostics permanently busy
or change a newer job. A deterministic test reaches that exact ordering and
requires a subsequent real diagnostic job to complete. Retired samplers cannot
publish another owner's cache or import its page request.

## Read-only local selection

The private UI/ADB view command is closed JSON, at most1024 UTF-8 bytes:

```json
{"kind":"overlay-view","section":"peers","page":1,"request":"example-view-1"}
```

Only sections `peers` and `diagnostics`, pages0..63 and request IDs matching
`[A-Za-z0-9_-]{1,64}` are allowed. Duplicate, missing, unknown, mistyped and trailing fields are
rejected before any state change. The command only selects a view of existing
state. It cannot start probes, call the SDK, reconnect, change a route or policy,
or create a new overlay owner. Existing sampling supplies the correlated page.

Host dispatch is session fenced and bounded. The UI waits only for its own
request echo, disables overlapping requests and expires the wait after8seconds
without retrying. An unavailable response never changes VPN intent. Missing or
malformed booleans, counts and modes display unknown, rather than false, zero
or an assumed VLESS connection. Legacy reports retain their explicit facts but
cannot claim full coverage without coverage metadata.

## Acceptance boundary

The first full report run44135415802 reached instrumentation but all three
emulator jobs hit their one-hour job limit without JUnit reports. Its log does
not identify the last started test, so the location of the hang remains unknown.
The new paging tests now advance frames during real scroll actions and restore
their original clock mode even on failure. Their pending-request, command-count
and8.1second timeout assertions remain. A scroll may not consume an entire
8second pending interval.

The packaged JNI test constructs an unstarted, direct-only runtime through the
public seven-argument API. The generated Runtime has no public zero-argument
constructor. The test never calls Start, uses an owned null-device descriptor,
requires all three view calls to return false and all Protector calls to stay
zero, and closes the runtime and descriptor. The eight new cases emit only
allowlisted test lifecycle identities and fixed JNI phases. A20minute host
instrumentation deadline fails the harness before external scenarios; it does
not claim that interruption stops JNI. Disposable-emulator cleanup follows.
These markers are diagnostics and cannot satisfy any passing-outcome gate.

The following run44153507385 completed instrumentation instead of hanging;
API29 exposed two paging assertions that read semantics after only one paused
clock frame. A matching response clears pending through a LaunchedEffect and
needs a following recomposition. The test now waits at most256ms of virtual
time for each matching acknowledgement, retaining its existing assertions.
Unrelated and retired responses receive three frames before their negative
assertions, so a delayed erroneous clear cannot hide behind the first frame.
The explicit8.1second timeout and command-count checks remain. This is a
test-clock propagation correction, not evidence of a production paging bug.
The first helper revision in run44161867003 incorrectly queried synchronized
semantics inside a main-clock callback, which runs on the UI thread. The
framework rejected that helper on all APIs. Queries now run on the test thread
between at most16 individual frames, preserving the same256ms bound. The
failed helper run remains a failed acceptance attempt.

Exact source Actions must retain all prior JVM, Android, native ordinary/race,
coverage, contract, ABI, artifact and privacy gates and execute the new bounded
projection, parser, ownership and UI cases. Source CI, protected merge/main CI,
and an installed Xperia USB/Wi-Fi check are separate stages. Large real Cloud
rosters, full SDK memory bounds, the shared resource governor, LTE, battery,
natural Doze and endurance remain separate open requirements.
