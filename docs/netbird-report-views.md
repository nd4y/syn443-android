# Bounded NetBird reports and local views

This change addresses report loss and misleading presentation for a large peer
roster. It does not establish a tunnel crash or out-of-memory root cause. The
SDK still creates its complete connection snapshot before our projection; that
SDK allocation is outside this wrapper's bound.

## Owned memory and coverage

Our connection projection contains at most16 peer rows. The diagnostic job
retains at most1024 results and independently owned valid probe targets; it
does not retain the complete SDK peer slice for its worker lifetime. Display
strings and numeric fields are bounded before serialization. A diagnostic
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

Exact source Actions must retain all prior JVM, Android, native ordinary/race,
coverage, contract, ABI, artifact and privacy gates and execute the new bounded
projection, parser, ownership and UI cases. Source CI, protected merge/main CI,
and an installed Xperia USB/Wi-Fi check are separate stages. Large real Cloud
rosters, full SDK memory bounds, the shared resource governor, LTE, battery,
natural Doze and endurance remain separate open requirements.
