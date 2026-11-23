# Android operator access over ADB

## Read VPN, route and NetBird status and logs from the release app

On the phone, open **Диагностический архив**. Under **Чтение через ADB**,
tap **Разрешить на 15 минут**. From the computer already paired with Android,
run `python3 tools/syn443ctl.py --serial <adb-serial> --local-read status`
or replace `status` with `logs` or `capabilities`. To inspect NetBird on a
compatible release, run `python3 tools/syn443ctl.py --serial <adb-serial> --local-read overlay-status --provider netbird`.
It reports the current control connection and its direct or VLESS transport.
When the underlying state cannot be confirmed the result is `unknown`.
This read neither contacts peers nor includes peer names, addresses or proxy
settings. Older clients continue to receive the original capability list. Logs also support
`--follow-seconds 60`. An unknown engine state omits `engineActive`.

To diagnose a sign-in problem, run
`python3 tools/syn443ctl.py --serial <adb-serial> --local-read auth-status`.
It returns the current login phase, a finite reason code, and available busy
and reauthentication flags. For example, `NEEDS_REAUTH` with `ACCESS_DENIED`
means access was refused. A cold controller returns `unknown`. An older
release reports an unsupported operation. On a debug pilot the same command
without `--local-read` uses the existing private provider and filters its output.
The current reason belongs to the running controller. After a restart, use
`logs` or the local support ZIP to look for an earlier `auth_access_denied`
event in the provisioning channel. It records the denial without an account
identifier and leaves the VPN state and its current reason intact.

To inspect the latest route checks, run
`python3 tools/syn443ctl.py --serial <adb-serial> --local-read routes-status`.
Each row identifies a route by its position in the current configuration.
It reports whether the route is required, its state, and the age in milliseconds
of a fresh success or failure. Adaptive routes can also report search progress.
An empty list means the current process has no route rows to report.
Reading the snapshot does not schedule probes. Device and proxy addresses,
route names and policy contents stay on the phone.

Use `python3 tools/syn443ctl.py --serial <adb-serial> --local-read config-render`
to inspect the running configuration. The command returns protocol counts,
whether adaptive routing is active, and available DNS and route-rule counts
for the current VPN generation. An idle controller or a replaced engine
returns `unavailable`. The command reads the same redacted configuration used
by the diagnostic archive after the engine starts.

The grant expires after fifteen minutes. The owner can revoke it on the same
screen. A controller restart also ends it. Exit code 4 with
`local_consent_required` means the phone needs a fresh local grant.
The separate read endpoint checks Android shell UID and returns a closed
projection of VPN health, overlay connectivity and technical events. The CLI lists exactly the
operations available through this grant.

The Android 15 installer workflow starts a separate ordinary app UID while the
owner's grant is active. Android denies status, logs, login and route reads
from that UID. It also denies access to the private config and archive
commands. Authorized shell reads still work and the VPN intent stays the same.
The app used to run this check is present only in the Android test APK.

See the [installer result](https://github.com/nd4y/syn443-android/actions/runs/45187983487).

## Development controls

Use `python3 tools/syn443ctl.py --serial <adb-serial> capabilities` to check
access. The serial is mandatory so a command never targets whichever phone
happens to be connected first. The client calls the existing debug provider
through ADB shell. It does not open a management port.

| Operation | Result |
| --- | --- |
| `status` | VPN intent, current runtime and route status |
| `logs` | Bounded technical event history; `--follow-seconds 60` emits changed snapshots as JSON Lines |
| `diagnostic-bundle` | Redacted state, captive-portal events, current transport and IP-family availability, activation-check freshness, route totals and process counters; no peer names, profiles, config or credentials |
| `routes-status`, `routes-check`, `routes-cancel` | Current results, request checks, or cancel; add `--route route-2` to check just one route |
| `overlay-status --provider NAME` | Accepts `netbird`, `tailscale` and `zerotier`. Planned modules return `not_implemented`. NetBird reports management and signal status. Read peer data paths with `netbird-view`. |
| `netbird-status`, `netbird-diagnose` | Overlay status or request diagnostics |
| `netbird-cancel --job-id <id>` | Request cancellation of the diagnostic job shown by status |
| `netbird-view --section peers --page 1` | Select a read-only peer page; `--section diagnostics` selects result pages, page0..63 |
| `vpn-start`, `vpn-stop`, `vpn-resume` | Submit a command to the durable VPN intent controller |
| `mode-get` | Current observed mode, automatic/assigned/manual source, allowed alternatives and their maximum duration. An inactive controller returns `unavailable`. |
| `mode-set --stamp <stamp> --mode WIFI --minutes 15` | Submit one temporary choice from the latest `mode-get`. Use `--mode AUTO --minutes 0` to clear a manual choice. Read `mode-get` again for the effective mode. |
| `config-plan`, `config-apply` | Validate and optionally write an unmanaged local config while the VPN is fully Off |

A successful command submission is not a successful connection. Read
`status` for the actual state. Every response has `schemaVersion` and
`operation`. Exit codes: 0 for a response, 2 for invalid arguments,
3 for ADB timeout/transport failure, 4 for a rejected command, 5 for a
malformed reply, and 130 for interruption.

To update a local config, run `config-plan --file <config.json>`, inspect
the returned `baseRevision` and `candidateRevision`, then supply both to
`config-apply --file <config.json> --expected-revision <baseRevision>
--expected-candidate <candidateRevision>`. The provider validates the file
again and compares both hashes before any write. The config travels over
ADB stdin into a private staging file, never as a shell argument. A timeout
does not imply that the operation failed; read the current revision before
retrying.

Debug shell supports unmanaged local configuration planning and application.
The ordinary release supports the passive reads listed above after local
consent. Keep device output private.

## Offline archive in debug builds

Use `diagnostic-bundle` for the bounded JSON snapshot. To use a local ZIP, run
`support-bundle --output FILE`, `support-bundle-collect`,
`support-bundle-status --bundle-id ID`, `support-bundle-cancel --bundle-id ID`
and `support-bundle-export --bundle-id ID --output FILE`. Only an explicit
export creates an output file, after full hash/ZIP/manifest validation, and
never overwrites an existing path. Job IDs support polling and cancellation;
short binary grants are not printed. See [scope and protocol](offline-support-bundle.md).
The existing DEBUG shell UID restriction is unchanged; release opt-in remains
a separate requirement. No archive is uploaded automatically.

NetBird view selection returns `pending`, section, requested page and a fresh
request ID. This is only command submission. A subsequent `netbird-status`
must contain that ID in the corresponding section's `view.request` before its
page can be treated as the response. The actual page may be clamped when the
roster shrinks. The CLI does not start diagnostics or poll automatically.
Reports show at most16 rows per section and retain at most1024; explicit
omitted/unknown/partial coverage prevents a truncated roster from looking like
a completed check of every peer. See [report bounds](netbird-report-views.md).
