# ADB control for development builds

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
| `netbird-status`, `netbird-diagnose` | Overlay status or request diagnostics |
| `netbird-cancel --job-id <id>` | Request cancellation of the diagnostic job shown by status |
| `netbird-view --section peers --page 1` | Select a read-only peer page; `--section diagnostics` selects result pages, page0..63 |
| `vpn-start`, `vpn-stop`, `vpn-resume` | Submit a command to the durable VPN intent controller |
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

Shell control remains restricted to debug builds. This client does not
expose fault injection, login credentials, raw configuration export or
managed policy overrides. Release opt-in, managed configuration editing,
mode commands, route job IDs and server audit require separate work. Keep
device output private.

## Offline archive candidate

The existing `diagnostic-bundle` JSON operation remains. The candidate adds
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
