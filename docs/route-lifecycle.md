# M1 route evidence and Android lifecycle

This stage adds per-outbound route evidence, not a universal reachability claim.
Every configured outbound has a row, including unused and unmeasured paths.
`routingRules` counts references to that outbound. An available TUN, optional
NetBird SDK or another successful outbound cannot make an unmeasured row work.

The optional client configuration field `route_checks` assigns a profile:

```json
{
  "outbounds": [{"type": "direct", "tag": "internet"}],
  "route": {"final": "internet"},
  "route_checks": [{
    "outbound": "internet",
    "required": true,
    "checks": [{"method": "https_204", "target": "https://probe.example.org/generate_204"}]
  }]
}
```

At most16 profiles, four checks each,64 total and24,000 UTF-8 bytes of profile
metadata, using all-of semantics. Supported
methods: `tcp`, `ssh_banner`, `tls`, `https_204`. HTTPS requires normal certificate
and hostname verification, status204, no body/transfer encoding and no redirect.
TCP means dial/transport establishment, not an application response or proof of
country; lazy proxy transports may provide weaker destination evidence. Use TLS,
SSH banner or HTTPS when application/data-path proof is required. An SSH banner
requires `SSH-2.0-`. New primitives and all/any/quorum trees remain capability work,
not silently accepted fields. Profiles and targets are configurable, without RU,
NON_RU or private-target assumptions. Missing profiles stay unverified.

Native probes use the requested outbound's actual DialContext, including detours
and selected groups; there is no direct fallback. Measured path IDs show selector
choice and detours. A changed selected path invalidates the sample. The profile is
client metadata and is removed before native configuration parsing. Successful
probes do not establish every routing-rule predicate, every destination/protocol,
exit geography or resilience of untested peers.

One batch, two workers,3s per check and30s total. Cancellation retains admission
until old workers drain; a non-interruptible call cannot grow the pool. No probes
are admitted outside the managed lease; a shortened lease cancels existing probes.
Native monotonic sample time, intent/network/activation/engine/config scope and
request ID are retained. Repeated heartbeats never refresh observation time.
Records live only in controller RAM; no targets, credentials or exception text
enter event logs. Local UI labels can contain private profile names and must not
be copied into public evidence.

States distinguish off/unavailable/unverified/checking/working/failed/stale/
incomplete. Freshness lasts120s; automatic configured checks run no faster than
once60s through the existing supervisor, with a manual check/cancel option.
Unknown, stale or failed required evidence prevents Online. An optional failure
does not restart the engine or withdraw independent traffic. Existing HTTPS/TUN
readiness remains required too. Cancellation/incomplete evidence is not a proxy
failure and does not consume the heavy restart budget.
If global readiness fails while a current assigned-target route still works, the
overall status is Degraded. Independent private traffic is retained; that partial
success never hides the failed global requirement or becomes Online.

ADB commands: `routes-status`, `routes-check` (optional `route-N` argument),
`routes-cancel`. These do not Connect or change user intent. `status.routeHealth`
uses the same memory view as UI. No check starts while Off; unassigned profiles
are visible. Labels/target settings require ordinary protected configuration import.
For now profiles are admitted only by the unmanaged M1 configuration import.
Signed assignment containing this extension is rejected until its activation gate
can include the same outbound-bound required evidence; it cannot silently commit
such requirements through the older generic policy-check protocol. Tags are bounded
to256 UTF-8 bytes. Probe-local exceptions become incomplete `probe_unavailable`
evidence, with no exception text. Authorization is rechecked at I/O and completion
using the boot clock, including after suspend.

The DEBUG-only `health-workers` command samples the existing shared policy-check
pool on explicit request: capacity counters and at most two fixed-name worker
stacks, twelve class/method symbols each, cached for30s. It contains no targets,
arguments, exceptions or configuration values, does not clear work or increase
capacity, and is unavailable in release builds. Emulator policy failures capture
this evidence instead of increasing activation deadlines or accepting incomplete checks.

## Lifecycle contract

The provider and boot receiver can observe Direct Boot. While the user is locked,
they do not create/read StateStore, Keystore, identity or recovery journals.
Status is NeedsUnlock with null desiredOn and desiredOnKnown=false. Commands are
rejected. BOOT_COMPLETED after unlock uses the existing durable intent/OS marker
and validated config/lease; it does not enroll again. No direct-boot copy of secrets
or alternative restart timer is introduced. Force stop still cancels the retained
non-wakeup sentinel; reopening or package replacement cannot silently resume it.

Actual system policy is sampled from an existing VpnService on status request.
With no live service the state is unknown, rather than presenting old cached flags
as current. UI links to ordinary Android VPN settings. Stop keeps precedence even
with Always-on/lockdown; lockdown may block traffic until policy is changed in
Android. The client does not rewrite secure settings or infer new Connect from a
restart callback.

New mandatory CI scenarios cover actual independent outbound/selector traffic,
required failure/optional independence without process restart, late-result Stop,
package update while Off, real secure locked boot/unlock, reboot while Off,
ordinary Settings Always-on/lockdown with newer Stop, and Force stop followed by
package replacement. The synthetic PIN is confined to disposable emulators and
is never set on a physical phone. Existing process/revocation/enrollment scenarios
remain mandatory. Minimum138 outcomes on each API29/35/37; recovery JVM minimum14.

The persisted engine-active flag is a recovery checkpoint. Status reports false
when no live controller service and no owned engine process exist, and unknown
when an orphan process or unavailable OS process inventory prevents a current
ownership claim. This response projection never changes durable intent, restart
budgets or the recovery checkpoint.

The emulator reboot driver requires an advanced Android boot counter. If the
owned host VM exits during reboot, it may cold-start that same AVD once using its
preserved userdata and port, without wiping data, clearing the PIN or replaying
Reboot/Connect. A live but unreachable VM is never replaced. The same150s boot
budget and every locked/unlocked/config/intent/budget assertion remain required.
PIN input waits for the real SystemUI keypad and verifies user unlock before
expecting recovery. CI uses the supported software renderer; the former
`swiftshader_indirect` mode is deprecated in [Android Emulator documentation](https://developer.android.com/studio/run/emulator-acceleration).

Physical Xperia acceptance is recorded separately from CI in the change's validation notes. The phone's
credentials must not be changed to manufacture a locked-boot test. USB/Wi-Fi can
verify supported reboot/update/force-stop/system-policy behavior and real external/
internal traffic. LTE, natural unplugged battery/Doze/endurance and complete M1-M5
acceptance are explicitly outside this stage. Green CI is not physical acceptance.

### First policy while restart budget is occupied

The first enrolled assignment keeps the TUN closed to user traffic until a
valid activation permit is ready. If local recovery history cannot reserve
both a start and rollback, the controller reports the earliest retry time and
uses the bounded hostless wake interval. The durable budget and the required
checks are preserved. A prepared assignment with an expired or withdrawn
lease remains blocked.

### Physical network preference

The network candidate compares the platform's validation and captive-portal
signals separately from transport. A newly visible, unvalidated Wi-Fi network
does not replace a validated network or the current VPN path with successful
checks. Validated Wi-Fi is preferred, equal choices retain their current
owner, and lost networks cannot lend their evidence to a replacement. The
selector does not infer trusted home Wi-Fi or restricted cellular access
from a transport. The controller consumes ordered Android callback values for
capabilities and link properties. Loss of validation or a metering change on
the same network advances the probe epoch and cancels pending measurements.
If the handle and link properties are unchanged, the controller keeps the
native network binding and does not advance the recovery budget. JVM cases
cover ranking, loss and the distinction between capability and path changes.
Physical handover and the four-mode policy matrix require separate acceptance.

When Android selects an Ethernet or other unrecognized physical underlay,
the adaptive runtime uses a distinct local `UNKNOWN` mode. Only entry hops
declared in all four signed network modes qualify. Both the Kotlin planner
and the native selector apply this rule to the first hop, retain the path's
existing exit and capability requirements, and require new evidence on the
new physical network. An empty set of eligible paths leaves the affected
group unavailable. The signed graph schema still accepts four declaration
values. Absence of a physical network continues to suspend probing.

### Route report delivery

The host publishes a route batch as soon as it is admitted, then reads its
result every two seconds while the same batch is running, for at most 35
seconds. Completion, cancellation, network replacement and owner retirement
end the polling window. This moves result delivery off the slower host
heartbeat without scheduling additional network probes. The two distinct
failure batches and fresh reserve checks remain required.

### Reserve probe cooldown

For the enrolled, signed internal Wi-Fi selector, a failed optional reserve
is attributed only when a different member passes the identical checks in
the same batch. The result must name the complete expected chain; missing,
cancelled and changed-path samples cannot create a failure. The second
independent attributable failure starts the existing local cooldown.

Routine checks defer optional members during that cooldown. They still
probe the required selector and any other required routes. A manual
diagnostic or a policy activation keeps its full check set; it cannot
promote a reserve with evidence sampled before the cooldown expires.
After expiry the reserve returns to the bounded probe scheduler and
needs fresh evidence. Changing the network, configuration or engine
fences both observations and cooldown. This is a single-intent Wi-Fi
implementation; it does not claim graph exploration, persistence across
process restart or physical cellular acceptance.

The controller requires the signed `route.reserve-cooldown.v1` capability
on the active, key-bound configuration to attribute optional reserve
failures and suppress their routine probes. Existing signed configurations
continue the previous scheduling behavior. A failed opt-in uses a distinct
rollback fingerprint; the legacy configuration with identical proxy bytes
can still be issued as a newer revision. This is a fixed local evaluator
feature that can be enabled for a reviewed recipient set.

Wi-Fi can be available before Android marks it validated. The first
validated, signed failover batch for the current route scope can bypass
the normal cadence once. It waits for a batch already in progress and
does not reuse its unvalidated measurements as a new receipt. Later
validation callbacks for the same scope cannot repeatedly accelerate
probing. Two independent receipts and a verified reserve remain required.

### Captive portal wait

When Android reports a captive portal, that physical Network is excluded
from VPN admission, even if the VPN previously had good evidence on it.
Other usable physical networks remain eligible. With only captive
networks, the controller keeps the user's intent and waits for Android
network callbacks without issuing route checks or starting a native
owner. A running owner is handled as on ordinary network loss, with new
socket protection fenced to the current eligible network.

The VPN screen shows the system sign-in instruction and a distinct
message under lockdown. The app never opens a bypass socket or changes
Android lockdown. Unknown reachability without Android's captive flag is
not treated as a portal or as a restricted cellular mode. A real portal
and lockdown still need separate acceptance.

### Physical IP families

Open **Маршруты и диагностика** while connected to see the transport that carries
the VPN. For IPv4 and IPv6, the screen separately shows whether Android reported
a non-link-local unicast address and a default route on that physical link. A
private address counts. The result describes the selected link itself. Proving
that a remote service responds still requires a route check.

The controller derives these flags from existing Android network callbacks.
The local `status.physicalLink` field contains only the transport and four
booleans. VPN stop, service replacement or a different network epoch invalidates
the observation. An unavailable observation appears as pending. Reading this
view creates no network traffic and does not request location permission.

### Reading route measurements

The duration and hop list belong to the reported check. If a batch ends or
times out without a result for a route, its duration becomes unknown and its
previous path and check-plan results are cleared. A duration of zero means
that the current measurement completed within one millisecond. The route
screen labels failed attempts and historical paths separately from successful
checks. An exit-country mismatch identifies a failed country condition.

## Checking one route

In an active VPN, the route diagnostic screen offers a check on each supported row. The equivalent ADB command is `routes-check --route route-2`. The action applies to the displayed configuration, VPN session and physical network. If these change, refresh the list and select the route again.

For a managed adaptive route the scheduler queues the selected group. Repeated requests before the next eligible check coalesce. Other groups keep their deadlines and the usual capacity, cooldown and energy limits still apply. The button confirms submission. A route's status changes when the engine supplies measurement evidence. Retrieving cooldown details does not change the scheduler's clock.
