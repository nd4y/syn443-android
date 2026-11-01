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
