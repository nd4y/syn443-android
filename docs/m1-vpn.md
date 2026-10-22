# M1 VPN implementation checkpoint

The debug APK now embeds a source-built Go sing-box engine. `TunnelService` in
`:controller` owns the original TUN descriptor, physical `Network` binding,
durable intent and watchdog. `EngineHostService` in `:engine` receives a duplicate
descriptor and loads the engine. The UI never loads Go. Source pins, local patches
and licenses live in `native/`; CI builds both arm64 and x86_64 with 16 KiB ELF alignment.

Connect/Stop commands first persist desired state and generation in an atomic
file. Imported engine configuration is encrypted with an Android Keystore key.
Stop invalidates late callbacks and pending starts. The JVM recovery model bounds
exponential backoff, jitter, network opportunities and heavy restarts; stable
progress is required before clearing failure history. Binder death and a native
progress timeout retire the old process before another identity owner starts.

The current engine configuration accepts `outbounds`, `dns` and `route` with
direct, HTTP, SOCKS, VLESS/XHTTP, SSH, selector, URL-test and a single NetBird outbound. The adapter
injects its sole TUN and DNS interception. This is a development import format,
not signed managed provisioning. The production readiness check requires an
actual HTTPS 204 response through the TUN. Engine liveness alone never means Online.

The debug-only shell API uses `content://io.syn443.control` with `status`,
`connect`, `disconnect`, `resume`, `import` (base64 JSON), and bounded `logs`.
For real credentials, use debug shell `import-file`: create the fixed private
`no_backup/operator-import.json` with `run-as io.syn443.android touch`, set mode
600 with `run-as ... chmod`, then pipe JSON through `adb shell -T run-as
io.syn443.android dd of=no_backup/operator-import.json`. Verify its SHA-256 before
calling `import-file` without arguments. The fixed private staging file is bounded
and removed after reading. Base64 shell arguments are for synthetic fixtures only.
Only the same UID or ADB shell may call the provider; the exported debug provider additionally
requires DUMP. Release builds do not export it. Debug `fault-crash` and `fault-hang`
target only a verified owned native PID. A fixed synthetic HTTP readiness mode is
available to hermetic emulator tests and visibly marked in the UI.

## Evidence and limits

- Seven deterministic recovery-model tests cover Stop, retry/budget bounds and time changes.
- Eight native instrumentation cases and seven external-driver cases exercise real TUN/Go/HTTP CONNECT traffic, crash recovery,
  full native SIGSTOP recovery, Stop precedence, Wi-Fi loss and actual UI/controller process death. They must
  actually pass on every configured API; compilation is not acceptance.
- Physical acceptance uses a separate private operator driver. Real credentials,
  device identifiers, screenshots, raw logs and signing keys never enter CI.
- Initial physical HTTPS connectivity and native crash/hang recovery have been
  observed on Android 14 and Android 17. This is bounded evidence, not endurance
  or energy acceptance.

Independent emulator scenarios reset their synthetic checkpoint only while Off and
after native ownership is released. This reset is debug/emulator-only; physical
devices and release builds reject it. Budgets are never reset inside a scenario.
The external controller-death case exhausts the persisted three-restart window
and proves that another controller restart cannot launch a fourth native owner.
Process-loss injection currently uses SIGKILL and full-process suspension uses
SIGSTOP. Fatal JNI/Go signals and Android crash-loop suppression remain separate
unverified OS gates.

Default DNS uses Android's raw resolver bound explicitly to the selected physical
Network. It never retains a Wi-Fi DNS server across a network change. Requests
have a two-query concurrency bound, three-second cancellation deadline and
session/network fencing; native tests reject cancelled, malformed and mismatched
replies. Explicit configured UDP/TCP/TLS/HTTPS DNS transports remain separate.

## Optional NetBird module

NetBird starts asynchronously after global engine construction. A missing setup
key or failed enrollment cannot hold startup of other outbounds. Private routes
remain attached to NetBird and fail closed while it is unready. One identity is
allowed per process; identity files live only under an app-owned no-backup path,
regardless of imported `state_directory`. Setup configuration is Keystore-encrypted;
SDK identity files currently rely on Android app sandbox/file encryption, not an
additional application encryption layer. These files must not enter diagnostics.

Normal mode is `connection_mode: direct`: protected sockets, physical DNS and
physical interface discovery avoid routing the underlay back into the TUN. Direct
P2P is attempted before per-peer relay fallback. `connection_mode: vless` requires
a separate VLESS-only detour; it cannot fall back to direct sockets. A failed start
has bounded cleanup, a persisted jittered retry deadline and an exclusive SDK lease.
Unconfirmed teardown requires action rather than starting another identity owner.
The global native watchdog remains responsible for a frozen process.

Cached status and peer roster travel through the existing session/generation
fence, stay in controller RAM and are excluded from durable logs. UI status shows
the actual mode and selected proxy. It distinguishes a started SDK, Cloud/signal
state and peer state from data-path proof. Manual peer diagnostics use at most four
workers and a two-minute job deadline; they do not run on the heartbeat loop.
UI exposes cache freshness; a stale sample cannot establish connectivity.

The M1 [signed policy coordinator](managed-policy.md) adds authenticated scoped
delivery, encrypted activation journal, baseline/candidate checks and offline
rollback. Full policy enrollment/rotation/publication is a later gate. Physical
Wi-Fi-only NetBird/internal TCP and ICMP recovery has bounded operator evidence;
it does not cover cellular, endurance or energy.

M1 remains **partial**. Full per-route status, exhaustive OS lifecycle,
restricted cellular handover and measured energy gates remain open. Importing
unsupported overlay configuration is rejected, never silently removed. The full
control panel remains gated on these checks. Do not use the development APK as
a claim of complete provisioning, traffic-leak protection or production readiness.
