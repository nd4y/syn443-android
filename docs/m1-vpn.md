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
direct, HTTP, SOCKS, VLESS/XHTTP, SSH, selector and URL-test outbounds. The adapter
injects its sole TUN and DNS interception. This is a development import format,
not signed managed provisioning. The production readiness check requires an
actual HTTPS 204 response through the TUN. Engine liveness alone never means Online.

The debug-only shell API uses `content://io.syn443.control` with `status`,
`connect`, `disconnect`, `resume`, `import` (base64 JSON), and bounded `logs`.
Only the same UID or ADB shell may call it; the exported debug provider additionally
requires DUMP. Release builds do not export it. Debug `fault-crash` and `fault-hang`
target only a verified owned native PID. A fixed synthetic HTTP readiness mode is
available to hermetic emulator tests and visibly marked in the UI.

## Evidence and limits

- Six deterministic recovery-model tests cover Stop, retry/budget bounds and time changes.
- Four emulator cases exercise real TUN/Go/HTTP CONNECT traffic, crash recovery,
  full native SIGSTOP recovery, Stop precedence and activity closure. They must
  actually pass on every configured API; compilation is not acceptance.
- Physical acceptance uses a separate private operator driver. Real credentials,
  device identifiers, screenshots, raw logs and signing keys never enter CI.
- Initial physical HTTPS connectivity and native crash/hang recovery have been
  observed on Android 14 and Android 17. This is bounded evidence, not endurance
  or energy acceptance.

M1 remains **partial**. NetBird, optional private-route startup/failure isolation,
signed policy/offline rollback, full per-route status, exhaustive OS lifecycle,
restricted cellular handover and measured energy gates remain open. Importing
unsupported overlay configuration is rejected, never silently removed. The full
control panel remains gated on these checks. Do not use the development APK as
a claim of complete provisioning, traffic-leak protection or production readiness.
