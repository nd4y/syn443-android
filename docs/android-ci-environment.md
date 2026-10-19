# Android emulator CI environment
API 37 uses the exact package `android-37.0`, 4 GiB RAM, 8 GiB userdata and supported software graphics. API 29/35 retain their previously verified graphics options. Disposable runner disk cleanup removes only preinstalled .NET/GHC toolchains before the API 37 image is installed; an available-space guard remains mandatory.

SDK Command-line Tools 22.0 are pinned to archive build `15859902`. The setup action installs that archive into a versioned directory. `tools/prepare_android_tools.sh` verifies its revision and points the disposable runner's `cmdline-tools/latest` alias at it because emulator-runner prepends that alias to PATH. The previous alias is preserved on that runner.

Before boot, CI checks the AVD metadata target against the exact matrix API. Old tools silently create `target=android-0` for minor-version packages. In our initial API 37 diagnostic run, before SYN443 was installed, SurfaceFlinger repeatedly aborted in RegionSampling / mapper.ranchu with `hasReadColorBufferDma`; package/settings services disappeared when the framework restarted. See [upstream reproduction and SDK tools diagnosis](https://github.com/actions/runner-images/issues/14484). Boot completion alone is insufficient evidence of health.

The real connected instrumentation task and JUnit evidence gate remain mandatory on every matrix API. `tools/run_emulator_tests.sh` preserves the original exit status and collects bounded crash/service diagnostics even on failure. A bootstrap-only diagnostic workflow does not establish application compatibility.

References: [emulator RAM/version requirements](https://developer.android.com/studio/releases/emulator), [current software graphics modes](https://developer.android.com/studio/run/emulator-acceleration).

Compose UI testing 1.12.1 requests Espresso 3.5.0 transitively. We explicitly pin espresso-core 3.7.0 because the old reflective InputManager.getInstance initialization is incompatible with API 37; see [AndroidX Test issue2507](https://github.com/android/android-test/issues/2507). CI inventories both application and instrumentation dependencies. On failure, bounded JUnit/UTP reports are printed in the job log in addition to crash diagnostics, so an artifact quota outage does not hide the cause.
