# SYN443 - Secure Your Network
Public development repository: **Android application**. User configuration, keys and device diagnostics never belong here.

- Android: https://github.com/nd4y/syn443-android
- Control plane and canonical contracts: https://github.com/nd4y/syn443-control-plane
- [Technical specification v0.8](docs/spec/TECHNICAL_SPEC_RU.md)
- [Architecture/security/development review](docs/spec/ARCHITECTURE_REVIEW_RU.md)
- [Roadmap](docs/ROADMAP.md), [test strategy](docs/TESTING.md), [requirements register](docs/requirements-register.json)

The development APK now forwards real VPN traffic with an embedded engine and recovery controller. It is not production-ready; see the [partial M1 checkpoint and remaining gates](docs/m1-vpn.md).
All 277 requirements and 90 acceptance scenarios are retained. A documented scenario is not a passed test.
The first deliverable is a reproducible decision/lifecycle core, followed by a physical Android vertical prototype.
The control-plane repository owns versioned cross-platform schemas and synthetic conformance fixtures; Android vendors an immutable hash-locked snapshot.

One Remnawave API resource and NetBird are in version 1.0.
Multiple Remnawave resources, x-ui/3x-ui and Tailscale/ZeroTier are extension contracts only.
Copyright (c) 2026 SYN443 contributors. This Android distribution includes GPL-3.0-or-later components; see [LICENSE](LICENSE) and [native source notices](native/THIRD_PARTY.md). Third-party dependencies retain their own licenses.

## M0 prototype
See [implementation status](docs/M0_IMPLEMENTATION.md) for implemented paths and limitations.

Build the embedded engine first with Go 1.26.7 and Android NDK 27.3.13750724: `bash native/build_engine.sh` (set `ANDROID_NDK_HOME`). Then run `./gradlew :core:decision:test :core:host-lifecycle:check :core:recovery:test :app:lintDebug :app:assembleDebug`. `bash tools/run_emulator_tests.sh` runs instrumentation and the external process-death driver on a disposable emulator only.
The source recipe defaults to a conservative Go memory budget for shared builders;
CI overrides `GOMEMLIMIT=3GiB` on its dedicated runner for NetBird JNI generation.

See [CI delivery limitations](docs/CI_DELIVERY.md) for current artifact-quota and private branch-protection constraints.
