# SYN443 - Secure Your Network

Public development repository: **android**.

Android client with an embedded source-built engine, isolated native host, durable
VPN controller, dark Compose UI, route evidence, identity/provisioning pilot and
SQL support-chat client. Accepted USB Wi-Fi/OS behavior is recorded separately
from LTE, natural Doze, battery and long endurance, which remain unaccepted.

- [Android repository](https://github.com/nd4y/syn443-android)
- [Control plane and canonical contracts](https://github.com/nd4y/syn443-control-plane)
- [Technical specification v0.9](docs/spec/TECHNICAL_SPEC_RU.md):292 requirements,98 acceptance scenarios
- [Implementation and acceptance](docs/implementation-status.md), [roadmap](docs/ROADMAP.md)
- [Requirements register](docs/requirements-register.json), [test strategy](docs/TESTING.md)
- [Architecture/security review](docs/spec/ARCHITECTURE_REVIEW_RU.md), [public-data rules](docs/PUBLIC_DATA.md)

M1 remains partial; M2 and chat have scoped pilot implementations. Full M2-M5 and
version1.0/production readiness are not accepted. One Remnawave API resource and
NetBird belong to version1.0 scope; that scope statement is not delivery proof.
Multiple Remnawave, x-ui/3x-ui and Tailscale/ZeroTier are extension contracts only.

See [VPN](docs/m1-vpn.md), [route/lifecycle](docs/route-lifecycle.md),
[identity](docs/identity-lifecycle.md) and [chat](docs/support-chat.md).
Native source/toolchain/patch locks and third-party notices live under native/.
Copyright (c) 2026 SYN443 contributors. This distribution includes GPL-3.0-or-later components; see LICENSE and native/THIRD_PARTY.md. Third-party dependencies retain their own licenses.

All builds run in GitHub Actions. Local/private signing and physical acceptance
are separate from compilation. User/provider configuration, keys, phone backups,
raw diagnostics and private network identifiers never belong in this repository.
Do not run historical build recipes on the operator laptop or against production.
