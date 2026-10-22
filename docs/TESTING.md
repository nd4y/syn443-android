# Testing and release gates
All automatable implemented behavior must run on pull requests and main in GitHub Actions.
- Documents: source hashes, 277 unique requirements, 90 unique sequential scenarios, traceability/evidence integrity.
- Contracts: strict schema validation, shared fixtures, unsupported fields/versions and bounded numeric inputs.
- Go: unit, property/permutation, fuzz seed/smoke, race detector, vet, coverage and HTTP boundary tests.
- Android: same fixtures on JVM, lifecycle/state tests, lint, APK build and connected instrumentation on emulator API 29, 35 and 37.
- Host lifecycle: eleven JVM methods, including concurrent requests and 10,000 deterministic randomized events; actual JUnit evidence is mandatory. Real process death/FD ownership still needs Android integration fault injection.
- Debug process harness: three actual Binder/process cases plus three UI cases are mandatory on every emulator API. Tests cover a remote worker, death, blocked-worker termination/rebind, a foreign session, dark rendering/contrast, safe insets and controls. They do not cover production native/TUN ownership.
- Cross-platform: identical fixture bytes and SHA lock; server/client expected route and explanation agree.
- Later: Postgres migrations/transaction races, job retries, provider fixtures, browser UI/API E2E, fault/load/security checks as components arrive.

Physical-only release gates: real restricted LTE, RF handover, vendor power management, measured idle energy, external-provider availability and long endurance.
CI must list these as pending rather than skip them and report success.
Coverage applies to implemented code; line coverage alone is not behavioral coverage.
All fixtures use synthetic endpoints, identifiers and secrets. No real provider credentials are needed in CI.
Every later feature PR updates requirements-register with scope and concrete evidence.

M1 recovery gates (REC-01-06 / AC82-AC90) remain partial; see [implemented paths and limits](m1-vpn.md). CI builds the native AAR from pinned source, checks ELF alignment/privacy, runs eight deterministic recovery tests and twelve policy methods (including a Go-issued ES256 fixture). It requires 38 emulator outcomes across UI, TUN, two-hop proxies, optional startup, process faults and managed activation. Twelve external policy scenarios cover scoped delivery, changed-engine commit, validation/import locks, native failure/rollback, required regression, degraded baseline, Stop, interrupted apply, lease expiry, offline delivery signed management release and budget waits longer than activation timeout. Policy probes in this emulator harness use a visibly synthetic HTTP response; they do not prove production TLS or physical Internet reachability. NetBird adapter and SDK tests separately cover leases, cancellation, private-route failure, blocked snapshots, actual loopback VLESS, relay ordering and exclusive transport. Physical-only evidence must separately report RF handover, actual OS restart/Force stop/revoke/Always-on/lockdown, Doze, energy and endurance. Never equate a live process or short charging run with these gates.
