# Testing and release gates

Capability negotiation adds ten required JVM cases (identity minimum107), a
separately checked90% negotiation-core line gate and four required controller
cases on each API29/35/37 (emulator minimum183). See
[scope and lifecycle](capability-negotiation.md). Pending/transport outcomes must
retain the current assignment; old unknown enrollment bodies stay immutable.

The [NetBird diagnostic lifecycle](netbird-diagnostic-lifecycle.md) adds five
native/race cases for an SDK-independent local cache, bounded roster preparation,
no replacement of blocked workers, cancellation and late-result fencing. All
builds and application tests run in Actions. Source-level regression coverage
does not close the failed physical peer-health observation.
All automatable implemented behavior must run on pull requests and main in GitHub Actions.
- Documents: source hashes, 292 unique requirements, 98 unique sequential scenarios, traceability/evidence integrity.
- Contracts: strict schema validation, shared fixtures, unsupported fields/versions and bounded numeric inputs.
- Go: unit, property/permutation, fuzz seed/smoke, race detector, vet, coverage and HTTP boundary tests.
- Android: same fixtures on JVM, lifecycle/state tests, lint, APK build and connected instrumentation on emulator API 29, 35 and 37.
- Host lifecycle: eleven JVM methods, including concurrent requests and 10,000 deterministic randomized events; actual JUnit evidence is mandatory. Real process death/FD ownership still needs Android integration fault injection.
- Debug process harness: three actual Binder/process cases plus three UI cases are mandatory on every emulator API. Tests cover a remote worker, death, blocked-worker termination/rebind, a foreign session, dark rendering/contrast, safe insets and controls. They do not cover production native/TUN ownership.
- Cross-platform: identical fixture bytes and SHA lock; server/client expected route and explanation agree.
- Later: Postgres migrations/transaction races, job retries, provider fixtures, browser UI/API E2E, fault/load/security checks as components arrive.

Physical-only release gates: real restricted LTE, RF handover, vendor power management, measured idle energy, external-provider availability and long endurance.

Disposable AVDs use an explicit256MiB Java heap; API29 also selects the Pixel2
hardware profile and2048MiB RAM. The generic old16MiB heap caused system_server
to die in ConfigUpdateInstallReceiver during an automatic system update, before
the instrumentation suite could complete. A hardware/serial-gated preflight now
checks the actual maximum and growth limit before installing the app. This does
not change application limits, omit media/OS cases or substitute for physical
memory/battery acceptance. An interrupted run remains failed.
CI must list these as pending rather than skip them and report success.
Resource observations add ten JVM cases with a 90% line-coverage gate and two Android cases for the real proc source/cache/intent invariants and manual UI. See [measurement semantics and limits](resource-observation.md).
Coverage applies to implemented code; line coverage alone is not behavioral coverage.
All fixtures use synthetic endpoints, identifiers and secrets. No real provider credentials are needed in CI.
Every later feature PR updates requirements-register with scope and concrete evidence.

M1 recovery gates (REC-01-06 / AC82-AC90) remain partial; see [implemented paths and limits](m1-vpn.md). CI builds the native AAR from pinned source, checks ELF alignment/privacy, runs eight deterministic recovery tests and fifteen policy methods (including a Go-issued ES256 fixture). It requires 59 emulator outcomes across UI, TUN, two-hop proxies, optional startup, process faults and managed activation. Twelve external policy scenarios cover scoped delivery, changed-engine commit, validation/import locks, native failure/rollback, required regression, degraded baseline, Stop, interrupted apply, lease expiry, offline delivery signed management release and budget waits longer than activation timeout. Policy probes in this emulator harness use a visibly synthetic HTTP response; they do not prove production TLS or physical Internet reachability. NetBird adapter and SDK tests separately cover leases, cancellation, private-route failure, blocked snapshots, actual loopback VLESS, relay ordering and exclusive transport. Physical-only evidence must separately report RF handover, actual OS restart/Force stop/revoke/Always-on/lockdown, Doze, energy and endurance. Never equate a live process or short charging run with these gates.


Bounded health checks: `:core:health:check` and `check_test_evidence.py health` are mandatory in Actions. Loopback/JVM regressions (18 methods, 90% line-coverage gate) cover cancellation, slow responses, complete versus incomplete observations, strict response parsing and a saturated non-interruptible resolver pool. The existing three-API managed-policy instrumentation covers the real application caller. Production HTTPS and internal-service probes require separate physical Wi-Fi evidence; JVM/USB checks do not close LTE, natural Doze or battery gates.

M2 identity/enrollment pilot: see [scope and evidence](enrollment-pilot.md). Actions must run strict OIDC/DPoP crypto and schema tests, real temporary PostgreSQL role/transaction races, Keycloak code/key/refresh conformance, and the Android identity JVM suite with its 90% protocol-class line gate. These do not establish Android browser enrollment or physical policy activation. Raw operator identity/device evidence is never an upload payload.

APK runtime asset admission: only the decision example and exact checked-in license contents are allowed; test-only contracts/signature fixtures stay in JVM resources. Check the built ZIP member set and bytes, including extra/missing/altered/duplicate assets and empty instrumentation assets. The recursive payload secret scanner remains mandatory with unchanged exceptions.
Identity protocol/recovery: minimum 72 actual JVM methods, zero skipped; 90% class gates include AuthProtocol, IdentityOperation, IdentityScope, TrustedTime, LoginRecovery, LoginIntent, RegistrationTombstone and LoginPayload. Test scope/boot/time/service/key fences, exact persisted retry bodies, account-scoped cleanup capacity, protected-payload binding, acknowledged retirement, one nonce retry, session rotation without absolute lifetime extension and real signed-policy rejection. External-browser interaction, managed-policy handoff and physical enrollment remain separate gates.

Identity storage adds eight Android cases to the preceding44-case emulator gate (52 total on each API). Seven exercise actual protected AtomicFiles/Keystore with synthetic namespaces, and one proves cancellation/creation/deletion ordering under the Keystore lock. Require those exact method names, not only aggregate counts. Interruption between intent/ciphertext, cancellation before a late crypto commit, cross-generation/namespace/authority substitution, corruption, backup recovery and UI-thread rejection must fail closed. Existing app data and other Keystore aliases must remain untouched. These tests do not establish external-browser login or managed-policy activation.

Identity coverage evidence independently requires every critical class (including nested Scope/Companion classes) in the XML report and checks its actual LINE counters at90%. Missing/unmatched class patterns cannot silently pass. Boundary tests cover Java/VM name conversion, absent counters/classes and subthreshold/invalid/duplicate counts.

The registration-only controller adds seven required emulator methods, for59 outcomes on each API. Three use the actual provider/callback Activity; four use a debug emulator-only isolated controller with the real protected journal and Keystore plus synthetic RS256/ES256-checked issuer/API replies. They cover start/cancel/restart, callback rejection/single use, successful registration, exact retry after server commit/response loss, cancellation of a committed enrollment, owner cleanup, online revoke and cancellation with unreadable metadata. No external service is contacted or enrolled in CI. The UI explicitly keeps assigned-policy activation unavailable until its separate signed handoff is implemented; no automatic VPN Connect or unsigned fallback follows login.

Assigned-policy cache adds six required Android cases (65 per emulator API) and seven JVM methods. See [assigned-policy-handoff.md](assigned-policy-handoff.md). Require encrypted assignment erasure, scope/AAD checks, receipt gating, signed-key rejection and exact session-rotation retry. Native managed activation and refresh during VPN remain unaccepted.

The login controller reserves a pending-command ticket before executor admission. A deterministic Android case pauses that boundary, verifies busy/duplicate-start rejection, cancels before enqueue and proves that the next generation still starts. A second case covers queue rejection, discarded pending commands and a fresh login after cancellation. Emulator minimum: 67.
Identity physical transport adds two JVM cases (minimum 66) and five Android cases (minimum 72 on each API). The real TUN case distinguishes process traffic from a separately bound control socket; it does not exercise LTE or a public identity service. See [physical identity transport](physical-identity-transport.md).

Six runtime-lease/activation/record-compatibility cases raise the identity minimum to 72. They enforce exact conservative expiry, current login/receipt/activation scope, non-resurrection on renewal, late-result rollback and interrupted candidate rejection. AssignmentPermit is independently required to exceed 90% line coverage. Android native handoff is not accepted by these pure-core tests.

Two Android runtime-view cases require worker-only preparation, memory-only native reads, logout invalidation and refusal of an undeclared managed overlay. Cache/restart tests also verify the prepared view status. Emulator minimum for this stage: 74; full native handoff remains pending.

Four controller transaction cases require durable begin/commit, last-known-good rollback, stale activation rejection, interrupted candidate poisoning before recovery, and cancellation before executor admission. The encrypted journal remains the single activation authority. Emulator minimum: 78. These isolated controller tests do not authorize the real TUN after enrollment; native lifecycle integration remains a separate gate.

The [enrolled native VPN](enrolled-vpn.md) adds three controller cases for authenticated denial versus offline failure, retirement while the native owner lock is held, and safe rejection after a runtime view disappears or the journal becomes unreadable. Five external emulator cases run the real TLS/PKCE/DPoP controller flow and Go/TUN, including controller death, rollback, denial and frozen-host logout. The minimum is now 86 outcomes per API. A three-case OpenSSL fixture test verifies TLS trust, proof signature/method/replay, PKCE, key-bound policy and revoke. Fixture keys exist only in a temporary directory and are never uploaded. The test APK driver is not an external-browser UI acceptance result.

[Foreground provisioning retries](provisioning-retry.md) add five identity JVM methods (minimum77;22 required coverage classes) and two Android outcomes (minimum88 per API): a generation/cancellation admission race and first-policy202 followed by automatic receipt through the visible UI. No poll runs on a background timer or enables VPN.

[Health attribution](health-attribution.md) raises the required health JVM minimum to21. It tests frozen timeout stages, queued timeout and queued cancellation without mislabeling local capacity as a network failure. Cold-start physical attribution remains separate.

Support chat adds encrypted SQL, account fencing, 25 MiB chunks, real photo/video compression and cancellation checks. The minimum is 110 outcomes on every emulator API. API37 excludes only the crashing virtual `c2.goldfish.h264.decoder`; a mandatory selection test preserves the remaining codec order, and the same successful 1080p-to-720p H264/AAC compression assertions still run. Physical codec behavior requires separate device evidence. Test-fixture cleanup removes AtomicFile sidecars and preserves the original failure if cleanup also fails. A lost refresh response must resume its exact persisted operation through chat without a manual login or controller restart; a stale generation cannot admit that request. An obsolete boot or expired three-minute retry window still requires reauthentication before any chat request.

A publisher requiring a fresh authentication receipt must end provisioning with NEEDS_REAUTH. The TLS-authenticated API error409/reauthentication_required is distinct from an idempotency conflict; malformed JSON remains invalid. Identity minimum:80 actual JVM methods.


### Cancellable Android DNS (v23)

Health and activation checks use the current VPN DNS path through Android DnsResolver. Each query has a 2500ms deadline inside the 3000ms total check deadline; timeout, job cancellation and synchronous completion cancel the platform query. Numeric IPv4/IPv6 addresses bypass DNS. Four Android cases cover literals, positive/negative/empty callbacks, timeout and late callback, and three successive cancellations followed by a successful check in the same bounded worker pool. These cases run on API29/35/37 and a USB phone; the mandatory emulator minimum is 110. Incomplete checks retain distinct fixed outcome codes (cancelled, unavailable, deadline) and cannot become a successful baseline. No endpoint or exception text is recorded.


### System VPN revocation (v24)

The callback durably cancels intent and its OS marker, then posts retirement to main. The service remains alive for the bounded drain and records engineActive=false after confirmed owner exit; it does not call the default stopSelf implementation prematurely. A debug, emulator-only callback on a worker thread proves real native/TUN retirement, truthful durable Off across controller death and explicit reconnection. A second case freezes the old owner, revokes it, then submits a newer Connect while retirement is pending: the newer intent survives, and replacement waits for the old owner to exit. Both external cases are mandatory; each emulator minimum is110. They do not represent actual system permission removal: Android Settings Always-on/lockdown removal is also tested on a USB phone.


### Fatal engine failures and exit diagnostics (v25)

See [fatal recovery](fatal-recovery.md). Seven additional Android cases cover bounded/redacted exit metadata and visible on-demand UI. Four external cases require actual uncaught Java/Go faults, owner-death evidence, synthetic real-TUN recovery and persistent crash budgets/Stop precedence. All122 outcomes are mandatory on API29/35/37, retaining all prior110. Phone acceptance remains separate.

The test APK includes an independent UID/TUN fixture restricted to documentation-network addresses. The real competing-owner case transfers Android VPN authorization, requires the original engine to drain with no retry fight across controller death, then explicitly reconnects. Emulator preauthorization is confined to a hardware-gated driver; physical phones use visible controls and the ordinary system VPN dialog. The fixture is absent from the client APK.

### Per-route evidence and OS lifecycle (v26)

See [route/lifecycle contract](route-lifecycle.md). Six recovery JVM methods, eight
Android metadata/UI cases and eight external actual-route/OS cases are mandatory.
Every API29/35/37 emulator requires138 passing outcomes, retaining the previous122.
Real package replacement, secure boot/unlock and ordinary Settings Always-on/
lockdown are exercised on disposable emulators. Physical credentials are never
changed to simulate locked boot. Xperia USB/Wi-Fi evidence remains separate.

Managed ongoing HTTPS health now follows every required HTTPS target from the
still-authorized signed policy for the actual running engine, including the
applying candidate. A missing/expired/wrong-engine managed view has no public
URL fallback. Pure checks cover multiple/optional/banner targets and bounds;
the actual controller test covers candidate, active and withdrawn views.
Unmanaged production and visibly synthetic emulator defaults stay explicit.
Native loopback tests additionally exercise the registered HTTP CONNECT and SOCKS5
clients, authenticated CONNECT, HTTP-over-SOCKS detour payloads, refused proxies
and bad authentication with a target counter proving no direct fallback. These
are not the complete VLESS/XHTTP/SSH/UDP interoperability matrix.

Diagnostic bind ownership: run41405230512 passed native/JVM and API29/37 but
API35 failed the existing wedgedWorkerCanBeTerminatedAndRebound at its10-second
replacement-bind wait. All120 connected cases ran;119 passed, including the new
namespace/vault/controller cleanup cases. Missing callback is the proven failure;
its exact framework cause was not recorded. The new harness waits for both Binder
death and the framework disconnect within the existing5-second total death bound,
uses a session-specific bind action and reports null/dead binding callbacks.
A real rejected-interface unbind regression requires an owned response afterward;
a stale/foreign unbind cannot kill the current debug session. Existing10-second
bind and5-second response limits, actual worker hang/death/rebound and foreign
message rejection remain. No rerun/skip or production-supervisor shortcut is used.
The new case is mandatory by exact method name; minimum160 Android outcomes.

Grant renewal requires two identity JVM cases and one actual Keystore Android
case (minimum94 identity,166 outcomes per API). They check durable old-operation
retention, exact same-identity replacement, new addressed reference, denial before
erasure/server acknowledgment, revoked local admission, stale operations, expiry,
main-thread rejection and byte-preserved SDK files. Confirmed registration never
uses grant renewal to silently enroll again. Compiled acceptance is pending.

Five additional Android cases require the real vault-to-provisioner flow and
RAM-only config localization: stable operation before fetch, independent signature,
no repeated fetch after restart, erasure before consumption, lost ACK retry,
keyless offline preparation, stale/cancelled proof rejection, local namespace/path
bounds, unchanged signed config/hash, coerced metadata and closed/expired material.
They use synthetic keys and do not claim actual native registration proof or the
controller/host process handoff. Those integration tests remain required.

Managed controller/host handoff adds five required Android cases (minimum171)
and one legacy capability migration JVM case (minimum95). Tests use actual bound
signatures, LoginJournal/OverlayVault and Keystore to prove namespace claim before
fetch, encrypted restart without refetch, private proof session fencing, erasure
before consumption, lost ACK/keyless offline recovery, late fetch logout and
signed wrong-address rejection with exact-operation retry. Native proof input is
injected only in these isolated controller cases; actual Cloud registration and
one-time process retirement after candidate commit require separate acceptance.

The active and candidate configuration can share an SDK namespace while naming
different pending grants. A current native owner finishes registration first;
without an owner the candidate is prepared first. Other pending references cannot
alternately discard one another. After durable registration both configurations
prepare the same keyless identity. An explicit controller case checks no second
fetch/consumption while the active proof is pending, and immediate candidate
preparation after that proof. Launch credential expiry and active policy expiry
are checked separately.

The first full managed controller source7a87a2b compiled and passed identity95,
but all three emulator APIs rejected its new signed policy before grant dispatch:
the low-level Kotlin Policy.capabilities still lacked overlay.credentials.v1.
The fix adds only that independently protected module discriminator and a required
real ES256 signature/key/device/expiry/unknown-feature/duplicate-capability JVM
case (policy minimum16). It does not relax signature, namespace, runtime material
or activation guards. Exact corrected Actions acceptance remains pending.
