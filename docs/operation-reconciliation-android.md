# Android operation outcome reconciliation

This source candidate adds explicit recovery of a possibly sent administrator
mutation. It is pending exact-head Actions, coverage and live integration. The
currently installed accepted phone checkpoint is v89 with68 scoped USB/Wi-Fi
physical outcomes. That earlier checkpoint does not accept this implementation
or establish real native administrator SSO, server MFA/ACL or publication.

## Exact pending operation and explicit recovery

An encrypted pending envelope keeps its original actor, API origin, action,
request ID, version, exact UTF-8 body, body hash and replay metadata. The client
does not replace a version1 operation with version2 bytes. Fresh mutations
explicitly negotiate supported version; only the defined old unsupported-route
responses permit version1 behavior. Authentication, quota, transient, malformed
and nonce failures do not trigger automatic fallback or retry.

The native editor first offers **Узнать результат на сервере**. A matching
version2 `UNKNOWN` observation may arm **Зафиксировать отсутствие операции**.
Sealing requires a separate confirmation bound to the same current pending
operation, document and local CAS. Busy, changed or cancelled state cannot
reuse an old confirmation. Recomposition, back navigation, foreground return
and process recovery never schedule lookup, seal, retry, polling or publication.

Receipts distinguish:

- `UNKNOWN`: no safe conclusion; preserve the exact pending envelope.
- `NO_EFFECT`: the server's version2 atomic absence fence prevents a late
  execution of that exact operation. Only matching current ownership and CAS
  permit local resolution, followed by explicit current state readback.
- `RECORDED`: body-bound historical effect or queue metadata. Queued/running
  results remain pending without automatic polling. Historical `READY` and
  retained preview tickets do not create a fresh review or permit publication.
- `RECORDED_RESULT_UNAVAILABLE`: recorded references remain observations; the
  missing payload is not reconstructed or treated as absence. The UI retains
  local text and offers the full web panel.

Version1 absence stays unknown. Generic HTTP denials, transport failure, nonce
challenges, malformed replies and uncertain delivery never clear pending state
or become proof of no effect. Lookup and seal use a fixed current signed origin
and route, fresh DPoP including the exact outer request hash, and strict
actor/action/request/body/target/effect bindings. A receipt is neither an ACL,
MFA credential, activation report nor permission to publish.

## Deadlines and encrypted owner continuity

Fresh publication retains the original review binding and BOOTTIME deadline.
Admission and actual post-journal HTTP dispatch both enforce it. Expiry after
the pending envelope was committed preserves that envelope without dispatching
late or inventing an acknowledgement. A blocked transport retains its actual
worker ownership until exit; cancelling the caller does not free it early.

The stable `aV2` encrypted editor identity binds service, installation anchor,
ordinary device projection and complete administrative metadata. Signed lease
or floor updates can preserve this local storage owner while invalidating the
old live OAuth/discovery session as required. Current session, root, BOOT,
account and trusted-time checks still apply to every network operation.

Migration accepts only an active legacy owner matching the exact **currently
verified** legacy binding and current actor. It advances local CAS once while
retaining proposal bytes, pending bytes and the existing AES key. Unknown past
floors remain opaque; a stable hash cannot search old owners, restore expired
credentials or revive a session. Closed tombstones retain the existing explicit
new-create rules. This is not a device-key or VPN-identity migration.

## Mandatory source evidence

The exact root registry adds46 identity JVM outcomes:18 reconciliation codec,
seven authenticated protocol, three real loopback TLS, six version negotiation,
six actual Go conformance and six stable-authority cases. It adds29 Android
outcomes: three dispatch-deadline, ten encrypted coordinator, five UI, three
wire, three actual-route/fake-bridge and five encrypted owner-migration cases.
The required floors rise from200/398 to246 identity and427 on each
API29/35/37. No old required root, skip/failure rejection or API is removed.

Seven new production types join the same90% per-class gate:
`AdminOperationRequest`, `AdminOperationJob`, `AdminOperationReceipt`,
`AdminOperationReconcile`, `AdminOperationIntent`, `AdminOperationOutcome` and
`AdminOperationJobState`. Independent class-presence/coverage and exact
source-name self-tests prevent optional or substituted evidence.

The Go tests require the actual pinned producer source
`164347d5c387d05077f43dde07f677d2bc6de47a` to regenerate eight original
envelopes and36 outcomes during the same Actions invocation. The corpus lives
only in the owned direct child of `RUNNER_TEMP` with bounded regular-file and
source checks. It contains an ephemeral synthetic preview root and actual Go
wire values. It is not a committed test resource or an uploaded artifact;
diagnostics expose finite test results without retaining its signed payloads.

The dedicated HTTP route permits a512KiB request and1MiB reply, while the
original operation body remains at most262144 bytes and its canonical outer
proof body remains bounded. Ordinary token, identity and layer HTTP limits are
unchanged. TLS, framing, scoped route, cancellation and real-worker-retirement
tests use only owned loopback fixtures.

For any later physical selection, the deadline, coordinator and owner-migration
classes remain CI-only: they construct isolated authority/storage fixtures.
Only the eleven UI/wire/route cases are pure presentation fakes eligible for
later phone execution after release acceptance. They do not use a real
administrative account, Provider, browser SSO, server or VPN mutation.

Initial device assignment still uses the web panel. Real authenticated mobile
administration, live reconciliation/publication, complete operational behavior
and excluded LTE, energy and endurance gates remain open. This candidate
implements a bounded recovery path, not the full specification.
