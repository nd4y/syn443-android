# Managed overlay identity boundary

The server and Android core now derive the same isolated NetBird state namespace
from authenticated service, owner tag and device plus the signed overlay,
provider resource, provider network/tenant, management origin and identity epoch.
The network ID does not mean Wi-Fi/LTE, a peer or a group. Configuration revision,
outbound tag, direct/VLESS mode, transient setup-key reference and signing-root
rotation do not change this identity. A deliberate identity epoch or authority
change does. Seven shared public vectors check cross-language agreement.

The managed root is distinct from the existing operator NetBird state directory.
The helper has no file, network, SDK, secret-delivery, signing or retirement
authority. It does not enable a managed outbound. Android continues rejecting
assigned NetBird configurations until addressed secret delivery, protected local
storage, native ownership/retirement and rollback are integrated and accepted.
Tailscale/ZeroTier remain unimplemented extension contracts.

Before activation the client must derive account/device binding from its verified
login/session, compare the signed overlay resource/network and obtain only that
identity's addressed credential. It must durably record enrollment before effects,
erase the setup secret after acknowledged enrollment, reuse the same SDK keys on
network/config changes and never substitute an operator identity. Logout/revoke
must withdraw permits first, wait for confirmed native owner release, then retire
only the owned managed identity; a permitted rollback retains the old identity.
These remaining paths require independent API/native/physical tests.

The Android cryptographic consumer verifies the separate credential signature,
closed canonical payload and every addressed field before exposing a setup value.
It uses both conservative clock bounds: not-before must be reached by the lower
bound, and expiry/offline lease must remain valid beyond the upper bound. A
borrowed byte buffer is zeroed on success/failure; closing the owner never waits
for a blocked borrower. Immutable JSON/crypto strings remain subject to JVM GC.
The core does not fetch or persist a secret and does not enable assigned NetBird;
protected delivery/cache, acknowledgment and native retirement remain pending.
The shared overlay-credential schema is byte-identical in both repositories.

## Android delivery journal and per-grant vault (acceptance pending)

The client protocol now has bounded addressed fetch/consume operations with fresh
session DPoP and independent credential verification. It is not advertised as a
managed capability yet. `OverlayAssignments` resolves the closed signed metadata
against authenticated local service/account/device/key state. It cannot grant
permission by itself.

`OverlayEnrollments` defines reserved, cached, enrolling, registered, erasing,
erased, acknowledged and retiring/retired states. It persists one stable operation
before requests and native effects. A pending operation cannot switch recipient,
reference or epoch; a confirmed SDK identity keeps its namespace across transport
and lease changes. Registration evidence precedes local credential erasure, which
precedes consumption acknowledgment. Phase flags alone are not SDK evidence.

The controller-process `OverlayVault` adds an independently keyed AES-GCM Keystore
cache in no-backup storage, exact ciphertext/record readback and generation CAS.
The operation is durable before encrypted cache writes, so an interrupted cache
commit retries its original operation. Missing keys, malformed journals or cipher
tampering fail closed and cannot silently reset enrollment. Late crypto is fenced
again before persistence/borrowing and against the current trusted upper deadline.
Cancellation only writes a bounded retirement fence; crypto/native cleanup runs
off the UI/Binder threads. Confirmed native ownership release is required before
retirement finishes. The vault cannot select or delete an operator SDK directory.

New JVM/protocol/state tests and Android Keystore/corruption/late-result tests are
authored and awaiting Actions. No native managed activation, actual provider
registration or physical acceptance is implied by these storage components.
