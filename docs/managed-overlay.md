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

At430283e34f5d3582acea52c8ca2ae1599f7a112a, the JVM/protocol/state suite and
Android Keystore/corruption/late-result cases passed Actions. All six vault cases
also passed API37 before an unrelated external Settings-navigation failure.
The complete API29/35 runs passed. These storage components do not establish
managed native activation, actual provider registration or physical acceptance.

## Native SDK ownership and registration evidence

The optional local `managed_namespace` material must end in the independently
derived `managed-netbird/<digest>` directory. The two owned path components and
key files cannot be symlinks; the preceding app-storage root is supplied locally
and may use Android's own system alias. A canonical, private, bounded ownership
manifest is reserved while the native identity lock is held. Existing SDK files
without that manifest are never adopted. The established SDK config must contain
valid WireGuard and SSH private keys matching its persisted public-key digest.
Missing, corrupted or changed keys fail before SDK construction, preventing the
SDK's automatic key generation from silently creating another Cloud peer.

Fresh offline SDK construction is followed by config sync, a directory sync and
an atomic initialized-manifest readback before SDK Start may contact management.
An interrupted offline construction can resume with the same valid keys. The
manifest is an ownership/key-continuity fence, not proof of Cloud registration.
The separate native proof additionally requires the current ready owner, both
management and signal connections and a valid assigned IP. It rechecks ownership
and authorization after the SDK recorder returns; Stop cannot publish a late proof.
Private-key files retain the SDK's app-private storage semantics; they are not
claimed to be nonexportable Keystore keys. Temporary Go/SDK key strings remain
subject to GC despite clearing owned byte buffers.

Generated-key, damaged-state, interruption, namespace, real pinned SDK offline
construction and owner-lifecycle tests are authored for Actions. This component
is not yet connected to the controller's credential/acknowledgment/retirement flow.
The assigned-NetBird guard and advertised capability remain unchanged until that
complete path and its affected physical tests pass.

The Android SDK-storage cleanup helper holds `engine-owner.lock` for the complete
operation and requires no live app-native process. It accepts only a derived
namespace, checks a closed ownership manifest and preflights a bounded tree before
deleting anything. A wrong key fingerprint, unknown SDK state, symlink or oversized
tree leaves the namespace pending. The ownership manifest is deleted last, so an
interrupted cleanup can retry the same namespace without adopting unclaimed keys.
Cancellation is rechecked between deletions. Sibling identities and the legacy
operator root are outside its selectable tree. Six additional required emulator
cases cover these paths and actual file-lock contention; their acceptance remains
pending. This helper still needs the controller's durable retirement integration.

## Durable login ownership and logout cleanup (acceptance pending)

Login recovery now carries a bounded list of managed namespace claims. A verified
worker must persist a claim before credentials or SDK side effects. Refresh and
reauthentication retain it; cancellation moves it into the retirement intent. The
device key cannot retire until all claimed SDK/cache erasures are acknowledged.
Older login intents without these fields decode with empty claims. Imported paths,
unprovisioned states, stale generations and more than16 claims are rejected.

The real logout worker now discovers these durable claims after a process restart,
waits for actual native exit, retires only their owned SDK directories and vault
keys/ciphertexts, verifies erasure and removes the operation metadata. It keeps the
login key and pending claim if an SDK manifest is unreadable. Repairing the same
ownership data permits the same retirement to resume; no alternate identity is
adopted. Server revocation tombstones keep their existing offline/retry semantics.

New core/Keystore/controller tests cover persistence, old-format compatibility,
lock contention, incomplete cleanup, late cancellation and resumed logout. Their
Actions acceptance is pending. Setup delivery/materialization/registration/ack and
the provider issuer still need integration before assigned NetBird is enabled.

## Consumption after reference refresh (acceptance pending)

The client cleanup request retains its original operation/reference/version and
DPoP body hash when the current verified assignment refreshes the reference or
security epoch for the same namespace. It still rejects another identity epoch,
service, device or key. Fetch continues requiring an exact current reference/version
and independently verified unexpired credential; consumption never returns a
secret. The server counterpart passed all8 jobs at5ab9cb4fc9bc90f367ef3a0d58e2f9373f2f9534,
Actions41409513759. The new client case awaits its next exact Actions acceptance.

Pending grant replacement has durable DISCARDING/DISCARDED states. Local erasure
removes only the old grant Keystore alias and ciphertext, preserves SDK state,
and retains the old operation through server acknowledgment. Only a different
signed reference/version for the same namespace/device key/login generation can
then reserve a new operation; confirmed registration cannot enter this flow.
Crash recovery can repeat erasure or acknowledgment without adopting SDK keys or
registering a known identity again. Full controller materialization remains open.

The worker ManagedOverlayProvisioner now composes stable reservation, addressed
fetch, signature-checked protected cache, ENROLLING-before-native, registration
receipt, local key/cipher erasure and independent consumption. Preparation can
reuse a completed SDK identity while consumption is offline; pending renewal
retries the old acknowledgment before fetching the new reference. Its caller must
persist the login namespace claim and fence the native proof by session/config.

OverlayRuntimeMaterial holds the optional setup value only in RAM, checks current
admission and conservative credential/policy deadlines, and localizes only the
exact signed config hash and closed metadata. Managed paths derive from the local
app root and authenticated namespace. The saved signed config/hash is unchanged;
inline setup keys, paths, foreign metadata and numeric coercion are rejected.
Completed identities render without setup keys. JVM/platform crypto and serialized
native JSON string copies remain GC-managed; retiring their process is still a
required controller integration step. No managed capability is advertised yet.
Seven new actual Android cases and two JVM cases are required in Actions; final
LoginController/host proof handoff and actual managed Cloud acceptance remain open.
