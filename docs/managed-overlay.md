# Managed overlay identity and credentials

The completion branch adds the addressed grant, protected vault, SDK ownership
and controller/native handoff below. This remains partial M2/M3 work: exact final
Actions, real managed provider enrollment and physical acceptance are required.
It does not adopt the operator NetBird identity or activate future providers.

## Identity and authority

The namespace is the shared canonical SHA256 derivation from authenticated
service/account/device and signed overlay/provider/resource/network/identity epoch
plus normalized management origin. Its separate managed-netbird root cannot alias
legacy operator netbird state. Outbound renaming, config revisions, direct/VLESS
selection and Wi-Fi changes do not rename that identity. The shared Go/Kotlin
vectors cover canonical origins and authority separation. Tailscale and ZeroTier
remain rejected extension contracts.

A signed policy carries closed managed metadata and the required capability
`overlay.credentials.v1`; it contains no setup key or local state path. Local
identity, device key, scope, independent policy signature and conservative lease
are prerequisites. Metadata cannot authorize itself. New enrollment/invitation
requests advertise the module; immutable older three-capability retry bodies stay
unchanged. Updating capabilities of an already registered server device remains
separate work and cannot be inferred from the new factory.

## Worker preparation and protected grants

LoginController derives the binding from its current verified assignment and
persists its bounded namespace claim before grant requests or SDK effects. One
stable operation is persisted before fetch. AuthProtocol uses the bound session,
fresh DPoP proof/body hash and independent addressed ES256 envelope verification.
The envelope binds service/account/device/resource/network/identity epoch, device
key, reference/version, security epoch, kind and a short conservative expiry.

OverlayVault uses an independent nonexportable Android Keystore AES-GCM key per
grant, noBackup AtomicFiles, bound AAD, CAS/readback, bounded closed metadata and
worker-only crypto. Late time/cancel/generation results, missing keys, corruption,
foreign paths and orphan ciphertext fail closed. Authorization/time callbacks use
immutable or volatile views; they never acquire UI/controller locks or do I/O.
No setup value enters the login intent, signed config, logs or public snapshots.

ManagedOverlayProvisioner composes RESERVED, protected CACHED and ENROLLING before
native effects. OverlayRuntimeMaterial owns the optional setup bytes only in RAM,
checks the exact signed config hash, current admission, credential and policy
expiry and localizes closed metadata into a locally derived SDK directory. Inline
keys/paths, another binding and numeric coercion are rejected. Local rendering
does not change the saved signed config or its content hash. A missing/expired
launch value waits for credentials without spending a native crash-restart budget.

An expired or superseded unconfirmed grant enters durable DISCARDING/DISCARDED.
Only its grant alias/ciphertext are erased; SDK keys are untouched. The old
operation remains until the server acknowledges irreversible consumption. SQL can
atomically abandon a never-dispatched issued grant; late fetch is permanently
denied. A different signed reference/version for the same namespace/device key
and login generation can then reserve a new operation. Confirmed registration
cannot take this path to silently re-enroll a revoked peer.

## Native registration and removal of setup material

The native SDK directory has a bounded closed ownership manifest and sealed
public-key evidence. Existing SDK files without a valid matching manifest are
never adopted. Missing, corrupt or changed established keys are rejected before
SDK.New can regenerate them. Ownership is reserved under the native lock before
SDK creation; initial keys and manifest are synced/read back before SDK.Start.
Offline pinned SDK tests cover key continuity, not actual provider registration.

The private native proof additionally requires the current owner, connected
management and signal, and a valid assigned IP; it rechecks ownership/lease after
SDK snapshot work. EngineHostService samples it on at most one disposable worker,
away from Stop/lease/control. Only a first-enrollment host with setup material
samples it. The one-way private Binder callback is separate from UI telemetry.
The controller fences it by host session, recovery generation, signed config hash,
namespace, login authority and conservative policy time before/after persistence.

REGISTERED is durable before local alias/cipher erasure. ERASED can prepare a
keyless runtime while consumption is offline; the exact old operation retries on
later preparation, including current reference/epoch refresh for the same identity.
Consumption returns no setup value, never proves SDK registration and cannot erase
another delivery's operation. Current account/session/policy/capability/namespace
and final SQL commit remain mandatory.

The active native host can complete registration after setup expiry while its
policy remains authorized. A new launch still requires an unexpired setup value or
confirmed keyless identity. After registration and candidate activation commit,
the supervisor retires the native process once and restarts from the same SDK keys
without setup material. Stop and owner-release fences remain authoritative. The
controller drops serialized setup JSON immediately after Binder dispatch. JVM,
crypto/JSON and Go/SDK strings remain GC-managed until their owning process is
retired; byte-owner closure alone does not guarantee their zeroization.

## Logout and retirement

LoginRecovery keeps at most16 canonical namespace claims through refresh/restart
and turns them into durable retirement claims on cancellation. Runtime admission
and RAM material are withdrawn first. The worker waits for actual native exit and
holds the native owner lock throughout SDK cleanup. It preflights the entire owned
tree, never follows symlinks and deletes the manifest last for crash recovery.
It verifies grant key/cipher erasure and removes operation metadata before dropping
claims or deleting the device key. Unreadable ownership leaves retirement pending;
repair of the same ownership permits retry. Operator/sibling state is untouched.

## Evidence and remaining work

CP5ab9cb4fc9bc90f367ef3a0d58e2f9373f2f9534 / Actions41409513759 and
CP8f3bab71b91dbc09622e7c4910fe9a91a3ed0bdc / Actions41413333223 passed all8 jobs,
including actual PostgreSQL expired/refreshed, revoked and unsent grant cleanup,
exact-operation rejection, irreversible erasure, role and cancellation boundaries.
Android3477ebb6ef675b6800c7bb32959eabc72e3fc1c1 passed native/JVM and API29/37;
API35 stopped before tests when Maven artifact resolution failed. This is not an
API35 acceptance result. Android08927c3adc7df0206408d9cac39f07b26e0c2ad9 native/JVM
passed; its new Keystore/platform cases are still awaiting the complete matrix.

The current controller/host changes add five Android integration cases and one
capability migration JVM case, for95 identity methods and171 required emulator
outcomes. They use actual Keystore/journals/signatures with synthetic issuer/API
replies. Injecting a private proof in a controller test does not establish native
Cloud registration or actual process-key cleanup on the phone.

Remaining: exact final controller/host Actions and physical keyless rotation,
provider issuer/configuration publisher wiring, existing-device capability upgrade,
full configuration/administration and real managed Cloud/browser/QR/trust-rotation
acceptance. No new APK has been installed for this branch. Physical LTE, natural
Doze, unplugged energy/endurance and full autonomous routing remain separate open
M1/M4/M5 gates.

The active and candidate configuration can share an SDK namespace while naming
different pending grants. A current native owner finishes registration first;
without an owner the candidate is prepared first. Other pending references cannot
alternately discard one another. After durable registration both configurations
prepare the same keyless identity. An explicit controller case checks no second
fetch/consumption while the active proof is pending, and immediate candidate
preparation after that proof. Launch credential expiry and active policy expiry
are checked separately.

The first complete controller run7a87a2b passed native/JVM95/APK but failed all
three emulator matrices before grant dispatch: the lower-level Kotlin signed-policy
capability set had not yet admitted overlay.credentials.v1. The addressed wire
schema and Go verifier already allowed it. A focused signed-policy regression now
requires successful module admission while keeping wrong key/device/signature,
expiry, unknown features and duplicate capabilities rejected. The five original
controller cases remain mandatory and unchanged; the corrected exact matrix is
still pending.
