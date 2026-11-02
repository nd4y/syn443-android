# Manual managed enrollment

Version0.9.0 adds syn443://enroll/v1, pasted links, QR images and full-resolution
camera capture. Incoming content is preview-only. The controller verifies the
signed service descriptor locally against installation-trust.json and stored
service floors, then shows service/origin before the user explicitly confirms.
No key, code or network request is sent by preview. QR content cannot install a
root, execute a command or publish an administrative setting. The image decoder
has16MiB/32-megapixel bounds and uses only content URIs selected by the user.
Temporary camera images stay in one private cache subdirectory and are removed
after decoding/cancellation. The Activity clears its incoming URI, excludes itself
from recents and protects its window; invitation strings redact their contents.

BootstrapTrustStore owns an AtomicFile/AES-GCM/no-backup journal with distinct
Keystore alias and namespace-bound AAD. It persists the service revision/hash
before enrollment, keeps floors across logout, accepts matching dual-root
transitions and blocks corrupted/unreadable state instead of reinstalling a root.
Public installation-trust.json currently pins an isolated test root. Its private
key is outside all repositories and Actions. Production root custody/recovery and
production deployment are separate release gates; this asset is not a general
public-service enrollment authority.

The existing LoginController single worker persists invitation intent, exact
claim/completion bodies and key alias before dispatch. IdentityScope cancels
network work; captured physical routes enforce network/generation freshness.
TLS server time is obtained without a code before claim. A claim is one-key and
one-use; it yields only pairing status. The native screen shows a pairing code
while a separately authorized administrator approves the exact key/version.
Polling is visible-UI only and uses the existing bounded provisioning backoff.

Completion is persisted before sending, so lost replies retry the same body and
request ID with a new proof. Only an independently published policy permits a
normal device session. Its ownerTag uses the same service/issuer/subject namespace
as OIDC. The client then uses the existing encrypted session, key-bound policy,
activation/rollback, chat and lifecycle paths. Old protected OIDC payloads with no
invitation field remain readable; the migration adds only an absent null variant.
Logout persists its generation/tombstone before network/key retirement and tries
to abandon only the captured claim/device. Unknown server results retain cleanup
metadata where a session might have been minted. Server-time maintenance expires
uncompleted reservations without widening the publisher's general session rights.

JVM tests cover protocol/key/body/time/owner/session binding, substitution,
clock/reboot behavior, pending/error/cancel mapping and shared login transitions.
New critical classes join the unchanged90% per-class identity line gate. Emulator
tests cover QR decoding, durable bootstrap floors/dual-root rotation/corruption,
and the actual controller/Keystore/journal with cryptographically checked
synthetic invitation/session replies, including cancellation during a held claim. Exact new Actions
results and physical Xperia USB/Wi-Fi enrollment/UI/recovery acceptance are pending.
This implementation is not evidence that all M2/M3 requirements are complete.

QR decoding uses the exact ZXing core3.5.4 artifact from Maven Central
(https://repo.maven.apache.org/maven2/com/google/zxing/core/3.5.4/).

The closed invitation-openapi.json contract is byte-identical to control plane.
Required test-name checks and independent JaCoCo class inventory prevent missing
invitation tests/classes from silently passing the unchanged coverage gates.
