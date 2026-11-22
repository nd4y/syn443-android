# Support chat pilot

The dark Android support screen uses the existing enrolled device session. Users
have one conversation per account; a live server-side chat grant enables the
administrator inbox. Chat operations are separate from VPN intent.

Messages and attachments are stored in control-plane PostgreSQL. The Android
outbox stores ciphertext in a no-backup SQLite database, with Keystore keys scoped
to the login generation. Each queued send keeps its message/upload IDs across
retries. Uploads use 256 KiB parts, SHA-256 verification and atomic publication;
the file limit is 25 MiB (shown as 25 MB), with up to four attachments per message.
Only visible chat polls the server. Leaving the screen cancels the current UI
operation; an unacknowledged send can be retried with the same ID.

Photo mode applies orientation, limits dimensions and writes a fresh JPEG without
source EXIF. Video mode uses pinned AndroidX Media3 1.11.1, H.264/AAC, up to 720p
and 30 fps, a duration-based bitrate budget and a checked final size. The long
edge is limited to 1280 pixels and the short edge to 720. Portrait and square
clips keep their display shape, and smaller clips keep their resolution within
encoder alignment limits. Original
file mode requires a file already within the size limit. Codec work uses bounded
private temporary files, which are deleted on completion/cancellation. Media3
is Apache-2.0 licensed; its modules are separate Gradle dependencies.

The controller exposes chat request/result/cancel only to its own UID. The debug
ADB interface cannot read conversation contents. Each part rechecks the current
account/session; cancellation and logout fence late results. DPoP signing and
HTTP request limits are increased explicitly only for chat calls; enrollment
keeps its original small bounds. No credentials cross Binder.

`contracts/v1/chat-openapi.json` is shared with the control plane. JVM tests cover
exact request proof binding and bounded replies. Android instrumentation adds
encrypted persistence/account fences, 25 MiB chunk integrity, local quotas/key
retirement, photo orientation/GPS removal, invalid media and the visible UI.
These tests are mandatory in the emulator evidence gate.

Android keeps the encrypted draft and file chunks until the send response
identifies the same conversation, client message, text and uploaded files.
It accepts either server attachment order. A missing or mismatched receipt
leaves the original client ID available for retry. Confirming delivery removes
the draft and its local chunks in one SQLite transaction.

The required Actions gate now contains 110 outcomes on each Android API and 80
identity JVM methods. It covers an interrupted session refresh with exact request
reuse, stale generation/boot rejection and a publisher requiring reauthentication.
The API37 virtual H264 decoder workaround preserves physical decoder ordering and
retains the same successful video export assertions.

A privately signed Actions APK passed 38 USB Xperia UI/storage/media checks.
Disposable SQL/Keycloak tests verified user/admin Android and web conversations,
25 MiB attachment hashes in both directions, role withdrawal and actual on-device
1080p-to-720p video compression. Reopening chat reuses one Activity; hidden chat
made no new authenticated requests during the observed interval. A natural access-token expiry during an API outage survived actual app process
death; the exact refresh operation resumed and the queued message was published
once without another login.

Cold VPN startup attributed its first timeout to DNS and recovered in 19 seconds;
crash, frozen-host and Wi-Fi return checks also recovered. This does not establish
zero transient failures or bounded recovery for every network. This is a draft
implementation, not production deployment. LTE, natural Doze, unplugged energy,
long endurance and the complete M1/M2 release gate have not been accepted.

## Report a problem

The phone home screen opens an incident preview. It shows the user intent,
corroborated VPN phase, counts of route check outcomes, a bounded fault category
and the active revision. Its last-known-good configuration and algorithm come
from the same authorized envelope that passed activation checks. The report has a short public
reference derived from the full idempotency key. Unknown and stale evidence
are shown explicitly. Hostnames, raw logs, addresses, account identifiers,
provider names, chat files and the diagnostic archive are excluded.

Confirming saves the displayed text in the generation-bound encrypted SQLite
outbox, even if the server is offline. Reopening the chat shows the reference.
On reconnection the authenticated self response supplies the destination.
An administrator viewing another conversation still queues their own report
to their own conversation. Delivery uses the normal SQL-backed message path
and checks the exact server receipt. The full diagnostic archive remains a
separate user action.
