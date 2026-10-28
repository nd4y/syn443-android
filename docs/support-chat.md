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
and 30 fps, a duration-based bitrate budget and a checked final size. Original
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
