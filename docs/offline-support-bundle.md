# Offline support archive candidate

This implements a local part of LOG-05/06 and ADB-02/04, with AC19/23 checks.
It does not implement remote diagnostic consent, upload, object download or
server audit from SEC-09/AC74. Source, Actions, resulting-main and Xperia
USB/Wi-Fi acceptance are separate. LTE and unplugged energy tests are excluded.

The user collects a sanitized archive, previews its composition and size, then
explicitly exports ZIP through Android's document picker. Collection never
starts probes, changes configuration or VPN intent, reconnects, clears the
event ring or uploads data. Export confirms a document write, not delivery to
support. The existing CLI `diagnostic-bundle` JSON snapshot stays compatible.

## Contents and privacy

There are nine fixed component names: versions.json, capabilities.json,
effective-config.json, health.json, events.jsonl, checks.json, overlay.json,
crashes.json and native-stacks.json. manifest.json lists every component with
state, a closed reason code, byte length and SHA-256 of actual included bytes.
The manifest does not hash itself. Metadata contains the full ZIP hash.

Only closed, typed scalar projections and counts may be collected. Labels,
targets, peer identities/IPs/FQDNs, URLs, subscription capabilities, raw crash
text, device/NetBird keys and identity files are excluded. Effective config
and native stacks are explicitly unavailable in this stage; no config is
decrypted for collection. `complete:false` also distinguishes projected,
missing, errored or truncated sources. Unknown fields cannot become false or
zero. Old cached checks keep their original time and unknown currentness.

The raw intent file is read without recovery or writes, capped at256KiB and
32 nested levels. Collection avoids ordinary status initialization and avoids
RouteSnapshot.view, whose read path can retire pending work. Context changes
between capture fences produce an explicit partial result without another
attempt. OS exit metadata is passive; API29 remains unsupported. Missing
sources never become successful empty observations.

Components are at most64KiB each and256KiB in total; manifest at most16KiB;
the ZIP at most512KiB. STORED entries have fixed names, CRCs and a fixed DOS
timestamp. A whole oversized component is omitted with an explicit error;
arbitrary byte truncation cannot create apparently valid JSON. No directory
crawl, arbitrary input path, imported archive or extraction is supported.

## Ownership and storage

One owner in `:controller` admits collection to a single worker. Cancellation
revokes publication and export immediately, while admission stays occupied
until the actual worker exits. A timer cannot release that slot. Status,
cancel and opening an export grant use RAM only. Reading admits one actual
bounded file/decrypt operation outside the state lock; status and cancellation
do not wait for it. The job, grant and deadlines are rechecked before returning
any bytes. Bounded bytes do not guarantee a wall-clock disk-I/O deadline.

Only AES-GCM ciphertext is persisted in the private no-backup subdirectory.
The random AES key exists only in the owning process; restart invalidates all
old artifacts and grants. There is at most one ready artifact and one temporary
file. Access lasts15minutes from the original monotonic creation time; an
object-scoped export grant lasts at most60seconds. Backward time fails closed.
Expiry is an access limit. Bounded encrypted residue is removed during the
next explicit collection, rather than by an autonomous deletion task. Cleanup
touches only validated owned filenames and never follows links or recurses.
The entire GCM tag is verified before any plaintext chunk is returned.

## Local protocol

ControlProvider keeps its existing own-UID access and DEBUG-only Android shell
UID2000 boundary. Bundle dispatch follows the unlock check but precedes login,
OS-intent, route and VPN initialization. No release ADB permission is added.

| Method | Argument | Result |
| --- | --- | --- |
| bundle-collect | none | collecting/busy with an opaque job ID |
| bundle-status | job ID | finite state and bounded ready metadata |
| bundle-cancel | job ID | revokes publication and export |
| bundle-open | ready job ID | short object-scoped export grant |
| bundle-read | grant:offset | at most32768 bytes as canonical Base64 |

IDs and grants are exactly32 lower-case hex characters. Read offsets are
nonnegative decimal integers without leading zeros. Manifest metadata stays
under16KiB; chunks stay well below Binder's transaction limit. Grants never
appear in UI, CLI output, filenames or logs. No retry recreates collection or
export authority after a lost acknowledgement.

The CLI provides `support-bundle-collect/status/cancel/export` and the
`support-bundle --output FILE` convenience path. Polling and download are
bounded. Before exclusively creating the output file, it verifies the whole
ZIP hash, exact names, sizes, framing, CRCs, manifest and component hashes.
It never extracts or executes entries, overwrites an existing file, stages
identity directories with run-as, or uploads the archive. Android buffers and
checks the complete archive digest before writing the selected document.

## Required evidence

Actions must execute the new archive, adversarial projection, source-fence,
worker/grant/encryption/cancellation, UI and CLI cases without dropping prior
outcomes or coverage gates. Physical acceptance separately collects while VPN
is running and offline, checks preview/cancel/export and verifies actual HTTPS,
TUN, configuration, identity, intent and device-setting preservation. An
unauthorized USB device cannot satisfy that gate.
