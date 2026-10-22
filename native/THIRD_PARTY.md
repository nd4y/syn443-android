# Native engine sources

The embedded Go engine uses sing-box, sing-tun and their transitive dependencies.
The Android platform contract is derived from NekoBoxForAndroid/libcore and sing-box.
These components are GPL-3.0-or-later. Corresponding source, patches, pinned revisions
and upstream notices must accompany distribution; generated AARs are build outputs.
The native engine is loaded only in the application's private engine process.

NetBird is a separate local Go module (`engine-netbird`), derived from the NekoBox
adapter. Its SDK and dependency forks are pinned in `engine-lock.json` and
`bridge/go.mod`; the source recipe applies the exact reviewed patch. The SDK's
BSD-3-Clause license has AGPL-3.0 directory exceptions, including relay sources.
Original SDK licenses are retained in app assets; upstream engine notice and all
patched corresponding source remain available. This inventory does not replace
the distribution/license review required for a production release.
