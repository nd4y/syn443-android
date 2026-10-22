# Native engine sources

The embedded Go engine uses sing-box, sing-tun and their transitive dependencies.
The Android platform contract is derived from NekoBoxForAndroid/libcore and sing-box.
These components are GPL-3.0-or-later. Corresponding source, patches, pinned revisions
and upstream notices must accompany distribution; generated AARs are build outputs.
The native engine is loaded only in the application's private engine process.

NetBird is not implicitly supplied by upstream sing-box. Its adapter and patched
dependencies require a separate inventory and regression gate before being enabled.
