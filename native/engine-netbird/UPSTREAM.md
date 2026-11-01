# Embedded NetBird adapter

Derived from the GPL-3.0-or-later NekoBoxForAndroid libcore adapter, with SYN443
optional-start/recovery integration. Packet tests use documentation addresses.
The SDK source is pinned at cf017119711184a0661062a0c8ac2043e4e8d411 plus the exact
reviewed Android/direct-first/underlay patch supplied in native/patches/netbird.patch.
SDK license exceptions are retained in its source and must accompany distribution.
The bridge registers this module. Android build, fail-closed lifecycle and
physical internal-peer acceptance remain explicit gates in docs/m1-vpn.md.
