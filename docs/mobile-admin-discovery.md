# Current signed administrative discovery admission

This source slice connects the administrative OAuth core to a typed, current
signed service snapshot. It adds no Android controller, key/journal, browser
callback routing, native quick screen, API action, live descriptor publication or
account permission. Source preparation and synthetic tests are not physical
administrative login acceptance. All executable tests/builds remain Actions-only.

`BootstrapTrust.adminDiscovery(raw, anchor, currentFloor, expectedDeviceBootstrap,
nowSeconds)` is a read-only verifier. It requires a nonzero committed floor,
re-verifies the existing offline signature/descriptor validity, and requires the
returned floor to equal the supplied committed floor exactly. It cannot accept a
newer descriptor by implicitly advancing that floor. The complete ordinary
`Bootstrap` projection must equal an owned copy of the expected device bootstrap,
including roots and existing origin/TLS fields. Absent metadata and invalid,
expired, mismatched or uncommitted inputs return no ticket. Fatal errors are not
silently converted into absence.

`AdminDiscovery` is an opaque, non-data class with a core-internal constructor.
Its public values are immutable `metadata` and a canonical SHA-256 rawurl
`binding`; descriptor validity remains core-internal. It has no copy/serialization
or restoration API. The domain-separated binding covers the full current anchor,
committed service/revision/hash floor and unchanged device bootstrap authority.
The descriptor floor already binds the complete administrative metadata and its
validity. Changing only the administrative revision therefore invalidates this
ticket without changing device `Bootstrap` or its authority/schema/journal.

The store adapter must call this verifier under one existing trust-store lock,
using the same current anchor, committed service floor, retained signed manifest,
expected device projection and current anchored time. It must return a freshly
checked ticket for each source callback, not capture a ticket indefinitely.
Caller-supplied or separately read values do not establish that atomic snapshot.
The ticket describes current trust metadata and grants no user role/session.

Plain `AdminIdentity` and `AdminProtocol` construction is now core-internal.
The public entry is `AdminProtocol.fromDiscovery(source, key, exchange, boot,
elapsed)`. The source and all protocol calls belong on the future identity
background worker: cache reads, signature validation and HTTP do not belong on
the Android main thread. The factory captures an initial typed ticket and checks
current binding, complete metadata and validity before operations, immediately
before POST after DPoP signing, after HTTP and after JWT validation. Removed,
replaced or expired trust produces finite `REAUTHENTICATE`, without a device
bootstrap/browser-origin fallback.

A guarded browser authorization or credential operation requires that factory's
own successful issuer discovery and full descriptor coverage of the trusted
HTTPS Date/BOOT window. Anonymous GET discovery can obtain the first clock from
the current store-verified snapshot. Rediscovery preserves an explicitly supplied
floor and the last successful same-BOOT clock; rollback/invalid replies cannot
discard it. Completed clock publication also retains a newer same-BOOT floor
when discovery calls overlap. Its small RAM lock performs no I/O or source
callback. A new factory/authentication or BOOT can obtain a new clock, but old
pending/session BOOT, one-use ownership and original session expiry remain
binding. A cancelled discovery does not publish its newly parsed clock before
the enclosing scope's final cancellation check.

Refresh still has one dispatch owner and no blind replay after uncertain
delivery, including trust changes during its response. Its local eight-hour cap
does not override descriptor expiry. Logout skips current discovery/expiry
requirements so revoked or expired administrative trust can always retire the
same local session family. It performs no network call, server revocation,
browser logout or VPN identity mutation. A future Android generation fence and
encrypted journal remain necessary around actual UI launch and durable recovery.

`AdminDiscoveryTest` adds generated offline signatures and real core protocol
calls with synthetic HTTPS/JWT replies. Eleven named methods cover exact committed
floor/full projection/root binding, metadata-only revisions, invalid/absent trust,
pre-discovery authorization, cancellation, signing/in-flight/post-JWT changes,
whole-window expiry, retained clock floors, old-BOOT owners and redaction. The
existing23 administrative OAuth roots remain mandatory and unchanged. New
handwritten admission classes are included in the existing90% class line gate;
Actions must independently require these new actual outcomes before acceptance.
