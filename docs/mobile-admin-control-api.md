# Typed read-only native administrative API

This source slice adds three administrative reads on the guarded
`AdminProtocol`: `listDevices(after, session, scope)`,
`deviceConfiguration(id, session, scope)` and `deviceRuntime(id, session, scope)`.
It adds no Android screen, controller mailbox, key/journal restoration, user
search, draft edit, publication, rollback or configuration mutation. Executable
tests and builds belong in Actions; injected protocol outcomes are not live
Keycloak/ACL/gateway or physical native-admin acceptance.

Every call targets exactly the signed `AdminBootstrap.apiOrigin` plus
`/v1/control/action`. There is no arbitrary public action/body/URL method,
browser-origin fallback or device-token promotion. The closed version1 request
has a fresh43-character request ID, one fixed action and a closed payload:
`after` for `configuration.devices.list`, or `id` for
`configuration.inventory.get` / `configuration.runtime.get`. IDs follow the
server's ASCII1..64 object-ID contract. Requests are POST `application/json`,
with DPoP Authorization, ES256 proof, access-token `ath`, exact UTF-8 request-body
`req_hash` and a fresh `jti`. No Origin header or control-API nonce retry is used.
Successful server replies are direct response objects, not result envelopes.

The API requires nonnull typed discovery admission, a verified administrative
session with the same authority/key/BOOT, an unconsumed live family and a live
access token. A still-live refresh token does not authorize a read after access
expiry. Current trust, key, clock, family and expiry are checked after signing
immediately before HTTP, after HTTP and after parsing. Cancellation before
signing sends nothing; cancellation or logout during a read publishes no result.
Reads never consume or rotate refresh ownership and never start hidden refresh
or retry. HTTP401 returns finite reauthentication,403 access denied and5xx
transport failure. Error text/nonce challenges do not create another request.

HTTPS Date is observed against the session and latest admitted clock floor.
After validated parsing and the final cancellation check, the existing private
admission clock records a conservative merged window. New Date evidence can
reject an access token, including before a later request, but cannot extend its
fixed access/session deadlines. These domain reads may create the server's
normal scoped audit/replay records; they do not change configuration authority.

Reply limits are32,768 bytes for pages,4096 for runtime and524,288 for a
configuration. They are bounded before UTF-8 decoding. The existing strict
Canonical parser's byte, depth24, object64 and array128 limits remain unchanged
for pages, runtime, OAuth and signed documents. Configuration replies use an
isolated strict reader with the same524,288-byte, depth24, Unicode and safe
integer rules, at most512 members per object and512 items per array. Only the
exact root path `effective.fields` permits4096 members: the server expands up
to4096 leaf origins there, independently of its512 aggregate change limit.
Nested or differently placed objects named `fields` retain the512-member bound.
Duplicate/null/mistyped/unknown outer fields, malformed pagination, mismatched
device identity, revision/time inconsistencies and oversize bodies fail closed
rather than yielding truncated results. Pages contain at most32 strictly sorted
unique IDs above the supplied cursor; a nonempty continuation must be the final
ID of a full page. The returned list is an unmodifiable owned copy.

Configuration exposes a small read-only metadata projection. Its complete
accepted original JSON is retained, including nested layer/effective/issued
fields. Those nested documents are not recompiled or claimed fully validated by
this reader; full editor/schema/permission enforcement remains future work.
Activation `reported`/`historical` values are publication observations, not
current connectivity. Runtime `none`/`recent`/`stale` validates the server's
sample/receipt freshness rule and finite client report, not independent traffic
or live-TUN proof. Historical activation revisions need not equal current issued
policy; only the server's `reported` state requires equality.

All three result DTOs have explicit bounded `wireJson()` access to their complete
validated original UTF-8 response for the authorized private UI handoff.
Their `toString` values, including nested summaries/reports, are redacted. This
data must not enter global status, logs, intents or public files. The Android
same-UID mailbox and its ByteArray Binder boundary are integrated in v86 source
but await Actions and physical/live acceptance. The core getter itself is not
an Android UID check or an export permission.

`AdminControlTest` adds13 required synthetic JVM methods with generated offline
discovery signatures, actual signed JWTs and cryptographically checked ES256
DPoP transcripts. They cover all three actions, body/token/key binding, request
freshness, pagination, complete UTF-8 handoff, runtime/history semantics, access
versus refresh expiry, source/key/BOOT/clock ownership, cancellation/logout,
finite no-retry failures and byte/parser limits. The configuration cases retain
complete Go-shaped129/256-change inventories and4096 origin records through the
authenticated protocol, reject4097 origins, and exercise exact path, tree, UTF-8,
Unicode, integer and duplicate-key boundaries without relaxing other readers.
Handwritten classes, including `AdminControlJson` and `AdminControlJson.Reader`, join the
existing90% class line gate. Exact actual outcome and independent coverage gates
must be retained in Actions before acceptance.
