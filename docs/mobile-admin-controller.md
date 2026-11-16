# RAM-only native administrative controller

`AdminController` is a separate singleton in the existing `:controller` process.
Its public methods expose bounded status, a fresh browser handoff and one private
read-result mailbox. The integrated provider requires the application's own UID.
The private Activity and separate callback use that provider; neither instantiates
a trust store or the production controller in the UI process. This integrated
source does not prove a physical administrative login.

The controller owns one bounded coordinator worker/queue and one lifetime
`BoundedHttp` transport. It has no timer, polling loop, implicit retries or
background token refresh. `busy` remains set until the real coordinator worker's
finally block and any requested key retirement finish. A cancelled scope is not
treated as worker termination. The existing bounded transport retains its own
blocked platform workers; recreating an operation never creates another pool.

Only alias ownership phases are durable. Administrative issuer/pending/browser
state, access/refresh tokens, session and shared refresh/logout family remain in
RAM. Startup reads the separate key journal on the worker. Any previous active
phase is explicitly tombstoned and retired before another login is admitted;
corruption blocks rather than resetting ownership. A process restart requires a
fresh browser authentication, even if the last record says `AUTHENTICATED`.

Start captures the ordinary device-context binding and current typed signed
administrative discovery from the read-only LoginController adapter. It persists
a fresh alias reservation before Keystore creation, discovers the issuer and
persists `BROWSER` before owning its private authorization URL. The protocol's supplier rereads the
current context and permits only the captured device/discovery binding. It never
borrows a device token or calls device start/logout, VPN Stop or StateStore.

There is no synchronous cached-browser URL getter. `prepareBrowser(id,generation)`
admits fresh worker-only device context and protocol authorization checks before
publishing a private handoff. A pending prepare has a 60-second bound; the ready
URL is valid for at most five seconds and the remaining pending OAuth window.
`browserResult` exposes it exactly once, only after the worker becomes idle and
the epoch/generation still match. Its `expiresAtElapsedMs` is the original
controller deadline; the UI must enforce it rather than starting another five
seconds after RPC delivery. This is a bounded handoff, not an instantaneous
revocation observer; credential exchange still performs fresh trust checks.
`browserCancel` removes only that handoff; it
cannot cancel the OAuth pending attempt, read mailbox, session or VPN. A cancelled
prepare cannot publish a late URL. Logout/callback also invalidate old handoffs.

A callback is never written to disk or logged. The core validates its exact
scheme, issuer/state, nonce/PKCE and token signatures. A malformed callback that
dispatched no token POST preserves BROWSER only if the existing pending attempt
can still produce the exact owned authorization URL. That extra check avoids
mistaking a consumed valid callback followed by a local signing failure for an
unused malformed callback. A valid denial, consumed attempt or uncertain token
exchange retires this admin owner. AUTHENTICATED is persisted before publishing
the RAM session, but is not a grant or credential restoration mechanism.

Logout immediately advances the RAM epoch, closes the current session family
through local core logout and cancels its IdentityScope. The same worker then
persists RETIRING before deleting that exact admin key and recording SIGNED_OUT.
An already running worker performs this retirement in its finally path. An
unknown cleanup remains blocked and retains the journal alias for an explicit
logout retry. No alias enumeration, device-key deletion, server revocation,
browser logout or VPN mutation is performed.

Manual reads support only `devices`, `configuration` and `runtime`, delegated to
the corresponding three typed core methods. The core constructs/proves the fixed
Control API action; there is no arbitrary URL/action/body or proxy-token bridge.
Each request captures a fresh protected physical route using platform TLS. Route
checks also bind the current epoch and device/discovery context. There is no
process DNS/VPN fallback or forwarded Origin header. Refresh occurs only during
an explicit read when access expires within 30 seconds. A rotation is published
only in the same epoch, and logout closes its shared family. Uncertain refresh
requires a new login; there is no replay of the old rotating pair.

One mailbox binds a 32-hex operation ID, current generation and 60-second BOOTTIME
window. Its body is private bytes, at most 524288 UTF-8 bytes, copied for the
same-UID caller and cleared on replacement, expiry, cancellation or logout.
Public status contains only generation, finite uppercase phase/reason and busy. Read
cancellation cancels only the matching mailbox operation; it neither stops the
VPN nor signs out a still valid admin session. A cancellation after an uncertain
refresh still requires administrative reauthentication. Server ACL/assurance
decisions remain authoritative; status and local AUTHENTICATED never grant roles.

The internal source/exchange/clock fixture factory requires DEBUG,
ranchu/goldfish, a test namespace and a dedicated exact test AES alias. It cannot
select the production journal key. No physical device may run these synthetic
identity fixtures. All executable builds/tests remain GitHub Actions-only.
The adapter/provider/manifest/core read methods and twelve signed controller
cases are integrated in v86 source. Actions, exact-source delivery and live
Keycloak/ACL/MFA plus physical administrative acceptance remain pending.
