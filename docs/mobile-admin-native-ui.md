# Separate native administrative read-only UI

This source slice adds a dark-by-default Material3 administrative screen,
separate administrative browser/callback navigation and a same-UID controller
bridge. It requires the independently integrated manifest/controller/API gates.
No live login, mobile client registration, MFA, server ACL, physical UI or
configuration publication is established by preparing these files.

The screen offers administrative login/logout, a32-device authorized page with
an explicit after cursor, device selection, sequential configuration/runtime
reads and the existing full web-panel shortcut. Pages replace previous pages;
the UI does not accumulate an unbounded inventory. Configuration is read-only
literal text, collapsed initially, then lazily rendered in chunks of at most2048
UTF-16 units without splitting surrogate pairs. UTF-8 bodies are capped at524288
bytes. Decoding, JSON parsing and chunking run on IO, never the main thread.
Runtime labels describe the last report as recent/stale/missing. An activation
receipt never becomes a claim that a device is connected now.

The bridge dispatches `admin-status`, `admin-login`, `admin-logout` and
`admin-callback` through `content://io.syn443.control`.
Reads use a fresh32-hex operation ID plus captured administrative generation:
`admin-read-start` carries generation/action/target; `admin-read-result` returns
finite state JSON and a UTF-8 `body` byte array; `admin-read-cancel` addresses only
that operation/generation. The controller retains its own single-worker,
authority and cancellation guarantees. UI polling exists only while foreground
and an operation is pending, at one-second intervals with a60-second bound.
Leaving the foreground cancels that UI job and clears RAM device/documents.
No body is logged, automatically copied, saved in state or passed as an Intent
extra. An explicit text-selection gesture is the only configuration copy path.

The full web-panel shortcut captures the ordinary device login generation,
checks `auth-admin-panel` and requests at most one `auth-admin-poll`, then polls
only that captured generation while foreground. It does not borrow the native
administrative generation or session. Origins are never carried in status.

An explicit browser tap starts one fresh32-hex `admin-browser-start` handoff,
then polls `admin-browser-result` at one-second intervals for at most30 seconds
while foreground. The controller revalidates current signed discovery and
authorization on its worker before exposing the one-use URL. There is no cached
`admin-browser` fallback. The UI carries the controller's original
`expiresAtElapsedMs` unchanged, checks it after cancellation/status roundtrips
and immediately before Custom Tab launch, and never restarts its five-second
window at receipt. A dedicated
`admin-browser-cancel` in finally addresses only that handoff; it never logs out
the session, cancels a read or consumes the OAuth pending attempt.
Shape validation requires a canonical HTTPS
endpoint ending in `/realms/<realm>/protocol/openid-connect/auth`, including a
canonical issuer path prefix such as `/auth`, the exact fixed client,
scope, callback, response type, S256, ACR and four canonical43-character proof
values. Unknown/duplicate parameters, device callbacks, fragments, userinfo,
unsafe origins and token fields are rejected. AndroidX Custom Tabs keeps the
dark toolbar/title and browser-owned session; app-supplied header extras are
removed. There is no WebView or alternate-URL fallback. The callback Activity
immediately clears Intent data, forwards only the bounded administrative route
to the controller on IO and returns to the administrative screen. It invokes
no VPN command or ordinary device-login callback.

`AdminNativeUiTest` uses immutable synthetic models and callback injection only;
`AdminLoginBrowserTest` checks URI/intent semantics without launching a browser.
Decoder cases cover the full byte limit, invalid UTF-8, surrogate-safe chunking,
foreign-device bodies and32-row pagination. These cases need Actions execution
and mandatory evidence registration; they do not prove a real administrative
session or phone acceptance. Editor/preview/publish and full native mobile
administration remain later slices.
