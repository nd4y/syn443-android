# Administration entry

An optional `controlPanelOrigin` can be supplied by the owner bootstrap or the
offline-root-signed service descriptor. It must be a canonical HTTPS origin:
no userinfo, path, query, fragment, trailing hostname dot, uppercase authority or
explicit default443 port. Empty/absent metadata provides no button and does not
invent an address from the enrollment API. Existing serialized authority bytes
remain unchanged when the optional field is absent.

The home screen exposes Administration after the current device session receives
a live navigation hint from the server. The controller checks login generation,
session generation, device, owner and a monotonic deadline before returning the
URL. It refreshes the hint at most once a minute while the home screen is visible.
The hint stays in memory. An absent grant, expired session, older server, logout
or process restart hides the entry until the server confirms eligibility. Status
contains only flags, with the URL returned to the app's own UI on explicit click.

The link contains no token, private key, invitation or device credential. The
control console obtains its own Keycloak control-audience session and fresh MFA;
server-side granular ACL remains mandatory. A visible button grants no rights.
A browser session has its own server logout and expiry lifecycle. Native quick
screens, the menu entry and the full managed editor remain separate work.

Core tests cover authenticated metadata, canonical URL rejection, authority
binding and legacy omission. Android controller tests cover current generation,
controller restart, absent grant, older servers, rate bounds and immediate logout
fencing on the required emulators. Physical role-gated browser entry and native
administration remain open.
