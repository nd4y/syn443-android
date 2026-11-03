# Administration entry

An optional `controlPanelOrigin` can be supplied by the owner bootstrap or the
offline-root-signed service descriptor. It must be a canonical HTTPS origin:
no userinfo, path, query, fragment, trailing hostname dot, uppercase authority or
explicit default443 port. Empty/absent metadata provides no button and does not
invent an address from the enrollment API. Existing serialized authority bytes
remain unchanged when the optional field is absent.

For a registered current login, the UI exposes Panel management and opens the
system browser. The controller checks the current generation/device/owner before
returning the URL; the app-only provider action cannot be invoked by debug ADB
shell. Logout/cancellation immediately removes the entry. Only availability is
included in ordinary status, without publishing the configured URL.

The link contains no token, private key, invitation or device credential. The
control console obtains its own Keycloak control-audience session and fresh MFA;
server-side granular ACL remains mandatory. A visible button grants no rights.
An administrator-specific bootstrap can supply this metadata; complete managed
UI-permission settings remain separate work. A browser session has its own
server logout/expiry lifecycle.

Core tests cover authenticated metadata, canonical URL rejection, authority
binding and legacy omission. Android controller tests cover current generation,
controller restart, absent metadata and immediate logout fencing on the required
emulators. Source v35 is pending GitHub Actions and exact Xperia UI acceptance.
It does not claim a live control-panel login or complete mobile administration.
