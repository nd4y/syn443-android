# Separate native administrative OAuth core

This source slice adds the identity/protocol foundation for MOB-02/MOB-04. It
does not expose an Android administrative screen, launch a browser, register an
OAuth client, store credentials or call the control API. Custom Tab navigation
remains the separate MOB-03 feature. Compilation, executable tests and acceptance
must run in GitHub Actions; source preparation is not live authentication proof.

`AdminIdentity` validates a copied `AdminBootstrap` and a canonical SHA-256
rawurl service-binding digest. It hashes both into an administrative authority.
The constructor verifies values, not a signature. Its future controller must
obtain metadata and its service/root/floor binding atomically from the same
verified BootstrapTrustStore state. Separate getters or a later device bootstrap
hash can race a trust update and are not sufficient. The future controller must
also recheck the current descriptor/discovery ticket and expiry before every
operation. The local eight-hour session cap does not override descriptor expiry,
role revocation or server policy. This core constructs no device `Bootstrap` and
does not modify the device DPoP key, owner, VPN session or journal.

`AdminProtocol` accepts its own injected `ProofKey`, bounded `IdentityExchange`,
BOOT and elapsed clock. Discovery pins the administrative issuer's exact
Keycloak authorization/token/JWKS endpoints, RS256 signing, ES256 DPoP and S256.
Authorization has fixed client, audience, scope, callback and assurance request
constants from `AdminBootstrap`; it does not request `offline_access`. The
separate callback is `syn443://admin/oauth/callback`, with exact state and issuer,
PKCE, nonce, key, generation and five-minute BOOT ownership. Device callbacks,
duplicate parameters, injected shapes, rollback and replay are rejected.

ID/access signatures and issuer, audience, authorized party, subject, short
expiry and DPoP confirmation are validated independently. Initial ID nonce is
required. A refresh ID token is optional; if present its signature, principal and
audience remain mandatory, its nonce must match the original when present, and
`at_hash` is checked whenever supplied. Required access scopes are checked;
cached roles or ACR claims do not grant privileges or replace server-side MFA.
HTTPS Date and measured RTT provide conservative BOOT expiry windows; body
`expires_in` must agree with signed access expiry within that window.

Access tokens last at most 600 seconds. Server `refresh_expires_in` must be
positive and at most 86,400 seconds. The initial local session is bounded by
that expiry and eight hours from the initial trusted Date. Rotation can only
shorten this original BOOT deadline. A rotating refresh has one process-owned
dispatch owner. Only one explicit token-endpoint DPoP nonce challenge permits
retry of the same body with a fresh proof. Success is never retried. An uncertain
transport, cancellation or invalid reply after refresh dispatch requires a new
authentication; the old refresh pair cannot be replayed. Cancellation before
dispatch sends nothing and retains an unused pair. No control-API nonce protocol
is added by this layer.

Pending attempts and sessions are process-owned and use private atomic lifecycle
state. Rotated pairs share a private RAM family-close latch: local logout closes
old, current and in-flight members, so a late refresh cannot publish a usable
member. They are not serialized or restored as authorization. An encrypted admin
journal, distinct key alias, atomic current-trust ticket, controller generation
fencing, callback routing and account/expiry recovery are future integration
work. They must never reuse the device journal. Logout here retires local
administrative ownership only; it makes no server-revocation, browser-logout or
device-key claim.

`AdminIdentityTest` and `AdminProtocolTest` contain synthetic runtime-generated
keys/JWTs and injected transport outcomes. They cover exact authorization and
callback shape, metadata/authority isolation, claims and access hash, BOOT/time
limits, nonce retry bounds, rotation, uncertain delivery, cancellation,
concurrency and redaction. They do not prove browser SSO, Keycloak registration,
MFA, live ACLs, durable storage or physical phone behavior. The exact named
methods must be required by the Actions outcome gate before merging this slice.

Protocol references: [RFC 8252](https://www.rfc-editor.org/rfc/rfc8252.html),
[RFC 9449](https://www.rfc-editor.org/rfc/rfc9449.html), and
[OIDC refresh validation](https://openid.net/specs/openid-connect-core-1_0.html#RefreshTokenResponse).
