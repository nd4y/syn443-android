# Trusted mobile administrative browser

The administrative entry opens the existing responsive PatternFly control panel
in an AndroidX Custom Tab. The toolbar/navigation colors come from the app, the
tab requests the dark scheme and visible title, and ordinary browser Back/Close
returns to the app. AndroidX Browser is pinned to1.10.0.

Navigation is derived from the trusted bootstrap control origin and current
device under the same command lock as the generation, session, owner, device
and discovery-expiry checks. The exact URL is `https://control.example.invalid/`
with a `device=` fragment containing the canonical current device identifier.
The fragment is navigation metadata, not an access grant. The existing BFF binds
it through login/callback and loads the card under its normal server ACL.

Both the origin and complete target are checked. Paths, queries, userinfo,
encoded/injected fragments, noncanonical device identifiers and stale/cancelled
discovery cannot produce a launch target. The browser owns its independent
Keycloak/BFF session and MFA. The app passes no device credential or HTTP headers
and creates no new OAuth client, WebView or JavaScript bridge. A missing browser
produces the existing finite launch error.

Actions requires four new intent/URL cases, the new prequeue-cancellation case
and the existing current-generation administrative-entry case. The v82 API 29/35/37
matrix required 284 unique actual outcomes without failures or skips. The
[signed admin metadata foundation](mobile-admin-bootstrap.md) raises the current
gate to 287 and adds separate trust outcomes. These browser tests
inspect intents and scoped discovery; they do not establish actual browser
rendering, Keycloak authentication or a live administrative card. Those remain
physical acceptance steps.

This implements the browser entry described by MOB-03. Native quick screens in
MOB-02/04/05, full local configuration editing/publishing, one-hand workflow and
the remaining M3 scope remain mandatory and are not completed by a browser link.
