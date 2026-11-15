# Capability negotiation across APK updates

The APK declares implemented modules; a declaration grants no account rights,
configuration or native-engine ownership. Existing approved enrollments remain
immutable. A separate server publisher re-verifies the signed request, current
account/device authorization and either the fresh OIDC identity or a narrow live
device-session fence before appending a strictly additive capability version.
Deploy the control-plane schema, roles and publisher before this APK.

The client reads the authenticated capability snapshot and derives a stable
operation ID from its authority, key, device/session generation, current authority
hash and old/new capability hashes. Pending or unknown acknowledgements repeat
the exact body. If approval already committed, the next snapshot reconciles it
without another mutation. An approved response is checked against the expected
hash/version, then the device path reads back the independently published head.
Unknown modules, downgrades, malformed replies and unbound heads fail closed.

Confirmed availability is stored only in the encrypted login payload. The absent
optional field preserves legacy payload bytes. Recording it preserves identity,
intent generation, assignment receipt, overlay ownership and activation state;
session refresh retains it. Pending approval or temporary server failure leaves
an existing authorized assignment intact. Existing worker cancellation, lease,
single-writer and backoff limits remain authoritative; no extra timer or VPN
restart is introduced.

Fresh OIDC enrollment can request the independent capability approval after the
specific `capabilities_update_required` conflict and then repeat its original
durable enrollment operation. Visible pending enrollment uses existing bounded
poll admission. An old enrollment body with an unknown acknowledgement is never
rewritten. Only after its bound acknowledgement can the controller persist a new
current-version operation and dispatch it. Manual pairing and cached device
sessions need no new Keycloak login for this additive negotiation.

Actions requires ten new JVM cases, an independent 90% coverage check for the
negotiation core and four controller/Keystore/restart cases on API29/35/37.
These gates do not establish real-server or physical Xperia acceptance. Full
settings provisioning, new-user defaults, key rotation and final M2/M3 acceptance
remain separate requirements.
