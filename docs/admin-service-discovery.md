# Anonymous service descriptor transport

`AdminServiceDiscovery(bootstrap, exchange).fetch(scope)` performs exactly one
anonymous GET to the currently owned ordinary Bootstrap API origin followed by
`/.well-known/syn443/bootstrap/<serviceId>`. It copies the bootstrap's roots,
validates the complete bootstrap and requires a canonical HTTPS API origin. The
canonical service identifier is used as one literal path segment. Callers cannot
supply a URL, query, redirect target or administrative issuer as a substitute.

The only request headers are `Accept: application/jose` and
`Cache-Control: no-store`. There is no request body, Authorization, DPoP, Cookie,
Origin, credential, retry or nonce-challenge handling. `IdentityExchange` receives
the exact single scope child and a 6144-byte response bound. The caller supplies
its existing platform-TLS transport and protected physical route owner; this
component owns no threads, pools, timers or Android state. Construction and fetch
belong on the identity worker, including bootstrap public-key validation.

Operator `tlsCaDer` bootstraps are explicitly rejected. A signed service
descriptor has no field for that development loopback CA, and this transport does
not silently enable one or downgrade TLS. This rejection does not alter the
ordinary Bootstrap or existing device login transport.

A response must be 200 with exactly one `application/jose` Content-Type (media
type case and surrounding header whitespace are insignificant; parameters are
not accepted). Its bounded body must be valid UTF-8 and ASCII compact JWS syntax:
three nonempty canonical unpadded base64url segments, with no leading/trailing or
embedded whitespace. The result is `AdminServiceManifest` with an explicit
immutable `raw` string and redacted diagnostics. It is not signature verification
or an `AdminDiscovery`, role, session, trust root or floor. Even a structurally
valid envelope signed by a foreign root is only an untrusted fetched value.

The [app Store refresh](admin-service-discovery-store.md) verifies this value
against its already installed root, requires the exact current ordinary
Bootstrap projection and owns the atomic floor/cache update. The explicit
[administrative-login fallback](mobile-admin-controller.md) applies that update
and rereads a fresh matching device/discovery context before reserving an admin
key. Metadata failure, logout or a captured-context change cannot publish a late
owner. No trust is derived from a root delivered in the response. HTTP Date is
ignored and neither creates nor updates a clock or admission floor.

Non-200 statuses, including redirects, 404, 429, 503 and authentication challenges,
produce finite `TRANSPORT`. There is no automatic retry or authentication. Invalid
headers, framing, UTF-8 or compact envelope syntax produce `INVALID_REPLY`;
cancellation produces `CANCELLED`. Errors contain no response text, endpoint or
manifest. IdentityScope/child cancellation is checked before and after transport,
after parsing and before the enclosing scope returns a value. Copied reply bytes
are cleared after decoding, and the single request child is retired by its owner scope.

Eight new `AdminServiceDiscoveryTest` methods cover the fixed request and child,
the full 6 KiB transport limit, invalid bootstrap/CA/path inputs, malformed envelope
and UTF-8/headers, finite statuses and transport failures without retry,
cancellation with a bounded held exchange, ownership under caller mutation and
the distinction between fetched data and existing-root trust. Generated
signatures and transport doubles use synthetic public data only. The three new
handwritten classes are included in the existing 90% class line gate and its
independent evidence verifier. Six additional Android outcomes cover Store,
ordinary-context and controller admission integration. Version87 /
`0.9.59-admin-discovery` is source-pending: builds and executable tests remain
GitHub Actions-only and have not been verified for this candidate. Source
integration does not establish live public descriptor publication, authenticated
Keycloak/MFA/ACL access, server configuration changes or physical acceptance.
