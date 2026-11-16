# Signed administrative metadata foundation

Android v83 / `0.9.55-admin-trust` adds optional offline-root-signed
`ServiceDescriptor.adminBootstrap` metadata. Its closed object contains exactly
`issuer`, `clientId`, `audience`, `apiOrigin`, `assuranceAcr`. The issuer accepts
a canonical HTTPS path; the API accepts only a canonical HTTPS origin. The
administrative issuer/API may differ from the device service.

The protocol fixes client `syn443-control-mobile`, audience `syn443-control-api`,
ACR `urn:syn443:loa:2`, scope `openid syn443.control` and callback
`syn443://admin/oauth/callback`. Scope and callback are compiled constants, not
descriptor fields. Present null, empty/incomplete objects, unknown or duplicated
members, unsafe origins and alternate protocol constants are rejected.

Omitted metadata retains the exact old descriptor serialization and signed
vectors. Admin metadata is never projected into device `Bootstrap`, its
serialized bytes or `Identity.bootstrapAuthority`. A signed metadata change must
still advance the whole service descriptor's protected revision/hash floor.
The existing browser entry and its independent server authorization are retained.
Older strict clients reject the new field when present, so publishing enriched
descriptors requires a compatible-client rollout. This source foundation does
not publish or replace a live descriptor.

`BootstrapTrustStore` keeps the signed manifest in a separate encrypted
`AtomicFile` for each accepted service. The existing maximum of 32 committed
service floors bounds cache ownership. Each encrypted file is capped at 8192
bytes; the manifest remains capped at 6144. The AES key is the existing local
Keystore key, with separate namespace/service/domain AAD. The 65 KiB primary
trust journal and its serialized fields are unchanged.

The primary floor is committed before the optional cache is written. An
interrupted or failed cache write preserves a valid device bootstrap and makes
admin metadata unavailable. Reading is worker-only: it requires the exact
committed service/revision/hash, then re-verifies the manifest's current root,
signature and validity and compares the complete device Bootstrap projection.
Missing, corrupt, oversized, stale, retired-root or foreign-service data returns
no metadata. Removing metadata in a newer signed descriptor deletes the old
cache; replay also fails the exact current floor check. Reaccepting the same
current descriptor can repair its cache without changing the device journal.

Three named JVM identity cases cover legacy bytes, unchanged device authority,
signed tampering/revision/expiry and shared Go/Kotlin strict vectors. Three named
Android cases exercise actual encrypted cache persistence, projection/service
isolation, removal/replay, root retirement, expiry, corruption and byte limits.
The retrieval-clock fixture requires an explicit synthetic anchor/profile,
debug build, test namespace and emulator hardware. It changes no device
admission or VPN lease clock and is unavailable on a physical phone.

GitHub Actions requires all six named outcomes. Each API 29/35/37 matrix must
produce at least 287 unique Android outcomes with no failures, errors or skips.
This source change has not been executed locally or physically accepted. The
native administrative OAuth flow, separate local DPoP keys/sessions, API client
and quick-screen UI remain unimplemented. Server grants remain mandatory;
signed discovery metadata provides no administrative authority.
