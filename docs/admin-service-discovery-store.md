# Metadata-only administrative service refresh

This APP source slice prepares a signed public service-descriptor refresh. It
does not fetch HTTP data, change an issuer/root, create an administrative key or
session, configure a live server, grant a role or modify VPN/device provisioning.
The anonymous [transport](admin-service-discovery.md) and explicit
[administrative-login fallback](mobile-admin-controller.md) integrate this Store
path without borrowing device credentials. Source integration remains pending
Actions and real administrative-login acceptance.

`LoginController.adminBootstrapContext()` returns an owned ordinary Bootstrap and
an opaque device-context binding for a current provisioned POLICY_CACHED or
REFRESHING intent. Administrative metadata need not exist. The binding preserves
generation, reauthentication revision, owner/device, key alias/thumbprint and
ordinary authority. Under the commands lock the adapter only reads public RAM
intent/cache fields, copies roots and computes the small context hash. Bootstrap
validation and KeyFactory work happen outside that lock, followed by a current
intent/cache fence. No device credential is exposed or refreshed.

`adminDiscoveryContext()` uses that ordinary context, obtains a freshly verified
Store ticket and checks the same current ordinary fence again. The two existing
adapter outcomes retain their names and now also exercise the ordinary getter
and update method's main/Binder-thread rejection.

`BootstrapTrustStore.refreshAdminDescriptor(raw, expected)` is worker-only. It
copies and validates the full expected Bootstrap, reads the current protected
root/floors/time, verifies the existing bounded signed-JWS contract and compares
the complete ordinary projection before writing. Service, issuer, client, API,
roots, control-panel origin and TLS-CA differences reject the update. The method
and administrative ticket lookup use the persisted current root without the
normal auto-upgrading Store reader: a pending installation-profile root upgrade fails closed until the
existing ordinary trust flow commits it. A fetched descriptor cannot drive a
root transition. Existing normal reader/upgrade behavior is unchanged.

A first service floor, a higher signed revision or the exact same floor/hash is
accepted. Only an advancing floor or signed issuance-time floor increments the
trust-record revision. That protected write precedes the optional encrypted
cache write/removal. Repeating the exact current signed descriptor can repair a
missing cache without rewriting the journal. Removal and replay cannot revive an
older cache. If cache writing fails after the new floor commits, ticket lookup
returns absent instead of borrowing the older floor. The Boolean result means
verified publication/cache attempt; it grants no authority by itself.

`LoginController.applyAdminDescriptor(expectedBinding, raw)` captures a matching
ordinary context, invokes the metadata-only Store method outside the commands
lock, then returns only a fresh current ticket with the same ordinary binding.
A same-owner ordinary reauthentication changes that binding even when key,
device, generation and Bootstrap remain unchanged. A racing owner change can
still leave a legitimate signed service-global floor advanced, but no ticket is
published for the old owner. Invalid signatures/projections do not change a
normally committed trust journal or cache. This guarantee does not claim that
AtomicFile's intrinsic recovery of a previously interrupted backup is mutation
free. The ordinary device journal/key/Bootstrap authority and an already
committed adaptive root fingerprint remain unchanged by metadata-only refresh.

Three new emulator outcomes use generated offline signing keys and the existing
isolated DEBUG ranchu/goldfish fixtures. They cover first-floor metadata absence,
legitimate update/removal/replay/higher revision, exact-floor repair, retired-root
rejection, every ordinary projection field, unchanged committed bytes, pending
installation upgrade rejection and captured reauthentication fencing. Device
payload/key/consent and fixture transport-path preservation are checked. There
is no test-root/hardware bypass and cleanup retains the existing exact namespace
ownership rules. Executable checks and builds remain GitHub Actions-only; none
have been run locally for this source slice.
