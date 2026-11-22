# Explicit public exit-country checks

The `https_exit_country` primitive is separately negotiated as
`route.exit-country.v1`. An approved per-device configuration may require it only
in a key-bound schema2 configure policy with `route.health.v1`. An older client
is denied this assignment; country support does not imply fixed-address support
and neither primitive can silently replace the other. A shared grant template
cannot bypass per-device approval. Existing live publication fences are retained.

The portable check contains `method`, `target` and `expected_exit_class` with the
exact enum `RU` or `NON_RU`. `expected_ip` is exclusive to `https_exit_ip`.
An HTTPS country target has only its root path, without a query, fragment or
userinfo. This prevents accidentally checking an arbitrary address lookup URL
instead of the caller's observed egress. The endpoint is administrator supplied;
no public provider, real user identifier or service credential is embedded.

The candidate connection must carry the request through the exact route being
tested. The endpoint contract is a bounded JSON object with an observed IP and
country. TLS validity, JSON/body/header limits, exact field parsing, known country
codes and cancellation/monotonic deadlines remain client responsibilities.
A valid response for the wrong class is distinct from endpoint failure or a
malformed response. The geo database behind an endpoint can be inaccurate or
stale: this is an observation at one time, not a physical-location guarantee or
authority for future untested connections. Names, flags and profile metadata are
never exit proof.

The route detail on Android and the ADB route response show `verifiedExit` after a
current, successful measurement on the selected path. It contains the coarse
class (`RU` or `NON_RU`), the source `https_exit_country` and the remaining
monotonic validity in milliseconds. A composed profile contributes only leaves
that actually passed. Conflicting classes, ordinary HTTPS success, expiry and a
change of network or policy remove the observation. The device keeps the
endpoint address, observed IP and individual country code out of this field.

The existing internal-only Wi-Fi failover pilot still requires comparable checks
against the internal destination. It rejects both public exit primitives; a
country response cannot establish access to a home service. Full adaptive public
graph activation, contextual quarantine, multiple predicate trees, provider
confidence and the physical Wi-Fi route acceptance remain separate work.

The configuration and policy tests cover method-specific fields, valid classes,
root-only targets, malformed predicates, signed capability matching, shared-grant
denial and the closed OpenAPI/schema contract. A PostgreSQL publication case
requires independent capabilities for a combined country/fixed-IP plan, preserves
both predicates and retains the live final SQL fence. Builds and executable tests
run only in GitHub Actions. Source presence is not CI or physical acceptance.


## Android/native implementation boundary

The native client validates exact case-sensitive `ip`/`country` JSON fields,
current ISO alpha2 country codes and non-scoped/non-mapped IP literals. Verified
TLS is required through the exact candidate; redirects, compressed/cached
responses and trailers are rejected. Limits are8192 header bytes,512 decoded
JSON bytes and2048 body/framing bytes, within the existing3-second and BOOTTIME
probe fences. A successful observation authorizes only that sampled candidate.
The endpoint implementation and its geo database remain trusted administrator
choices; no particular public service or its availability is assumed.

The key-bound policy verifier requires the independently negotiated country
capability. The Android configuration parser preserves the exact method-specific
predicate and renders a generic mismatch without targets or observed addresses.
The internal-only Wi-Fi failover pilot cannot use this public classification.

The new private TCP hub connects the closed graph, owned catalogue, bounded
pool and per-group probe receipts. It remains an internal primitive: no accepted
graph policy or Java Runtime method activates it yet. Shared scheduler, all
protocol transitions, contextual quarantine, managed graph issuance and actual
phone chain acceptance remain open. Ordinary/race and Android API29/35/37
outcomes must be read from the exact Actions commit before acceptance.

The hub admits one actual construction/probe worker and one pending receipt.
Successful checks do not switch traffic. The caller must explicitly commit or
discard that receipt before another exploration; a commit attempt consumes the
receipt even when it has expired. The cache has at most32 resident candidates
and16 groups within128 adapters and128 flow holds. Pressure may retire one idle
unselected candidate, but capacity stays occupied until actual cleanup finishes.
A retired cached handle is purged before rediscovery. A blocked constructor,
probe, close or unknown constructor allocation cannot admit replacement work or
produce a false Stop confirmation.

Fresh, complete wrong-IP/country evidence for the currently selected candidate
withdraws new and existing TCP authority for that group only. Independent groups
sharing the same candidate remain usable. Target/TLS failure, cancellation, clock
rollback and late evidence do not become a confirmed bad-proxy classification.
Per-group/path cancellation handlers are bounded by the existing flow-hold cap;
one blocked socket close cannot prevent independent flows from being cancelled.

## Internal engine outbound handoff

The compiled `syn443-adaptive` adapter can delegate real sing-box TCP traffic to
a hub group. Its reference is created before box construction and initialized
against that exact box before Start. A private context marker alone cannot grant
authority: service registry, actual router/manager, owned tag/group mappings,
catalogue/pool and live lease must all match. There is no direct or UDP fallback.
Closing the reference revokes all groups synchronously; a successful box.Close
acknowledges a cleanup request and cannot substitute actual hub retirement.

This adapter is not registered in the public Runtime, negotiated as a graph
capability or admitted by accepted client policy. Its typed group options reject
unknown/case/duplicate/null fields when decoded directly. The pinned upstream
options decoder first collapses duplicate fields in the original engine JSON;
therefore a strict whole-document decoder before upstream parsing is mandatory
for future activation. The existing outer Android validation must not be removed
or replaced by the typed outbound decoder.

Four additional mandatory native ordinary/race cases cover actual box traffic,
two-hop switching/draining, foreign-runtime/reference substitution, all-group
withdrawal and unknown/blocked owner retirement. The required bridge set is32;
CI and physical runtime activation remain separate acceptance stages.
