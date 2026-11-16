# Native comparison and local rebase

Version89 (`0.9.61-admin-compare`) is a source candidate. Its new executable
outcomes, live administrator OIDC/MFA/API acceptance and physical comparison UX
remain unverified. Builds and executable checks run only in GitHub Actions. LTE
testing remains excluded. The existing [layered editor contract](mobile-layered-editor-contract.md)
continues to define server drafts, preview, publication and durable pending work.

## Explicit comparison workflow

For one already assigned device, an administrator can explicitly load the base,
local proposal and current remote layers, page through conflicts or differences,
and request one bounded raw value or provenance fragment. Summaries do not carry
whole documents. A comparison page contains at most20 rows; a requested detail
contains at most8192 UTF-16 units. The private same-UID frame is limited to65536
UTF-8 bytes and uses canonical base64url for detail text, strict UTF-8, closed
fields, duplicate rejection and worker-only processing. Computed leaf paths have
at most16 ASCII key segments of64 characters (1040 characters including slashes);
mutation paths retain their separate512-character limit. Configuration details
can be confidential even though the frame carries no OAuth or device-identity
fields.

`AdminLayerComparison` performs a bounded local three-way comparison. It keeps
SET, DELETE and INHERIT distinct, preserves protected parent/permission bytes,
and can require explicit LOCAL or CURRENT choices for a bound conflict. Changed
choices change the resolution-state binding. A ready local projection neither
compiles typed VPN settings nor establishes a role, current approval or right to
publish. Unsupported shapes, invalid permissions and unresolved conflicts do
not expose a ready candidate.

Apply requires a separate confirmation bound to the exact resolution state,
device and local editor revision. The controller then rechecks the current
administrator context, a fresh device head, the actual saved private-draft CAS,
and the actual encrypted local record. Only the matching proposal is saved by
the local REBASE operation. It does not save a server draft, request a preview,
publish, activate a policy, or change the administrator phone's VPN. Those
actions remain separate explicit operations with server ACL/MFA and validation.

An ordinary successful preview exposes its own cached read-only full difference
view. It retains the same proposal/CAS and original review deadline. Paging,
viewing provenance and returning to the editor do not request another preview
or renew that deadline. Unsaved input disables opening the old full difference
and invalidates publication review. Read-only comparison cannot choose or apply.
STOP, removal and recreation clear presentation RAM and cancel only the owned
request; they do not automatically reload an editor, replay a mutation or log in.

## Actual Go projection evidence

The richer public fixture is the accepted Control Plane PR57 producer output,
not a handwritten Kotlin oracle. Its receipt is
[`admin-layer-projection-source.json`](../core/identity/src/test/resources/admin-layer-projection-source.json):

- Producer source: `d4d9a4d774a6b1bc404563af648d547b92399af4`.
- [Actions43956602201](https://github.com/nd4y/syn443-control-plane/actions/runs/43956602201),
  artifact `layer-projection-evidence`, ID`14272259074`.
- Fixture SHA-256: `7187eb00ad98742b1043c867b2c3d909e34cd9764d8149d69f6565df89c6a135`.
- Artifact digest: `sha256:89325b5b220c0659a086fd32c6fdef97fe45e4759a46d6a808c2c8f003bf6c19`.

The byte-exact resource supplies41 actual Go DecodeLayers/Merge projection
outcomes,11 explicitly chosen rebase projection examples and2 source-generated
4096/4097-leaf bound summaries. The chosen examples do not claim that Go has a
production three-way rebase library. Each projection retains the full effective
document, field origins and restrictions or its finite rejection code. Global
layer hashes use the actual Go Marshal/SHA-256 formula. The earlier CP55 wire
fixture remains unchanged. Android conformance to this richer accepted resource
still requires its own Actions results.

## Required evidence and remaining work

The candidate adds14 exact identity roots and21 exact Android roots:5 coordinator,
7 pure UI,5 private-wire and4 actual-route/fake-bridge outcomes. The mandatory
floors are200 identity outcomes and398 actual Android outcomes on each required
API29/35/37 emulator. All11 new stable handwritten comparison/projection classes
join the unchanged90% per-class line-coverage rule in both verifiers. Pure enum,
local generated data, anonymous and compiler-generated classes are not used to
pad that requirement. Source gates are requirements, not passed-test evidence.

Initial assignment, complete user/server administration, real native OIDC/MFA
and live mutation acceptance remain open. Generic HTTP400/403/409/429 after an
uncertain earlier dispatch is not proof of no committed mutation. Durable
pending bytes remain owned until exact reconciliation; a checked server
operation-ledger/nonmutation-receipt protocol is still needed to safely release
otherwise unknown outcomes. This comparison slice does not close that gap or
claim completion of M3 or the full specification.
