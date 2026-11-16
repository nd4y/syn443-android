# Native layered editor value contract

The v88 source candidate connects bounded layer codecs, guarded administrative
HTTP, an encrypted local editor, the controller coordinator and an explicit
native editing route to the existing Control API. Codec values and local files
never establish permissions, satisfy fresh MFA or authorize publication. The
current separate administrator session and server ACL remain mandatory at every
operation. This candidate is source-pending: its new executable outcomes, live
publication and physical editor UX have not been accepted. All builds and
executable checks belong in GitHub Actions.

The source scope is editing one already assigned device, explicit private-draft
save, preview, review, publication and reconciliation. Initial assignment,
changed-head rebase, broad user/server administration and the remaining full
workflows use the web panel. This is not completion of the full specification.

## Existing operations

`AdminLayerAction` contains only the existing fixed actions:

| Factory | Control action | Reply |
| --- | --- | --- |
| `inventory` | `configuration.inventory.get` | Current device configuration and layer provenance |
| `history` | `configuration.history.get` | Exact historical revision/hash |
| `listDrafts` | `configuration.layers.drafts.list` | At most 64 saved draft summaries |
| `getDraft` | `configuration.layers.draft.get` | Saved portable proposal |
| `saveDraft` | `configuration.layers.draft.put` | Saved draft with private revision CAS |
| `discardDraft` | `configuration.layers.draft.discard` | Exact saved revision discard receipt |
| `preview` | `configuration.preview.request` | Preview job |
| `poll` | `configuration.request.get` | Same typed preview/publication job |
| `publish` | `configuration.publish` | Publication job and resulting desired heads |

The caller supplies a validated 24-128 character operation request ID. The
request owns immutable UTF-8 bytes; `bodyBytes()` returns a copy. A retry of the
same uncertain operation retains those exact bytes and ID. A new HTTP dispatch
still needs a fresh DPoP proof whose `req_hash` covers these exact bytes. The
encoder sorts known envelope fields while embedding validated opaque layer spans
unchanged. It does not claim recursive JCS normalization of portable values.

The protocol must select the currently signed API origin, verify the live
administrator/session/device context, enforce cancellation, and perform fresh
MFA when required. The actor argument is the protocol-derived digest of verified
issuer, NUL, and verified subject. Passing an actor or origin to a codec grants no
rights. A result of `published` describes desired configuration heads; it does
not describe Android activation, VPN readiness, or connectivity.

## Portable proposals and editing

`proposal(raw)` retains a complete portable proposal. Bounds include 262144
UTF-8 bytes per proposal/request, 64 distinct recipients, 20 layers per recipient,
at most 16 group layers, 256 changes/permissions per layer, 512 changes and 256
permissions across each recipient's layers. IDs, revisions, target scopes,
permissions, change paths and base revision/hash pairs are checked. A server
preview remains authoritative for inheritance, group conflicts, restrictions,
profile/source authorization, merged settings and current recipient state.

`editDevice` starts from an actual nonhistorical inventory. It creates a
single-device proposal with the current base revision/hash and mode, and edits
only the requested device/local layer. Both kinds use the recipient device ID as
their layer ID. An absent device/local layer is added only when capacity permits.
The private draft ID is independent. Existing parents and their revisions remain
unchanged; only the edited layer revision advances. Private draft revision and
global layer revision are separate domains. A new helper proposal begins at
private draft revision 1.

`newDeviceDraft(inventory, draftId, approvalUntilMs)` copies an assigned current
inventory into a private draft without changing any global layer revision. It
retains the authoritative raw layer array, current base revision/hash and mode;
the requested approval cannot exceed the captured inventory approval. It does not
create the first configuration of an unassigned device.

`prepareDeviceDraft(baseInventory, candidate, expectedDraftId,
expectedSavedDraftRevision)` is the bounded full-text editor preparation path.
It requires one device/bundle, matching draft ID, captured target/base revision
and hash, and bounded approval. It regenerates the private draft revision as the
saved private revision plus one, rather than trusting a revision edited as text.
The candidate may explicitly select any existing mode (`home_wifi`, `wifi`,
`cellular_restricted`, or `cellular`); the chosen mode is retained for fresh server
preview and ACL checks. This is configuration support, not LTE testing or phone
network activation.
All existing layers are retained. Template/group/user layers and every existing
permission are immutable in this mobile path. Resetting own overrides uses an
empty change array, not removal of the layer. A new device/local layer may contain
no permissions.

Protected layers are compared recursively by JSON values using exact
`BigDecimal` numeric equality. Formatting, escaped-string spelling, key ordering
and equivalent values such as `1.00` versus `1` may differ, but the output copies
the original **server raw layer bytes**. Distinct high-precision numbers that
round to the same `Double` remain different and are rejected. The same rule
protects existing permissions. If an own layer's changes are semantically
unchanged, its whole server wire and global revision remain unchanged. Otherwise
its global revision becomes the captured base layer revision plus one, once for
the entire batch of local edits; the user-supplied own-layer revision is ignored.
New own layers begin at global revision 1. Repeated local preparations do not
increment that global revision again. `saveDraft` retains the separate explicit
private draft CAS.

A historical inventory may be used only as a captured base for private
preparation. This is not a new base, automatic rebase, current approval, or
publication grant. Comparison is explicit. Rebase onto a changed head is not
implemented in this candidate: `REBASE_REQUIRED` retains private edits and blocks
publication until the operator resolves the new base in the full panel. An
unchanged base still requires a fresh authoritative server preview and review.

`SET` stores one bounded portable value, `DELETE` emits an explicit field deletion,
and `INHERIT` removes an existing override without emitting a deletion. The helper
preserves exact raw bytes for every unchanged whole parent layer, untouched target
change and permission array. It does not reconstruct a parent from
`effective.document` or silently flatten the hierarchy.

The layer-only JSON reader retains raw spans, including string escapes, object
ordering and numeric lexemes such as `1.00` and `1e0`. These matter to Go
`json.RawMessage` layer hashes. Finite portable fractional/exponent values follow
the existing server numeric bounds; integer metadata remains strict integer
tokens. Generic objects/arrays are bounded at 512 entries and depth at 24. Only
the exact inventory root `effective.fields` map may contain 4096 entries. UTF-8 is
bounded at 524288 bytes and the tree at 262144 nodes. Global OAuth, device and
signature JSON limits are unchanged.

Generated Kotlin examples exercise shape and lexical retention. The immutable
`admin-layer-wire.json` test resource now contains five actual Go-marshaled layers
and four actual Go-merge scenarios, with its producer recorded separately in
`admin-layer-wire-source.json`. Its accepted producer is Control Plane commit
`4407bd8747bf4f7f66d889ec9b444b52b8853fe8`,
[Actions run 43928005749](https://github.com/nd4y/syn443-control-plane/actions/runs/43928005749).
The exact resource SHA-256 is
`a70a87e162484e2dbe77e81659080af25f6eef641330bbab582f1a193522b713`.

The new Kotlin conformance test pins that provenance, checks every Go layer hash,
wraps the actual layers/effective documents in strict synthetic inventory replies,
and checks editor/request/replay parent-byte retention. Generic parent
re-encoding is a negative hash-difference case. These are now 23 codec and four
reader test roots in source. Producer acceptance is complete; the new Kotlin
conformance test has **not** been executed locally and remains pending GitHub
Actions acceptance. Neither the producer fixture nor a future passing Kotlin
test alone proves a real administrative publication, Android activation, or
phone connectivity.

## Preview and publication bindings

The preview and publication context binds proposal, actor, origin, original
request ID and derived job ID. Ready results match the proposal scope/mode,
recipient set, each base revision/hash, current metadata shapes and bounded ticket
times. The compact ticket has the actual Go ES256 header purpose and closed
payload, canonical base64url segments and a 64-byte signature representation. Its
decoded payload must exactly match the outer preview object. Go emits struct
field ordering, not sorted-key JCS; that valid ordering is accepted. These are
syntax and binding checks, not ECDSA verification or client-side authorization.

Seven current job states are accepted: `queued`, `running`, `ready`, `published`,
`rejected`, `expired`, and `cancelled`. The legacy SQL fixture state `applied` is
outside this native current-job workflow and is rejected rather than interpreted
as activation or success. Rejected/expired results cannot enable publication.
Published heads must match every recipient, base revision plus one, and the
preview draft hash. Effective hash and desired-head hash are not interchangeable.

## Durable reconciliation boundary

`replayContext(request, actualActor, actualOrigin)` returns a closed value-only
snapshot of at most 8192 bytes. The private controller store must authenticate and
encrypt it with the exact body and captured proposal **before** any mutation HTTP
dispatch. It must separately retain phase/dispatched/uncertain ownership. The
snapshot is not a session, MFA grant, signature trust, or authorization token.

`restoreRequest(exactBody, context, ownedProposalRaw, actualActor, actualOrigin)`
checks UTF-8/byte limits, exact shape, body/proposal hashes, current actual actor
and origin, fixed action and scope, original request/job IDs and preview metadata.
It reconstructs the fixed envelope and requires byte-identical operation bytes.
Original publish requests additionally decode their retained ticket and check its
payload against the proposal/context. A publish-job poll body contains only the
job ID, so its authenticated snapshot retains bounded preview metadata and ticket
hash rather than duplicating the ticket or full recipient list.

Every restored preview is `replayOnly`. A ready result obtained through a restored
preview operation also remains `replayOnly`; `publish` rejects it for a new
request ID. An original restored publish request may be explicitly polled or
retried with the same body/ID, including after ticket expiry, because the server
owns idempotency and terminal decisions. Restoration never schedules network
work or renews an approval. A fresh publish requires a new explicit preview and
review. Invalid dirty local editor text does not prevent discarding an already
saved draft: discard restores its saved ID/revision/scope without parsing that
unsaved text.

All DTO string formatting is redacted. Complete validated wire replies are
available only through explicit `wireJson()` for the private authorized editor
handoff. They must not be copied into global status, telemetry, logs, or public
artifacts.

## Local ownership and revision domains

Four revision domains remain separate: each published global layer revision,
the server's private-draft CAS revision, the encrypted local editor CAS revision,
and each recipient's published desired-head revision. A local text save changes
only the local CAS. Private-draft preparation derives its next saved revision
from a checked server draft; publication checks the captured desired base and
returns the next desired head. None of these counters is substituted for another
or inferred from a successful local write. Publication is not VPN activation.

`AdminEditorStore` owns one AES-GCM/AtomicFile editor in `no_backup`, under a key
separate from device identity, administrator DPoP and login journals. Its closed
binary record contains only bounded owner digests, target/draft IDs, local CAS,
UTF-8 proposal and optional exact pending body plus replay context. It stores no
access/refresh token or administrative grant. Caller arrays are copied, foreign
owners cannot read the record, and a corrupt/missing key or orphaned file fails
closed without resetting ownership. Work runs on the controller worker.

The pending envelope is durable before mutation dispatch. A lost reply,
revocation, logout or process restart retains the exact request ID/body/context
and forbids editing, replacing or closing the unknown operation. Recovery sends
nothing automatically. Explicit reconciliation rechecks the current signed
administrator context, actor, origin and exact saved envelope; a new login can
restore authority without converting the retained bytes into a grant. A restored
ready preview cannot authorize a new publication. Only a matching verified
terminal result resolves pending ownership. A closed empty tombstone can start a
new owner while preserving the monotonically increasing local CAS and AES key.

The native route presents local save, server-draft save, preview and publication
as separate actions. Publication needs a fresh bounded review of the exact
binding and explicit recipient confirmation; local changes invalidate that
review. Stop/removal clears unsaved presentation RAM and cancels only its owned
editor operation. It does not log out the VPN device, alter its desired state,
enable cellular tests or schedule a hidden publication. Full server-side ACL,
MFA, jobs and signed-policy activation remain independent gates.

## Required source evidence

The candidate adds 42 named identity outcomes and 44 Android outcomes, raising
the mandatory floors to 185 and 377 on each API29/35/37 emulator. All 19 new
handwritten layer classes require 90% line coverage in both existing verifiers.
The source tests include the actual Go fixture, exact parent spans, immutable
DPoP-bound requests, refreshed ownership, encrypted lost-acknowledgement recovery,
four revision domains, changed-head refusal and UI review lifetime. These names
and counts are mandatory source gates, not a claim that they have run or passed.
