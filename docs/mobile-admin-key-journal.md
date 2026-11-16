# Administrative key ownership journal

This source slice supplies an isolated Android administrative signing key and a
small encrypted ownership journal. It does not implement the admin controller,
callback routing, API actions or native screen. Administrative OAuth sessions,
pending PKCE values, tokens and shared refresh/logout CAS state remain RAM-only.
Controller-process death requires a fresh browser authentication; an
`AUTHENTICATED` journal record is ownership metadata, never a restored session.

`AdminKey` implements `ProofKey` using a non-exportable P-256 signing key in
Android Keystore. Aliases are generated as `syn443-admin-dpop-` plus a fresh
43-character random base64url value. Creation, opening, public-key access, signing and deletion reject
the main and Binder threads. `createIfCurrent` checks the controller's short
reservation predicate under the key lock; a cancellation must persist retirement
before queuing owned deletion, which waits for any already admitted creation.
There is no alias enumeration. `deleteOwned` rejects device, policy and all other
subsystem prefixes. The controller must generate a fresh alias for every new
reservation and fence the returned key against its current generation.

`AdminKeyJournal` belongs in the existing `:controller` process and uses its own
static writer lock. The fixed production AES-GCM alias is
`syn443-admin-store-v1`; it is separate from device login, bootstrap trust and
chat storage. Files live under `no_backup/admin-login/<namespace>/owner.bin`.
The AEAD domain and namespace are authenticated. Both disk and Keystore work are
worker-only. A plaintext record is bounded to 4096 bytes and the versioned
12-byte-IV/16-byte-tag frame to 4125 bytes. Strict JSON contains exactly
`version`, `revision`, `generation`, `phase` and `alias`. The journal contains no
URLs, subject/device identifiers, grants, PKCE material or access/refresh tokens.

The only transitions are:

```text
SIGNED_OUT -> RESERVED       revision+1, generation+1, fresh owned alias
RESERVED -> BROWSER          revision+1, same generation and alias
BROWSER -> AUTHENTICATED     revision+1, same generation and alias
any active -> RETIRING       revision+1, generation+1, same alias
RETIRING -> SIGNED_OUT       revision+1, same generation, empty alias
```

Version is 1, counters are safe nonnegative integers, and alias is empty exactly
when signed out. Exact expected-record CAS rejects stale writers; no reset,
erase-file or same-phase revision API exists. A pristine absent namespace reads
as initial signed-out metadata without creating a key or file. An existing empty
directory, orphaned `.new`, invalid frame, missing AES key, wrong namespace or
malformed record fails closed. Normal AtomicFile backup recovery preserves the
last committed record. Every write independently reads back the full record;
I/O or crypto failure cannot be reported as a successful commit.

The controller must persist `RESERVED` before key creation. Startup with any
active record has no recoverable credentials: persist `RETIRING`, delete only its
exact owned alias, then commit `SIGNED_OUT` before a new sign-in. A crash during
retirement retains the alias for retry. Journal operations never delete signing
keys or modify VPN/device state. Finishing retirement remains a controller
responsibility, not something a journal record can prove by itself.

Seven new `AdminKeyJournalTest` methods exercise real Android Keystore and
AtomicFile state: non-exportable signing and a preserved synthetic device-key
sentinel; recreated ownership-only phases; stale CAS/invalid transitions;
tamper/truncation/oversize/namespace substitution; missing-key/orphan/backup
recovery; main/Binder/foreign-alias rejection; and blocked creation ordered
against persisted retirement and owned deletion. Fixture namespaces and exact
fixture AES aliases are isolated. The test factory requires DEBUG,
ranchu/goldfish and a `test-` namespace, and never selects the production AES
alias. Cleanup deletes only exact fixture aliases/files.

All executable checks and builds belong in GitHub Actions. These emulator-only
fixtures must not run on a physical Xperia. Source preparation is not CI,
physical acceptance, administrative login or proof that the controller lifecycle
has been integrated. Durable credential recovery, server revocation and device
identity mutation are deliberately absent.
