# Private structured lifecycle journal

This candidate continues LOG02/03 after the offline archive component. It is
not full logging, crash collection, debug/trace consent or remote support.
All executable validation belongs in GitHub Actions. Physical USB/Wi-Fi
preservation and real export remain separate gates; LTE is excluded.

## Closed input

Use the existing core/observability module for typed lifecycle records. Phase,
code, channel and severity are finite catalog values; unknown inputs become
fixed redacted/unknown values. No arbitrary message, exception, path, header,
URL, subscription, label, identity, network name or nested object is accepted.
The remaining fields are bounded numeric times/generations and a local random
correlation ID. The same projection is applied at event admission and export.
Old state events remain a bounded compatibility source, not a raw-log source.

## Actual writer and retention

Only :controller owns one actual writer. Producer admission does no disk or
Keystore work and has a queue of64 records with a saturating loss counter.
Writes are batched with a minimum interval of 500 ms. A blocked writer retains its
slot; neither cancellation nor timeout admits another writer. Failure drops
bounded diagnostic data and cannot block, restart or reconfigure the VPN.
The writer counts late records it cannot append in chronological order.
Export marks known loss as partial and displays a source error if the writer
has failed and no records are available.

Each immutable sealed segment is AES-GCM encrypted with one journal-specific
Android Keystore AES alias, shared only by this journal and distinct from VPN,
device and authentication keys. Its count is one, not one key per segment.
Encryption uses filename-bound AAD. Credential storage/noBackup only. Files
are owned regular files under one fixed directory, opened without following
symlinks. Payloads/paths/keys are never included in errors or logs. Bounds:
64KiB for the whole encrypted frame (including its header, nonce and tag),
64MiB total including temporary ciphertext,1023 sealed files plus at most one
owned temporary file,7days maximum readable age. Before creating a temporary
file the writer reserves both its complete byte bound and its sealed-file
slot; any required owned victim is authenticated and retired first. It never
temporarily exceeds either limit. Each admission prunes at most eight owned
segments. In routine writes it decrypts only the most recent clock anchor.
Pruning inspects up to seven additional candidates. Foreign entries are
never recursively deleted; invalid ownership or namespace fails closed.

Each frame authenticates the committed flush clock and the first event clock;
filename boot/elapsed fields must match the committed clock. Startup/passive
reads authenticate the latest current-boot frame as the persisted high-water,
never replace it with fresh RAM time, and fail closed on a corrupt/missing
anchor. Retention accepts only same-boot monotonic time with nondecreasing
wall time against that committed anchor. A detected same-boot rollback denies
append/export and all pruning, preserves its durable high-water witnesses,
and cannot begin a new epoch until time is trustworthy again. With no current-boot frame,
the first writer may begin a new local epoch; old-boot frames remain excluded
and cannot become that epoch's observation authority.
An app-process restart on the same boot retains valid history. A new boot
makes old age unverifiable: passive readers omit those old-boot records;
the next writer admissions conservatively retire only authenticated owned
old-boot segments within the same bounded prune budget. This is an explicit
privacy reset on unverifiable age, not a claim to know the old wall-clock age.
The sole exception is one matching owned0600 inode-checked `.tmp` scratch
frame: only the writer may discard it without decrypting it. It was never
sealed, read/exported or a committed clock witness. A rollback cannot remove
a sealed floor through this scratch rule.
Physical ciphertext removal is best-effort while the application can run;
seven days is an access limit, not an autonomous OS deletion promise. It never
restamps old events or promotes their observations into route authority.

## Passive archive projection

The archive worker may return at most64KiB of recent valid structured JSONL.
One invocation enumerates at most1024 directory entries and opens/decrypts at
most eight sealed frames (512KiB ciphertext total), chosen by provisional
same-boot filename order. It authenticates filenames and embedded metadata
before trusting any event. More history, exhausted budgets or invalid entries
produce explicit incomplete/unavailable results; there is no full-scan or
fallback decrypt loop. The metadata enumeration never follows foreign paths.
Every writer and passive reader instance shares one publication fence. It
marks writes before any IO, retains a blocked actual writer, and rejects and
clears stale read results if a new commit/attempt overlapped their capture.
Its short lock contains no filesystem, Keystore or network operation.
Reading creates no key/file/directory, performs no cleanup or source sampling,
does not change VPN intent or telemetry consent, and does not upload anything.
Missing key, locked storage, malformed/corrupt ciphertext, races and partial
coverage are explicit unavailable/error/truncated results. All plaintext
passes through the closed codec again before export. Persistent log records
never become fresh health observations.

## Required checks

Cover exact enum/numeric/correlation and size boundaries, injected test secrets,
unknown fields, same-boot restart, age limits, wall rollback/new boot, corrupt
and partial ciphertext, symlink/foreign files, queue overload, blocked actual
writer ownership, failure isolation and passive-read immutability. Preserve
all old test names/assertions, coverage, contracts and public-data gates.

Actions requires 12 new JVM outcomes and 12 new tests on each Android API 29,
35 and 37 emulator. The 524 existing Android outcomes remain required, for a
total of at least 536 per API. The existing 90% observability coverage rule
also applies. This change still needs exact-commit CI and physical acceptance.
