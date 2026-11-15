# Bounded assignment JSON - quoted-string allocation

API 29 in Actions `43687790712` exposed an actual pre-output allocation in
`LoginJournal.prepareAssignment`. The unchanged full-size
`assignmentEscapedByteOverflowLeavesItsPreviousCiphertextAndReceiptIntact` case
requires a redacted storage failure without replacing the prior ciphertext.
Instead, `OutputStreamJsonWriter.ensureTotalCapacity` tried to allocate
7,519,984 bytes while escaping a 400,000-character string, before the bounded
output received that string. The process reported a 16 MiB growth limit even
though the preflight Android properties reported 512 MiB. Property readback does
not prove the heap limit captured by an already running ART process.

The former chunked output prevented a complete plaintext concatenation but could
not bound this serializer-internal string allocation. The new typed storage
encoder streams each quoted character into a fixed 8 KiB buffer. It follows the
generated serializers' field order and default/optional-field decisions, writes
explicit nulls and booleans, and supports integer/list/object values and strict
UTF-8. Unsupported future structural/numeric kinds and malformed UTF-16 fail
closed. All temporary bytes are wiped, including exceptional exits. The existing
2 MiB limit, encryption scope/AAD, atomic replacement, cancellation fences and
v1 nonce/ciphertext/tag layout are retained. No out-of-memory error is swallowed.

The canonical readback comparison uses the same bounded writer. Independent
reference bytes still come from the previous JSON serializer on small samples:
all control escapes, BMP and supplementary Unicode, optional/default fields,
populated activation report, lists, integers, booleans and nulls. The original
400,000-control-character overflow, large three-snapshot encrypted roundtrip and
legacy ciphertext comparisons remain mandatory. New exact-head Actions and
existing encrypted-assignment readback on Xperia are pending acceptance.

The dark-theme test independently allocated a complete second screen-sized pixel
array to inspect one background pixel. It now reads the same single pixel into a
1x1 array and keeps the original luminance and title contrast assertions. The
full screenshot/title rendering and UI assertion still run.

No local suites or APK builds are used. This correction is separate from the
chat root-attachment race boundary documented in `chat-startup-layout.md`; a
successful new run must not be called permanent proof of the earlier Compose
reentrant traversal's full cause.
