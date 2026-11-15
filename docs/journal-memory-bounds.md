# Assignment journal memory bounds

The documentation-only integration run43657705343 reproduced a real storage
boundary defect on API29: `assignmentBoundsOrphansMissingReceiptsAndWrongThreadFailClosed`
expected a bounded storage rejection, but the JSON String writer first requested
an8389616-byte array with about4.4MiB free in a16MiB heap. The journal checked its
2MiB UTF-8 limit after full String encoding. A preceding successful matrix and
physical connectivity did not prove that oversized input was safely handled.

The writer now enforces the same byte cap while streaming JSON into bounded8KiB
plaintext chunks. AES-GCM consumes chunks into the final ciphertext array. All
plaintext chunks are wiped on exit, including overflow and crypto errors. It does
not catch an out-of-memory error and present it as a normal rejection.

The reader allocates from the opened file's checked size instead of its maximum
limit and an additional full copy. It detects truncation/growth, decrypts without
a ciphertext slice, decodes from a byte stream and compares canonical output
incrementally. Identity, generation, namespace, trust/AAD and atomic-commit fences
are retained. The v1 nonce/ciphertext/tag layout and2MiB limit remain unchanged.

Mandatory emulator regressions include the original overflow case, JSON escaping
that exceeds the byte cap while its character count fits, a large encrypted
roundtrip and exact legacy-format/Unicode comparison. All previous scenarios and
the three-API matrix remain required. Exact Actions
[run43663104984](https://github.com/nd4y/syn443-android/actions/runs/43663104984)
passed all8 jobs and228 actual outcomes per API29/35/37, zero skipped. A same-signer
v73-to-v74 physical upgrade preserved the encrypted assignment, device key,
binding, intent and configuration. Native/controller faults and Wi-Fi loss/return
recovered with active VPN and independent HTTPS204. See the scoped
[non-LTE evidence](non-lte-acceptance-20261115.md); full-protocol, cellular,
energy and endurance acceptance remain open.

The same integration run failed an API37 direct-boot fixture when `uiautomator`
did not produce a hierarchy file. Observation now removes its own stale file and
retries only hierarchy acquisition within a25-second/three-attempt budget, on a
disposable emulator only. It never repeats PIN input. Readiness retries, invalid
roots and physical-device refusal have separate Python checks; actual reboot,
locked-storage and VPN-recovery assertions remain mandatory.
