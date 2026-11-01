# Installation trust for invitation bootstrap

`BootstrapTrust` verifies the service descriptor locally against an installation
anchor before any discovery or invitation-code transmission. A QR cannot supply
its own trusted root. The protected ES256 type, exact service/origin, root epoch,
per-service revision/hash, validity and separate online policy keys are checked.

The link form is `syn443://enroll/v1` with exactly `service`, `origin`, `code` and
`bootstrap`. Duplicate/unknown members, fragments, invalid UTF-8/encoding, versions
and oversized data fail closed. The code is not an administrative credential;
the invitation service must separately enforce one use, expiry, proof of device
key possession and administrator confirmation. Diagnostic string forms redact it.

Root transitions require the same payload signed by both old and new roots and
the exact next epoch. The caller must atomically persist the new anchor and
service floors before use. An already accepted transition can be acknowledged
again; retired roots cannot authorize fresh enrollment. Root compromise/loss
requires the independently trusted release/recovery channel.

Core JVM tests and shared Go/Kotlin vectors cover signature/key substitution,
header/type/encoding rejection, revision/expiry/replay, dual-key rotation, hostile
links and redaction. New protocol classes join the existing90% identity line gate.
The protected Android journal and camera/paste/Intent UI are integrated with
manual claim/approval/session provisioning; see [manual enrollment](manual-enrollment.md).
New Actions and physical Xperia acceptance remain open; integration alone does
not complete M2 or M3. All compilation/tests run in GitHub Actions.
