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

## HTTPS App Links

The manually dispatched Android Actions build reads the repository variable
`SYN443_PUBLIC_ENROLLMENT_LINK_HOST`. Set it only to an explicitly public
hostname. Generic builds use the reserved `links.example.invalid` fixture.
The APK declares `/syn443/enroll` for Android domain verification. The public host
must serve a Digital Asset Links statement for the exact app package and signing
certificate. [Android intent filters](https://developer.android.com/training/app-links/add-applinks)

Share `https://HOST/syn443/enroll#` followed by the original `syn443://enroll/v1`
invitation. The web request omits the fragment. The client accepts only the
configured HTTPS host and exact path. The inner invitation must pass the same
bounded parser and installation-root verification as a direct link or QR. A
valid incoming Intent fills the private preview field. Binding still requires
the user's confirmation and the independent server approval. Browser fallback
and Android domain association need a real deployed host for acceptance.

## Managed first launch

A manually dispatched Actions build can embed an explicitly public installation
profile from the control plane's offline `enrollment-admin bootstrap-profile`
command. Supply the base64url profile through the masked Actions input
`SYN443_PUBLIC_INSTALLATION_PROFILE`. The input contains the public installation
anchor and its signed service descriptor. The build checks the decoded public
payload before compilation. No private root key is used by the Android build.

On a fresh managed installation the normal Keycloak button uses the embedded
descriptor after local signature, expiry and revision-floor validation. The
same root also verifies invitations. The encrypted trust journal binds its
rotation history to the original installed anchor. Existing enrolled sessions
keep their protected authority. A damaged local override or trust journal
fails closed. Configure and physically verify the real signed managed APK
separately from generic Actions builds.

An APK may carry a version 2 profile with the next installation anchor, a
descriptor signed by that anchor and a dual-signed proof from the previous APK
anchor. On an existing installation, the worker checks the stored anchor binding,
the transition window and the descriptor revision before committing the new root
and service floors in one encrypted write. An unrelated transition or an expired
transition the client has never accepted leaves the journal intact. An APK carrying the previous root can no longer read
the migrated journal. Existing enrolled sessions retain their own authority.

A clean installation uses the root from its signed APK. Once migration succeeds,
a later APK can use a normal version 1 profile signed by the new root. A client
that misses the transition window needs a separately trusted recovery release.
The automated tests cover the journal and profile formats. A signed update on
the configured release device remains a separate acceptance check.
