# Accepted v90 source, main and USB/Wi-Fi checkpoint

This is a dated acceptance snapshot, not a statement about every later build
or current service health. Physical readback was accepted on2026-11-17.
The full specification and unaccepted paths remain open.

## Source and artifact provenance

Exact v90 / `0.9.62-admin-reconcile` source
`c2a549b9a4ad2609bc69bab3caf54af29899a8e7` passed all8 mandatory jobs in
[Actions44012133076](https://github.com/nd4y/syn443-android/actions/runs/44012133076).
Independent archive SHA-256/CRC and source-name parsing confirmed498 JVM cases,
337 identity cases,427 unique passing outcomes on each API29/35/37,104 required
classes at90% coverage or above, and53 native roots in ordinary and race runs.
All declared required outcomes were actual passes; foreign names or packages
could not substitute for them.

Protected integration `2ca75cab1c9137008d49aab623967f0e0ea8e08f` passed all8 jobs
in [main44018639542](https://github.com/nd4y/syn443-android/actions/runs/44018639542)
with the same source tree. The installed APK came from the accepted candidate
Actions artifact. Both native ABIs, the six declared source inputs and exact
artifact hashes were verified. Local operations only applied the existing
development signer; every non-signature APK payload entry remained identical.
There was no local product build.

## Actual phone acceptance

The USB test Xperia stayed on Wi-Fi with airplane mode enabled. An encrypted
pre-install recovery checkpoint and old accepted APK remained available.

The physical run passed79 unique outcomes:20 original cases and59 administrator
presentation cases (13 earlier presentation,19 editor,16 comparison and11
operation-outcome cases). The eighteen new authority/storage/coordinator
fixtures remained CI-only. These presentation cases use controlled values;
they do not authenticate an administrator or publish a server configuration.

The same run exercised two real Wi-Fi loss/return cycles and an actual native
process failure. The replacement process, application's TUN/UID ownership,
shell UID routing and independent HTTPS204 were checked. Original key/binding,
configuration, telemetry consent and system settings were preserved. All15
cleanup steps passed, the test package was removed, and the accepted application
finished Online. A separate read-only verifier parsed all79 unique raw outcomes
and checked the fresh installed APK hash, active VPN and preserved state.

The earlier v89 receipt retains its68-case scope. It is not substituted for
the v90 installation or eleven new presentation outcomes.

## Remaining acceptance

Version91 search-status source later passed its own437-per-API candidate CI;
its resulting-main, delivery and real managed adaptive chain need separate
receipts. The ten new coordinator/snapshot simulations are not phone tests.

Real native administrator SSO, server ACL/MFA, edit/preview/publish and live
lost-response reconciliation remain open. No permission expansion, new OIDC
client, SQL restore, signed managed chain or live feature enablement was
performed by this phone run. Full XHTTP/other protocol combinations, four-mode
autonomous routing and complete version1.0 operations remain separate gates.

LTE/restricted LTE and Wi-Fi/LTE transitions were excluded. Natural Doze,
unplugged battery and endurance are unverified. Device identifiers, private
addresses, credentials, signing material, configurations, backups and raw
device evidence remain outside the public repository.
