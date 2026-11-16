# Non-LTE acceptance checkpoint - 2026-11-16

This records accepted revisions, separately from newer source under development.
No private configuration, account, device identifier or physical log is included.

## Current installed checkpoint - Android v82

Source `10bfdacbb07dc98ca278517a4aaf26f599126845` passed all eight required jobs
in [Actions43859154434](https://github.com/nd4y/syn443-android/actions/runs/43859154434).
The API29/35/37 archives each contained284 unique actual Android outcomes, with
zero failures, errors or skips. All53 required native roots passed ordinary and
race execution. The exact Actions APK v82 was installed on the authorized
USB/Wi-Fi phone; this receipt does not apply to a newer APK.

The final observed-window batch produced20 actual Android outcomes: nine
UI/intent/country cases and11 coordinator cases using virtual clocks and
synthetic native reports. The latter remain simulations even when executed on
a physical phone. Two real Wi-Fi loss/return cycles each included six seconds
without Wi-Fi. An actual native-process failure recovered with fresh process
ownership, an active TUN and independent HTTPS204. Device identity/binding,
configuration, consent and authentication method were preserved; the support outbox
remained empty. Original settings and radios were restored. These were Direct
policy checks, not physical managed adaptive-chain acceptance.

The failure history remains part of this receipt. The first run recorded four
five-second chat-root timeouts while Android immediately paused each support
Activity with reason `sleep`; the other16 cases passed. The screen had switched
off before the first chat launch. A first guarded retry stopped before tests
because MainActivity was not in the foreground while an owned chat task was
retained. The second guarded attempt completed all20 cases, both Wi-Fi cycles
and native recovery, then retained a final-cleanup `RuntimeError`. Its cause is
`NOT_VERIFIED`; this is not an unqualified successful script exit or a permanent
RCA closure based on a warm rerun.

Three later read-only samples over28 seconds independently confirmed the owned
package/UID TUN, HTTPS204 and stable Online state with the same generation.
Those samples establish the actual restored runtime separately from the saved
cleanup exception. They do not identify that exception's cause or prove
unplugged endurance. The Custom Tab cases establish URL/intent behavior, not a
real browser/Keycloak/MFA session or authenticated administrator device-card
readback.

## Newer source checkpoint - Android v83

The signed administrative metadata/cache foundation source
`9d7f0ef0e5de648d875b5f438fb5357ec5abffe9` passed all eight required jobs in
[Actions43863335190](https://github.com/nd4y/syn443-android/actions/runs/43863335190).
Each API29/35/37 archive contained287 unique actual outcomes with zero failures,
errors or skips. All53 required native roots passed ordinary and race execution.
The20 newly affected mandatory JVM outcomes comprise six cursor, six admission
budget, five signed-policy and three administrative-bootstrap cases;20 is not
the total JVM suite size. The three new encrypted-cache Android cases were
accepted on emulators. This APK has not been installed on the physical phone.

The protected merge is `9a948fd3daf60f0f105027c74a3cdc7da7913bf0`, recorded at
12:59:13 UTC. Its [actual-main Actions43871522969](https://github.com/nd4y/syn443-android/actions/runs/43871522969)
passed all eight jobs with an identical source tree. This does not imply a
physical v83 installation. See [signed administrative metadata](mobile-admin-bootstrap.md).

## Administrative OAuth source - Android v84

Source `110f817ca42dbabb9afe648c465809551a95c9db` passed all eight jobs in
[Actions43876233986](https://github.com/nd4y/syn443-android/actions/runs/43876233986):
287 unique actual outcomes per API29/35/37,43 newly affected mandatory JVM
outcomes and53 native roots each ordinary/race. All outcomes passed without
failure, error or skip. An independent raw report review confirms23 new admin
OAuth cases and all eight handwritten security classes above90% line coverage.
The protected merge is `d4dd7565a836ec4d31672e6c07aa3d336e462635`; its actual-main
run and physical v84 acceptance remain separate pending gates at this snapshot.

## Current source - Android v85

The [signed discovery admission](mobile-admin-discovery.md) requires one current
verified trust snapshot before and after administrative credential operations.
The [adaptive RAM budget owner](probe-budget-owner.md) preserves debt across
native/service/coordinator recreation in the same controller process. Eleven
new JVM methods, six new Android cases and three new security-class coverage
checks are required in Actions; none have yet executed for this candidate.
The new cache fixtures remain emulator-only and retain their hardware guards.
No physical native-admin callback/session, managed chain, full common energy
governor or controller-process-death persistence is claimed.

## Earlier accepted foundation

Android [PR78](https://github.com/nd4y/syn443-android/pull/78) source
`168fa2c42aec049b01cd9eb4060cbdcc5fe77f78` passed all eight required jobs in
[Actions43824486302](https://github.com/nd4y/syn443-android/actions/runs/43824486302).
The independently checked API29/35/37 archives each contained259 unique actual
outcomes with zero failures, errors or skips. Native checks covered45 required
roots in ordinary and race suites. Its protected merge
`a1fc292d0e5651fdfefed2192debea0fc4f3ec1d` passed all eight actual-main jobs in
[Actions43832025626](https://github.com/nd4y/syn443-android/actions/runs/43832025626),
with the same accepted source tree. Earlier failures remain historical evidence.

The exact Actions APK version79/0.9.51 was installed on the authorized USB/Wi-Fi
test phone with the existing development signer. Private acceptance records
retain APK/ABI payload hashes, five route-status/country and four chat outcomes,
two real Wi-Fi loss/return cycles and recovery after an actual native-process
failure. Fresh process ownership, active TUN and independent HTTPS204 were checked.
Device key/binding, current configuration, consent and original test settings
were preserved. The installed policy was Direct: these checks do not prove a
managed adaptive chain or a new NetBird underlay.

Control Plane [PR50](https://github.com/nd4y/syn443-control-plane/pull/50) source
`136537e496fe119c9da7c1c976d271ab0c65a390` passed all eight jobs in
[Actions43827442334](https://github.com/nd4y/syn443-control-plane/actions/runs/43827442334).
The protected merge `4ff3bb3546018c9ec72b845a0e83e63cfc05ce5a` passed all eight
actual-main jobs in
[Actions43829280560](https://github.com/nd4y/syn443-control-plane/actions/runs/43829280560).
Four pilot services received verified Actions binaries; runtime and trusted-HTTPS
UI asset hashes matched. Database, gateway and owner containers, device/account
bindings and ACLs were preserved. Managed publication and the source worker were
not enabled by that binary rollout. The trusted Android-browser landing opened,
but an authenticated normal-user device card was not established by that check.

Bounded search, lease continuity and recovery-reserve simulations now have the
scoped v82/v83 evidence above. Full normal managed publication, actual
adaptive chains, shared energy/admission, home-network proof, complete mobile
administration and the remaining specification stay open. LTE, natural Doze,
unplugged battery and endurance checks are excluded from this checkpoint.
