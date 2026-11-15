# Emulator lifecycle fixture corrections

These changes run only in the disposable `syn443-ci` emulator. They do not alter
client Android lifecycle behavior, physical credentials, authorization or routes.

## Independent VPN owner

API 29, Actions `43689824037`, failed before the competing-owner scenario because
the test Activity called `startService(STOP)` from `onCreate` while its UID was
still cached/background. Android's actual exception identifies that forbidden
service start. The test APK now dispatches its one explicit action after Activity
resume and uses the foreground-service entry point for both Start and Stop. The
service fulfils its notification contract before processing Stop; it never
establishes a TUN merely to write an off marker. No background restriction,
permission or readiness assertion is bypassed.

The original driver then lost its JUnit failure when cleanup removed a reverse
mapping that had not yet been created. The finalizer now attempts every cleanup,
removes only an acknowledged owned mapping and always writes the original case.
A new cleanup failure turns an otherwise successful case into a failed result;
it cannot erase the original failure or become a skip. All original ownership,
revocation, restart-intent and no-retry-fight assertions remain mandatory. The
minimum stays 238 outcomes; the former 237 was a missing failed case, not a
reason to lower the gate.

## Reboot and preserved userdata

API 37 in Actions `43690709099` reached `RUNNING_LOCKED` after its host emulator
exited and was relaunched once, but the installed package/provider was absent.
The available evidence does not prove why it disappeared. An increased Android
boot counter alone did not establish preservation of the tested installation.

Before issuing the single real reboot, the helper now records the exact installed
APK path, digest and main-package UID, creates its own random userdata marker and
flushes the guest filesystem. After boot it must observe the same marker, APK
and UID before accepting recovery. It never creates that marker again after
reboot, reinstalls the app, wipes userdata, borrows the test-package UID, adopts
another AVD or replays the reboot. A temporary unavailable PackageManager read
may be polled within the original deadline. Changed userdata/APK/UID fail closed.

The separate locked-boot case still requires no native owner, `NeedsUnlock` and
redacted credential-backed intent before the first unlock, followed by real VPN
reconciliation. Those assertions and deadlines are retained. A marker is removed
only after successful preservation proof; a failed run retains its evidence.
The upstream host exit/disappearance is not declared a permanently resolved RCA.

Host unit cases cover failed cleanup, false success, changed userdata/APK/UID,
exact package selection, missing/duplicate UID, unchanged boot count, one-shot
host recovery and refusal of wipe/alternate-userdata options. Exact-head all-job
Actions and actual mandatory Android outcomes remain required before acceptance.
