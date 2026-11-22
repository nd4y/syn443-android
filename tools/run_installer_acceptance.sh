#!/usr/bin/env bash
set -euo pipefail

test "${GITHUB_ACTIONS:-}" = true
test "${SYN443_CI_AVD:-}" = syn443-ci
test "$(adb -e emu avd name | tr -d '\r')" = $'syn443-ci\nOK'
test "$(adb -e shell getprop ro.build.version.sdk | tr -d '\r')" = 35
case "$(adb -e shell getprop ro.hardware | tr -d '\r')" in
  ranchu|goldfish) ;;
  *) exit 1 ;;
esac
# A new emulator has no installed identity. The run never receives a real account.
test -z "$(adb -e shell pm list packages --user 0 io.syn443.android | tr -d '\r')"
adb -e install "$RUNNER_TEMP/base-debug.apk"
adb -e install -t app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk
adb -e shell appops set io.syn443.android ACTIVATE_VPN allow
adb -e shell pm grant io.syn443.android android.permission.POST_NOTIFICATIONS
original=$(adb -e shell settings get global stay_on_while_plugged_in | tr -d '\r')
restore_display() {
  if [[ "$original" == null ]]; then adb -e shell settings delete global stay_on_while_plugged_in
  else adb -e shell settings put global stay_on_while_plugged_in "$original"; fi
}
trap restore_display EXIT
adb -e shell settings put global stay_on_while_plugged_in 7
adb -e shell input keyevent KEYCODE_WAKEUP
adb -e shell wm dismiss-keyguard
python3 tools/run_enrolled_vpn.py --system-installer
