#!/usr/bin/env bash
set -euo pipefail

case "$(adb -e shell getprop ro.hardware | tr -d '\r')" in
  ranchu|goldfish) ;;
  *) echo 'Refusing tests outside the disposable emulator'; exit 1 ;;
esac

instrumentation_display=''
restore_instrumentation_display() {
  if [ -n "$instrumentation_display" ]; then
    if [ "$instrumentation_display" = null ]; then
      adb -e shell settings delete global stay_on_while_plugged_in
    else
      adb -e shell settings put global stay_on_while_plugged_in "$instrumentation_display"
    fi
    instrumentation_display=''
  fi
}

collect_diagnostics() {
  result=$?
  trap - EXIT
  restore_instrumentation_display || true
  python3 tools/print_emulator_reports.py || true
  printf '\n=== Disposable runner memory/disk ===\n'
  free -m || true
  df -h / || true
  sudo dmesg | tail -200 | sed -n '/[Oo]ut of memory\|[Kk]illed process\|oom-kill\|segfault\|general protection\|qemu-system/p' || true
  ps -C qemu-system-x86_64 -o pid=,stat=,rss=,etimes=,comm= || true
  if [ -f "$RUNNER_TEMP/syn443-preserved-emulator.log" ]; then tail -40 "$RUNNER_TEMP/syn443-preserved-emulator.log"; fi
  printf '\n=== Android crash buffer (diagnostics only) ===\n'
  timeout 20s adb -e logcat -b crash -d || true
  printf '\n=== Android service state (diagnostics only) ===\n'
  timeout 10s adb -e shell service list || true
  exit "$result"
}
trap collect_diagnostics EXIT

adb -e shell getprop ro.build.version.sdk
python3 tools/check_emulator_heap.py
adb -e shell df -h /data
# Disposable emulator only: prove the app stays dark with light system settings.
adb -e shell cmd uimode night no
test -f app/build/outputs/apk/debug/app-debug.apk
test -f app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk
adb -e install -r app/build/outputs/apk/debug/app-debug.apk
# Permission changes happen before the instrumentation process exists.
adb -e shell appops set io.syn443.android ACTIVATE_VPN allow
if [ "$(adb -e shell getprop ro.build.version.sdk | tr -d '\r')" -ge 33 ]; then
  adb -e shell pm grant io.syn443.android android.permission.POST_NOTIFICATIONS
fi
# Compose needs a visible root for UI assertions. Keep this fixture's screen
# awake only for instrumentation; the later lifecycle scenarios own their
# display, lock, reboot and idle conditions separately.
screen_original="$(adb -e shell settings get global stay_on_while_plugged_in | tr -d '\r')"
[[ "$screen_original" = null || "$screen_original" =~ ^[0-9]+$ ]]
instrumentation_display="$screen_original"
adb -e shell settings put global stay_on_while_plugged_in 7
adb -e shell input keyevent KEYCODE_WAKEUP
adb -e shell wm dismiss-keyguard
result=0
# Capture the actual failing assertion before long native fault scenarios. A
# failed instrumentation run cannot satisfy the mandatory evidence gate anyway.
if ! ./gradlew :app:connectedDebugAndroidTest --info --stacktrace --max-workers=1 '-Dorg.gradle.jvmargs=-Xmx768m -XX:MaxMetaspaceSize=384m -XX:ActiveProcessorCount=2 -Dfile.encoding=UTF-8'; then
  python3 tools/print_emulator_reports.py || true
  exit 1
fi
restore_instrumentation_display
# The Gradle runner uninstalls both APKs when its suite ends. External enrollment
# also needs its own-UID driver, which exists exclusively in the test APK.
adb -e install -r app/build/outputs/apk/debug/app-debug.apk
adb -e install -r app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk
adb -e shell appops set io.syn443.android ACTIVATE_VPN allow
# Fail early on the new OS scenarios. Missing old outcomes can never pass the
# final evidence gate; successful runs still execute every previous scenario.
if ! python3 tools/run_route_lifecycle.py; then
  python3 tools/print_emulator_reports.py || true
  exit 1
fi
python3 tools/run_vpn_process_faults.py || result=1
python3 tools/run_vpn_revocation.py || result=1
python3 tools/run_vpn_fatal.py || result=1
python3 tools/run_vpn_competing.py || result=1
python3 tools/run_policy_activation.py || result=1
python3 tools/run_enrolled_vpn.py || result=1
python3 tools/check_test_evidence.py emulator || result=1
exit "$result"

