#!/usr/bin/env bash
set -euo pipefail

collect_diagnostics() {
  result=$?
  trap - EXIT
  python3 tools/print_emulator_reports.py || true
  printf '\n=== Disposable runner memory/disk ===\n'
  free -m || true
  df -h / || true
  sudo dmesg | tail -80 | sed -n '/[Oo]ut of memory\|[Kk]illed process\|oom-kill/p' || true
  printf '\n=== Android crash buffer (diagnostics only) ===\n'
  timeout 20s adb logcat -b crash -d || true
  printf '\n=== Android service state (diagnostics only) ===\n'
  timeout 10s adb shell service list || true
  exit "$result"
}
trap collect_diagnostics EXIT

adb shell getprop ro.build.version.sdk
adb shell df -h /data
# Disposable emulator only: prove the app stays dark with light system settings.
adb shell cmd uimode night no
test -f app/build/outputs/apk/debug/app-debug.apk
test -f app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk
adb install -r app/build/outputs/apk/debug/app-debug.apk
# Permission changes happen before the instrumentation process exists.
adb shell appops set io.syn443.android ACTIVATE_VPN allow
if [ "$(adb shell getprop ro.build.version.sdk | tr -d '\r')" -ge 33 ]; then
  adb shell pm grant io.syn443.android android.permission.POST_NOTIFICATIONS
fi
result=0
# Capture the actual failing assertion before long native fault scenarios. A
# failed instrumentation run cannot satisfy the mandatory evidence gate anyway.
if ! ./gradlew :app:connectedDebugAndroidTest --info --stacktrace --max-workers=1 '-Dorg.gradle.jvmargs=-Xmx768m -XX:MaxMetaspaceSize=384m -XX:ActiveProcessorCount=2 -Dfile.encoding=UTF-8'; then
  python3 tools/print_emulator_reports.py || true
  exit 1
fi
# The Gradle runner uninstalls both APKs when its suite ends. External enrollment
# also needs its own-UID driver, which exists exclusively in the test APK.
adb install -r app/build/outputs/apk/debug/app-debug.apk
adb install -r app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk
adb shell appops set io.syn443.android ACTIVATE_VPN allow
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

