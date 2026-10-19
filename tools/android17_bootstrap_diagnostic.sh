#!/usr/bin/env bash
set -euo pipefail
collect() {
  result=$?
  trap - EXIT
  python3 tools/print_android17_reports.py || true
  timeout 20s adb logcat -b crash -d || true
  timeout 20s adb logcat -d -s AndroidJUnitRunner TestRunner ActivityManager AndroidRuntime || true
  exit "$result"
}
trap collect EXIT
adb shell getprop ro.build.version.sdk
adb shell df -h /data
./gradlew :app:connectedDebugAndroidTest --info --stacktrace
python3 tools/check_test_evidence.py emulator
