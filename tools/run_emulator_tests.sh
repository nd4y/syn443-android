#!/usr/bin/env bash
set -euo pipefail

collect_diagnostics() {
  result=$?
  trap - EXIT
  printf '\n=== Android crash buffer (diagnostics only) ===\n'
  timeout 20s adb logcat -b crash -d || true
  printf '\n=== Android service state (diagnostics only) ===\n'
  timeout 10s adb shell service list || true
  exit "$result"
}
trap collect_diagnostics EXIT

adb shell getprop ro.build.version.sdk
adb shell df -h /data
./gradlew :app:connectedDebugAndroidTest --stacktrace
python3 tools/check_test_evidence.py emulator

