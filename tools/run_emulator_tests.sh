#!/usr/bin/env bash
set -euo pipefail

collect_diagnostics() {
  result=$?
  trap - EXIT
  python3 tools/print_emulator_reports.py || true
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
./gradlew :app:assembleDebug :app:assembleDebugAndroidTest
adb install -r app/build/outputs/apk/debug/app-debug.apk
# Permission changes happen before the instrumentation process exists.
adb shell appops set io.syn443.android ACTIVATE_VPN allow
./gradlew :app:connectedDebugAndroidTest --info --stacktrace
adb install -r app/build/outputs/apk/debug/app-debug.apk
python3 tools/run_vpn_process_faults.py
python3 tools/check_test_evidence.py emulator

