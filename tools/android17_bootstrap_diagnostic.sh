#!/usr/bin/env bash
set -euo pipefail
adb shell getprop ro.build.version.sdk
adb shell df -h /data
for attempt in 1 2 3 4 5 6; do
  echo "health iteration $attempt"
  adb shell pidof system_server || true
  adb shell service check package || true
  adb shell service check settings || true
  sleep 10
done
adb logcat -b crash -d
adb logcat -d -s AndroidRuntime SystemServer Watchdog PackageManager
adb shell service list
