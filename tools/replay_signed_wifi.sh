#!/usr/bin/env bash
set -euo pipefail
test "$GITHUB_ACTIONS" = true
test "$SYN443_CI_AVD" = syn443-ci
test "$(adb -e emu avd name | head -n 1 | tr -d '\r')" = syn443-ci
adb -e install "$RUNNER_TEMP/wifi-replay/app-debug.apk"
adb -e install "$RUNNER_TEMP/wifi-replay/app-debug-androidTest.apk"
adb -e shell appops set io.syn443.android ACTIVATE_VPN allow
python3 tools/run_enrolled_vpn.py --wifi-only
