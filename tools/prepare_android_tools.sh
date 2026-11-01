#!/usr/bin/env bash
set -euo pipefail
# setup-android pins this archive; emulator-runner prepends "latest" to PATH.
tools_dir="${ANDROID_HOME:?}/cmdline-tools"
pinned_dir="$tools_dir/15859902"
grep -Fx 'Pkg.Revision=22.0' "$pinned_dir/source.properties"
test -x "$pinned_dir/bin/avdmanager"
if [ -e "$tools_dir/latest" ] || [ -L "$tools_dir/latest" ]; then
  test ! -e "$tools_dir/latest-before-syn443"
  mv -- "$tools_dir/latest" "$tools_dir/latest-before-syn443"
fi
ln -s -- 15859902 "$tools_dir/latest"
test "$(readlink -f "$tools_dir/latest")" = "$(readlink -f "$pinned_dir")"
"$tools_dir/latest/bin/sdkmanager" --version
