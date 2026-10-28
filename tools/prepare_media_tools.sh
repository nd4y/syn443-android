#!/usr/bin/env bash
set -euo pipefail
# GitHub's Azure HTTP mirror delivered a measured 9MB package in >3 minutes.
# Use signed Ubuntu archives directly, without changing the runner's global sources.
source /etc/os-release
test "$ID" = ubuntu && test "$VERSION_CODENAME" = noble
sources=$(mktemp "${RUNNER_TEMP:?}/syn443-ubuntu-XXXXXX.sources")
trap 'rm -f -- "$sources"' EXIT
cat > "$sources" <<'SOURCES'
Types: deb
URIs: https://archive.ubuntu.com/ubuntu/
Suites: noble noble-updates
Components: main universe
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg

Types: deb
URIs: https://security.ubuntu.com/ubuntu/
Suites: noble-security
Components: main universe
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg
SOURCES
apt_options=(-o Dir::Etc::sourceparts=- -o "Dir::Etc::sourcelist=$sources" -o Acquire::Retries=2 -o Acquire::http::Timeout=20 -o Acquire::https::Timeout=20 -o Acquire::ForceIPv4=true)
timeout 180s sudo apt-get "${apt_options[@]}" update
timeout 300s sudo apt-get "${apt_options[@]}" install -y --no-install-recommends ffmpeg
ffmpeg -version
