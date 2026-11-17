#!/usr/bin/env bash
# Actions-only lifetime owner for a generated, unpublished Go wire specimen.
set -euo pipefail
if [[ "${GITHUB_ACTIONS:-}" != true || "${RUNNER_TEMP:-}" != /* || "${RUNNER_TEMP:-}" == / || ! -d "$RUNNER_TEMP" || -L "$RUNNER_TEMP" || "$#" -lt 1 || "$1" != ./gradlew ]]; then
  echo 'operation_conformance_admission_failed' >&2
  exit 1
fi
case " $* " in
  *' :core:identity:check '*|*' :core:identity:test '*) ;;
  *) echo 'operation_conformance_identity_command_required' >&2; exit 1 ;;
esac
umask 077
SYN443_OPERATION_SOURCE_SHA=164347d5c387d05077f43dde07f677d2bc6de47a
SYN443_OPERATION_OWNED="$(mktemp -d "${RUNNER_TEMP}/syn443-operation-wire.XXXXXXXX")"
SYN443_OPERATION_FIXTURE="$SYN443_OPERATION_OWNED/operations.json"
export SYN443_OPERATION_SOURCE_SHA SYN443_OPERATION_OWNED SYN443_OPERATION_FIXTURE
readonly SYN443_OPERATION_SOURCE_SHA SYN443_OPERATION_OWNED SYN443_OPERATION_FIXTURE
cleanup_operation_conformance() {
  local status=$?
  trap - EXIT
  if ! rm -rf -- "$SYN443_OPERATION_OWNED"; then
    if [[ "$status" -eq 0 ]]; then status=1; fi
  fi
  exit "$status"
}
trap cleanup_operation_conformance EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
python3 - <<'PY'
import io
import os
from pathlib import Path, PurePosixPath
import tarfile
import urllib.request

source = os.environ['SYN443_OPERATION_SOURCE_SHA']
assert source == '164347d5c387d05077f43dde07f677d2bc6de47a'
owned = Path(os.environ['SYN443_OPERATION_OWNED'])
runner = Path(os.environ['RUNNER_TEMP']).resolve(strict=True)
assert owned.is_dir() and not owned.is_symlink() and owned.parent.resolve(strict=True) == runner
assert owned.name.startswith('syn443-operation-wire.')
url = 'https://codeload.github.com/nd4y/syn443-control-plane/tar.gz/' + source
request = urllib.request.Request(url, headers={'Accept': 'application/gzip', 'User-Agent': 'syn443-operation-conformance'})
try:
    with urllib.request.urlopen(request, timeout=60) as response:
        assert response.geturl() == url and response.status == 200
        archive = response.read(16 * 1024 * 1024 + 1)
    assert 0 < len(archive) <= 16 * 1024 * 1024
    prefix = 'syn443-control-plane-' + source
    destination = owned / 'source'
    destination.mkdir(mode=0o700)
    files = set()
    total = 0
    with tarfile.open(fileobj=io.BytesIO(archive), mode='r:gz') as bundle:
        for index, member in enumerate(bundle):
            assert index < 10000 and (member.isdir() or member.isfile())
            name = PurePosixPath(member.name)
            assert not name.is_absolute() and name.parts and name.parts[0] == prefix
            assert all(part not in ('', '.', '..') and '\\' not in part for part in name.parts)
            relative = name.parts[1:]
            if not relative:
                assert member.isdir()
                continue
            path = destination.joinpath(*relative)
            if member.isdir():
                path.mkdir(mode=0o700, parents=True, exist_ok=True)
                continue
            assert 0 <= member.size <= 4 * 1024 * 1024 and member.name not in files
            total += member.size
            assert total <= 64 * 1024 * 1024
            files.add(member.name)
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            stream = bundle.extractfile(member)
            assert stream is not None
            with stream, path.open('xb') as output:
                value = stream.read(member.size + 1)
                assert len(value) == member.size
                output.write(value)
    assert (destination / 'cmd/layer-fixture/operations.go').is_file()
    assert (destination / 'go.mod').read_text(encoding='utf-8').splitlines()[0] == 'module github.com/nd4y/syn443-control-plane'
except Exception:
    raise SystemExit('operation_conformance_source_unavailable')
PY
if [[ "$(go env GOVERSION)" != go1.27.4 ]]; then
  echo 'operation_conformance_go_version_mismatch' >&2
  exit 1
fi
(
  cd "$SYN443_OPERATION_OWNED/source"
  GOTOOLCHAIN=local GOWORK=off go run -mod=readonly ./cmd/layer-fixture --operations > "$SYN443_OPERATION_FIXTURE"
)
python3 - <<'PY'
import os
from pathlib import Path
path = Path(os.environ['SYN443_OPERATION_FIXTURE'])
assert path.is_file() and not path.is_symlink() and 0 < path.stat().st_size <= 65536, 'operation_conformance_fixture_missing_or_unbounded'
PY
# Preserve the original Gradle command/status. Do not exec: EXIT owns cleanup.
set +e
"$@"
status=$?
set -e
exit "$status"
