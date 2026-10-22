#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
work="$root/native/build"
mkdir -p "$work"
python3 - "$root/native" "$work" <<'PY'
import hashlib,json,pathlib,subprocess,sys
root,work=map(pathlib.Path,sys.argv[1:])
lock=json.loads((root/'engine-lock.json').read_text())
for name,source in lock['sources'].items():
    patch=(root/'patches'/f'{name}.patch').read_bytes()
    assert hashlib.sha256(patch).hexdigest()==source['patchSha256']
    target=work/name
    if not (target/'.git').is_dir():
        subprocess.run(['git','init',str(target)],check=True,stdout=subprocess.DEVNULL)
        subprocess.run(['git','-C',str(target),'fetch','--depth=1',source['url'],source['base']],check=True)
        subprocess.run(['git','-C',str(target),'checkout','--detach','FETCH_HEAD'],check=True)
        if patch: subprocess.run(['git','-C',str(target),'apply','--binary','-'],input=patch,check=True)
    if name=='sing-box':
        compat=(root/'patches/http2-compat.patch').read_bytes()
        assert hashlib.sha256(compat).hexdigest()==lock['compatibilityPatchSha256']
        test=subprocess.run(['git','-C',str(target),'apply','--check','-'],input=compat,capture_output=True)
        if test.returncode==0: subprocess.run(['git','-C',str(target),'apply','-'],input=compat,check=True)
        else: subprocess.run(['git','-C',str(target),'apply','--reverse','--check','-'],input=compat,check=True)
PY
mkdir -p "$work/bridge"
gofmt -w "$root"/native/bridge/*.go "$root"/native/engine-netbird/*.go
cp -R "$root/native/engine-netbird" "$work/"
cp "$root"/native/bridge/*.go "$root"/native/bridge/go.mod "$root"/native/bridge/go.sum "$work/bridge/"
cd "$work/bridge"
export GOMAXPROCS="${GOMAXPROCS:-2}" GOFLAGS="-p=1" GOTOOLCHAIN=local
export GOMEMLIMIT="${GOMEMLIMIT:-1400MiB}" GOGC="${GOGC:-50}"
export GOMODCACHE="$(go env GOPATH)/pkg/mod"
export PATH="$(go env GOPATH)/bin:$PATH"
go install github.com/sagernet/gomobile/cmd/gomobile@v0.1.12
go install github.com/sagernet/gomobile/cmd/gobind@v0.1.12
export GOBIND="$(go env GOPATH)/bin/gobind"
go mod tidy
go get github.com/sagernet/gomobile/bind@v0.1.12
gofmt -w ./*.go
go test -tags=with_gvisor,with_utls,with_quic ./... io.syn443/engine-netbird
if [ "${SYN443_RACE:-0}" = 1 ]; then
    go test -race -tags=with_gvisor,with_utls,with_quic ./... io.syn443/engine-netbird
fi
go test github.com/netbirdio/netbird/client/internal/peer -run 'Test(DirectFirstDefersRelayUntilUnreachable|SuccessfulP2PDoesNotOpenRelayUntilLost|DirectFirstWaitCancelsWithEngine)$' -count=1
go test github.com/netbirdio/netbird/client/underlay -count=1
go test github.com/netbirdio/netbird/client/underlaytest -run '^TestControlAndRelayUseOnlyUnderlay$' -count=1
gomobile bind -target=android/arm64,android/amd64 -androidapi=29 -trimpath -tags=with_gvisor,with_utls,with_quic -ldflags='-checklinkname=0 -s -w -linkmode=external -extldflags=-Wl,-z,max-page-size=16384' -o "$work/engine.aar" .
cp go.mod go.sum "$root/native/bridge/"
echo 'Embedded engine AAR built from pinned source'
