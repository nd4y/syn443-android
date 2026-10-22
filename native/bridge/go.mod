module io.syn443/bridge

go 1.26.0

require (
	github.com/caddyserver/certmagic v0.25.2 // indirect
	github.com/database64128/tfo-go/v2 v2.3.2 // indirect
	github.com/go-chi/chi/v5 v5.2.5 // indirect
	github.com/godbus/dbus/v5 v5.2.2 // indirect
	github.com/gofrs/uuid/v5 v5.4.0 // indirect
	github.com/libdns/acmedns v0.5.0 // indirect
	github.com/libdns/alidns v1.0.6 // indirect
	github.com/libdns/cloudflare v0.2.2 // indirect
	github.com/logrusorgru/aurora v2.0.3+incompatible // indirect
	github.com/metacubex/utls v1.8.4 // indirect
	github.com/mholt/acmez/v3 v3.1.6 // indirect
	github.com/miekg/dns v1.1.72
	github.com/sagernet/bbolt v0.0.0-20231014093535-ea5cb2fe9f0a // indirect
	github.com/sagernet/fswatch v0.1.2 // indirect
	github.com/sagernet/gvisor v0.0.0-20250811.0-sing-box-mod.1 // indirect
	github.com/sagernet/quic-go v0.59.0-sing-box-mod.4 // indirect
	github.com/sagernet/sing v0.8.10
	github.com/sagernet/sing-mux v0.3.4 // indirect
	github.com/sagernet/sing-quic v0.6.1 // indirect
	github.com/sagernet/sing-tun v0.8.10
	github.com/sagernet/sing-vmess v0.2.8-0.20250909125414-3aed155119a1 // indirect
	github.com/sagernet/smux v1.5.50-sing-box-mod.1 // indirect
	github.com/sagernet/ws v0.0.0-20231204124109-acfe8907c854 // indirect
	github.com/vishvananda/netns v0.0.5 // indirect
	go.uber.org/zap v1.27.1 // indirect
	go4.org/netipx v0.0.0-20231129151722-fdeea329fbba // indirect
	golang.org/x/crypto v0.55.0 // indirect
	golang.org/x/exp v0.0.0-20260410095643-746e56fc9e2f // indirect
	golang.org/x/mod v0.39.0 // indirect
	golang.org/x/net v0.58.0 // indirect
	golang.org/x/sync v0.23.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	google.golang.org/grpc v1.80.0 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)

//replace github.com/sagernet/sing => ../sing

replace github.com/sagernet/sing-vmess => github.com/starifly/sing-vmess v0.2.8-mod.1

replace github.com/metacubex/sing-shadowsocks2 => github.com/Restia-Ashbell/sing-shadowsocks2 v0.0.0-20250606153500-31ef7b14aaa6

replace github.com/amnezia-vpn/amneziawg-go => ../amneziawg-go

replace golang.org/x/net => ../net

replace github.com/metacubex/utls => ../utls

require (
	github.com/klauspost/cpuid/v2 v2.3.0 // indirect
	lukechampine.com/blake3 v1.3.0 // indirect
)

require (
	cunicu.li/go-rosenpass v0.5.42 // indirect
	github.com/DeRuina/timberjack v1.4.2 // indirect
	github.com/andybalholm/brotli v1.1.0 // indirect
	github.com/anmitsu/go-shlex v0.0.0-20200514113438-38f4b401e2be // indirect
	github.com/aws/aws-sdk-go-v2 v1.39.1 // indirect
	github.com/aws/aws-sdk-go-v2/config v1.31.10 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.18.14 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.18.8 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.4.8 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.7.8 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.8.3 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.13.8 // indirect
	github.com/aws/aws-sdk-go-v2/service/route53 v1.58.3 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.29.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.35.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.38.5 // indirect
	github.com/aws/smithy-go v1.23.0 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/caddyserver/zerossl v0.1.5 // indirect
	github.com/cenkalti/backoff/v4 v4.3.0 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/cilium/ebpf v0.19.0 // indirect
	github.com/cloudflare/circl v1.6.3 // indirect
	github.com/coder/websocket v1.8.14 // indirect
	github.com/coreos/go-iptables v0.8.0 // indirect
	github.com/creack/pty v1.1.24 // indirect
	github.com/database64128/netx-go v0.1.1 // indirect
	github.com/ebitengine/purego v0.10.0 // indirect
	github.com/florianl/go-nfqueue/v2 v2.0.2 // indirect
	github.com/fsnotify/fsnotify v1.9.0 // indirect
	github.com/gliderlabs/ssh v0.3.8 // indirect
	github.com/go-ole/go-ole v1.3.0 // indirect
	github.com/gobwas/httphead v0.1.0 // indirect
	github.com/gobwas/pool v0.2.1 // indirect
	github.com/golang-jwt/jwt/v5 v5.3.1 // indirect
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/google/btree v1.1.3 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/google/go-tpm v0.9.8 // indirect
	github.com/google/gopacket v1.1.19 // indirect
	github.com/google/nftables v0.3.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/gopacket/gopacket v1.4.0 // indirect
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.26.3 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/go-multierror v1.1.1 // indirect
	github.com/hashicorp/go-version v1.7.0 // indirect
	github.com/hashicorp/yamux v0.1.2 // indirect
	github.com/huin/goupnp v1.2.0 // indirect
	github.com/jackpal/go-nat-pmp v1.0.2 // indirect
	github.com/klauspost/compress v1.18.7 // indirect
	github.com/koron/go-ssdp v0.0.4 // indirect
	github.com/kr/fs v0.1.0 // indirect
	github.com/libdns/libdns v1.1.1 // indirect
	github.com/libdns/route53 v1.6.2 // indirect
	github.com/libp2p/go-netroute v0.4.0 // indirect
	github.com/lrh3321/ipset-go v0.0.0-20250619021614-54a0a98ace81 // indirect
	github.com/lufia/plan9stats v0.0.0-20240513124658-fba389f38bae // indirect
	github.com/mdlayher/genetlink v1.3.2 // indirect
	github.com/mdlayher/netlink v1.9.0 // indirect
	github.com/mdlayher/socket v0.5.1 // indirect
	github.com/mitchellh/hashstructure/v2 v2.0.2 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/netbirdio/go-nat v0.0.0-20260821095157-6b2c8c5c74e8 // indirect
	github.com/petermattis/goid v0.0.0-20250303134427-723919f7f203 // indirect
	github.com/pion/dtls/v2 v2.2.10 // indirect
	github.com/pion/dtls/v3 v3.0.9 // indirect
	github.com/pion/ice/v4 v4.0.0-00010101000000-000000000000 // indirect
	github.com/pion/logging v0.2.4 // indirect
	github.com/pion/mdns/v2 v2.0.7 // indirect
	github.com/pion/randutil v0.1.0 // indirect
	github.com/pion/stun/v2 v2.0.0 // indirect
	github.com/pion/stun/v3 v3.1.0 // indirect
	github.com/pion/transport/v2 v2.2.4 // indirect
	github.com/pion/transport/v3 v3.1.1 // indirect
	github.com/pion/turn/v3 v3.0.1 // indirect
	github.com/pion/turn/v4 v4.1.1 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pkg/sftp v1.13.9 // indirect
	github.com/power-devops/perfstat v0.0.0-20240221224432-82ca36839d55 // indirect
	github.com/prometheus/client_golang v1.23.2 // indirect
	github.com/prometheus/client_model v0.6.2 // indirect
	github.com/prometheus/common v0.67.5 // indirect
	github.com/prometheus/procfs v0.19.2 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	github.com/quic-go/quic-go v0.62.0 // indirect
	github.com/sagernet/gomobile v0.1.12 // indirect
	github.com/sagernet/netlink v0.0.0-20240612041022-b9a21c07ac6a // indirect
	github.com/sagernet/nftables v0.3.0-mod.2 // indirect
	github.com/shirou/gopsutil/v4 v4.25.8 // indirect
	github.com/sirupsen/logrus v1.9.4 // indirect
	github.com/skratchdot/open-golang v0.0.0-20200116055534-eef842397966 // indirect
	github.com/things-go/go-socks5 v0.0.4 // indirect
	github.com/ti-mo/conntrack v0.5.1 // indirect
	github.com/ti-mo/netfilter v0.5.2 // indirect
	github.com/tklauser/go-sysconf v0.3.15 // indirect
	github.com/tklauser/numcpus v0.10.0 // indirect
	github.com/vishvananda/netlink v1.3.1 // indirect
	github.com/wlynxg/anet v0.0.5 // indirect
	github.com/yusufpapurcu/wmi v1.2.4 // indirect
	github.com/zcalusic/sysinfo v1.1.3 // indirect
	github.com/zeebo/blake3 v0.2.4 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.uber.org/zap/exp v0.3.0 // indirect
	go.yaml.in/yaml/v2 v2.4.3 // indirect
	golang.org/x/oauth2 v0.36.0 // indirect
	golang.org/x/text v0.41.0 // indirect
	golang.org/x/time v0.15.0 // indirect
	golang.org/x/tools v0.49.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
	golang.zx2c4.com/wireguard/wgctrl v0.0.0-20241231184526-a9ab2273dd10 // indirect
	golang.zx2c4.com/wireguard/windows v0.5.3 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20260319201613-d00831a3d3e7 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260401024825-9d38bb4040a9 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	gvisor.dev/gvisor v0.0.0-20260219192049-0f2374377e89 // indirect
	howett.net/plist v1.0.2-0.20250314012144-ee69052608d9 // indirect
)

require github.com/sagernet/sing-box v1.0.0

replace github.com/sagernet/sing-box => ../sing-box

require (
	github.com/netbirdio/netbird v0.0.0
	golang.zx2c4.com/wireguard v0.0.0-20231211153847-12269c276173
	io.syn443/engine-netbird v0.0.0
)

replace io.syn443/engine-netbird => ../engine-netbird

replace github.com/netbirdio/netbird => ../netbird

replace github.com/kardianos/service => github.com/netbirdio/service v0.0.0-20240911161631-f62744f42502

replace github.com/getlantern/systray => github.com/netbirdio/systray v0.0.0-20231030152038-ef1ed2a27949

replace golang.zx2c4.com/wireguard => github.com/netbirdio/wireguard-go v0.0.0-20261016113635-bd0cb75a3df0

replace github.com/cloudflare/circl => codeberg.org/cunicu/circl v0.0.0-20230801113412-fec58fc7b5f6

replace github.com/pion/ice/v4 => github.com/netbirdio/ice/v4 v4.0.0-20250908184934-6202be846b51

replace github.com/dexidp/dex => github.com/netbirdio/dex v0.244.1-0.20260716205454-a163de3129e5

replace github.com/dexidp/dex/api/v2 => github.com/netbirdio/dex/api/v2 v2.0.0-20260512110716-8d70ad8647c1

replace github.com/mailru/easyjson => github.com/netbirdio/easyjson v0.9.0

replace github.com/wailsapp/wails/v3 => github.com/netbirdio/wails/v3 v3.0.0-beta.3.0.20261009120932-4e087a8bfd6d
