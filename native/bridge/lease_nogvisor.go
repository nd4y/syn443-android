//go:build !with_gvisor

package bridge

import tun "github.com/sagernet/sing-tun"

func protectStackTun(base, _ tun.Tun, _ *leaseGuard) tun.Tun { return base }
