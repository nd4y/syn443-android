package bridge

import (
	"github.com/netbirdio/netbird/client/embed"
	nbnet "github.com/netbirdio/netbird/client/net"
	"github.com/netbirdio/netbird/client/underlay"
	wgconn "golang.zx2c4.com/wireguard/conn"
	"syscall"
)

func init() {
	*wgconn.ControlFns = append(*wgconn.ControlFns, func(network, address string, connection syscall.RawConn) error {
		if underlay.DirectEnabled() {
			return nbnet.ControlProtectSocket(network, address, connection)
		}
		return nil
	})
}
func installOverlayPlatform(protector Protector) {
	installOverlayResolver(protector)
	nbnet.SetAndroidProtectSocketFn(func(fd int32) bool { return protector.Protect(fd) == nil })
	embed.SetPhysicalInterfaceDiscoverer(protector.PhysicalInterfaces)
}
