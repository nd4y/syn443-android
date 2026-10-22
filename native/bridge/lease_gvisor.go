//go:build with_gvisor

package bridge

import (
	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	tun "github.com/sagernet/sing-tun"
)

// gVisor's endpoint reads the FD directly, bypassing Tun.Read. Fence its
// dispatcher and link writer as well as the direct WritePacket fast path.
type guardedGVisorTun struct {
	tun.Tun
	raw   tun.GVisorTun
	guard *leaseGuard
}

func protectStackTun(base, raw tun.Tun, g *leaseGuard) tun.Tun {
	if gv, ok := raw.(tun.GVisorTun); ok {
		return &guardedGVisorTun{base, gv, g}
	}
	return base
}
func (t *guardedGVisorTun) WritePacket(p *stack.PacketBuffer) (int, error) {
	if !t.guard.allowed() {
		return 0, errLeaseExpired
	}
	return t.raw.WritePacket(p)
}
func (t *guardedGVisorTun) NewEndpoint() (stack.LinkEndpoint, stack.NICOptions, error) {
	ep, options, err := t.raw.NewEndpoint()
	if err != nil {
		return nil, options, err
	}
	guarded := &guardedEndpoint{ep, t.guard}
	if gso, ok := ep.(stack.GSOEndpoint); ok {
		return &guardedGSOEndpoint{guarded, gso}, options, nil
	}
	return guarded, options, nil
}

type guardedEndpoint struct {
	stack.LinkEndpoint
	guard *leaseGuard
}
type guardedGSOEndpoint struct {
	*guardedEndpoint
	stack.GSOEndpoint
}

func (e *guardedEndpoint) Attach(d stack.NetworkDispatcher) {
	if d == nil {
		e.LinkEndpoint.Attach(nil)
	} else {
		e.LinkEndpoint.Attach(&guardedDispatcher{d, e.guard})
	}
}
func (e *guardedEndpoint) WritePackets(p stack.PacketBufferList) (int, tcpip.Error) {
	if !e.guard.allowed() {
		return 0, &tcpip.ErrAborted{}
	}
	return e.LinkEndpoint.WritePackets(p)
}

type guardedDispatcher struct {
	stack.NetworkDispatcher
	guard *leaseGuard
}

func (d *guardedDispatcher) DeliverNetworkPacket(protocol tcpip.NetworkProtocolNumber, p *stack.PacketBuffer) {
	if d.guard.allowed() {
		d.NetworkDispatcher.DeliverNetworkPacket(protocol, p)
	}
}
func (d *guardedDispatcher) DeliverLinkPacket(protocol tcpip.NetworkProtocolNumber, p *stack.PacketBuffer) {
	if d.guard.allowed() {
		d.NetworkDispatcher.DeliverLinkPacket(protocol, p)
	}
}
