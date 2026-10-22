//go:build with_gvisor

package bridge

import (
	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	tun "github.com/sagernet/sing-tun"
	"testing"
)

type fakeDispatcher struct{ network, link int }

func (d *fakeDispatcher) DeliverNetworkPacket(tcpip.NetworkProtocolNumber, *stack.PacketBuffer) {
	d.network++
}
func (d *fakeDispatcher) DeliverLinkPacket(tcpip.NetworkProtocolNumber, *stack.PacketBuffer) {
	d.link++
}

type fakeEndpoint struct {
	stack.LinkEndpoint
	dispatcher stack.NetworkDispatcher
	writes     int
}

func (e *fakeEndpoint) Attach(d stack.NetworkDispatcher) { e.dispatcher = d }
func (e *fakeEndpoint) WritePackets(stack.PacketBufferList) (int, tcpip.Error) {
	e.writes++
	return 1, nil
}
func (e *fakeEndpoint) GSOMaxSize() uint32               { return 65536 }
func (e *fakeEndpoint) SupportedGSO() stack.SupportedGSO { return stack.GSONotSupported }

type fakeGVisorTun struct {
	*fakeLeaseTun
	ep      *fakeEndpoint
	packets int
}

func (t *fakeGVisorTun) WritePacket(*stack.PacketBuffer) (int, error) { t.packets++; return 1, nil }
func (t *fakeGVisorTun) NewEndpoint() (stack.LinkEndpoint, stack.NICOptions, error) {
	return t.ep, stack.NICOptions{}, nil
}
func TestGVisorDirectFDPathsCannotBypassLease(t *testing.T) {
	now := int64(10)
	g := &leaseGuard{clock: func() int64 { return now }}
	_ = g.set(20)
	raw := &fakeGVisorTun{fakeLeaseTun: &fakeLeaseTun{}, ep: &fakeEndpoint{}}
	gv, ok := protectTun(raw, g).(tun.GVisorTun)
	if !ok {
		t.Fatal("gVisor contract lost")
	}
	ep, _, err := gv.NewEndpoint()
	if err != nil {
		t.Fatal(err)
	}
	if ep.(stack.GSOEndpoint).GSOMaxSize() != 65536 {
		t.Fatal("GSO capabilities lost")
	}
	d := &fakeDispatcher{}
	ep.Attach(d)
	raw.ep.dispatcher.DeliverNetworkPacket(0, nil)
	raw.ep.dispatcher.DeliverLinkPacket(0, nil)
	if d.network != 1 || d.link != 1 {
		t.Fatal("authorized packet dropped")
	}
	now = 20
	raw.ep.dispatcher.DeliverNetworkPacket(0, nil)
	raw.ep.dispatcher.DeliverLinkPacket(0, nil)
	if d.network != 1 || d.link != 1 {
		t.Fatal("expired incoming FD packet escaped")
	}
	if n, e := ep.WritePackets(stack.PacketBufferList{}); n != 0 || e == nil || raw.ep.writes != 0 {
		t.Fatal("expired endpoint write escaped")
	}
	if n, e := gv.WritePacket(nil); n != 0 || e == nil || raw.packets != 0 {
		t.Fatal("expired direct packet escaped")
	}
	ep.Attach(nil)
	if raw.ep.dispatcher != nil {
		t.Fatal("detach lost")
	}
}
