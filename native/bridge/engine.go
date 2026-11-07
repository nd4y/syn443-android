// SPDX-License-Identifier: GPL-3.0-or-later
// Platform contract based on sing-box and the NekoBox Android adapter (see THIRD_PARTY.md).
package bridge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	netbird "io.syn443/engine-netbird"
	"net"
	"net/netip"
	"runtime/debug"
	"sync"
	"syscall"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	boxservice "github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/direct"
	"github.com/sagernet/sing-box/protocol/group"
	"github.com/sagernet/sing-box/protocol/http"
	"github.com/sagernet/sing-box/protocol/socks"
	"github.com/sagernet/sing-box/protocol/ssh"
	tunin "github.com/sagernet/sing-box/protocol/tun"
	"github.com/sagernet/sing-box/protocol/vless"
	tun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/common/x/list"
	"github.com/sagernet/sing/service"
)

type Protector interface {
	Protect(fd int32) error
	ExchangeDNS(query []byte) ([]byte, error)
	PhysicalInterfaces() (string, error)
}

type Runtime struct {
	box      *box.Box
	cancel   context.CancelFunc
	platform *platform
	routes   *routeRunner
}

func NewRuntime(config string, fd int32, protector Protector, name string, index int32, leaseDeadline int64) (*Runtime, error) {
	if fd < 0 || protector == nil || name == "" || index <= 0 {
		return nil, errors.New("invalid host context")
	}
	guard := &leaseGuard{clock: bootMillis}
	if err := guard.set(leaseDeadline); err != nil {
		return nil, err
	}
	netbird.DiagnosticsAllowed = guard.allowed
	installOverlayPlatform(protector)
	ir := inbound.NewRegistry()
	tunin.RegisterInbound(ir)
	or := outbound.NewRegistry()
	direct.RegisterOutbound(or)
	http.RegisterOutbound(or)
	socks.RegisterOutbound(or)
	vless.RegisterOutbound(or)
	ssh.RegisterOutbound(or)
	group.RegisterSelector(or)
	group.RegisterURLTest(or)
	netbird.RegisterOutbound(or)
	dr := dns.NewTransportRegistry()
	registerPhysicalDNS(dr, protector)
	netbird.RegisterDNSTransport(dr)
	registerRemoteDNS(dr)
	ctx, cancel := context.WithCancel(dialer.WithRuntimeOptions(context.Background(), dialer.RuntimeOptions{SkipInterfaceSelection: true}))
	ctx = box.Context(ctx, ir, or, endpoint.NewRegistry(), dr, boxservice.NewRegistry())
	ctx = service.ContextWithDefaultRegistry(ctx)
	p := &platform{fd: int(fd), protector: protector, iface: control.Interface{Index: int(index), Name: name, MTU: 1500, Flags: net.FlagUp}, lease: guard}
	p.mon = &monitor{iface: p.iface}
	service.MustRegister[adapter.PlatformInterface](ctx, p)
	var options option.Options
	if err := options.UnmarshalJSONContext(ctx, []byte(config)); err != nil {
		cancel()
		return nil, errors.New("invalid engine configuration")
	}
	instance, err := box.New(box.Options{Options: options, Context: ctx})
	if err != nil {
		cancel()
		return nil, errors.New("engine construction failed")
	}
	r := &Runtime{box: instance, cancel: cancel, platform: p}
	r.routes = newRouteRunner(ctx, func(tag string) (adapter.Outbound, bool) { return instance.Outbound().Outbound(tag) })
	r.routes.limit = func() time.Duration {
		if !guard.allowed() {
			return 0
		}
		s := guard.state.Load()
		remaining := int64(30_000)
		if s.deadline > 0 && s.deadline-guard.clock() < remaining {
			remaining = s.deadline - guard.clock()
		}
		if remaining <= 0 {
			return 0
		}
		return time.Duration(remaining) * time.Millisecond
	}
	var routeConfig struct {
		Outbounds []struct {
			Tag       string   `json:"tag"`
			Detour    string   `json:"detour"`
			Kind      string   `json:"type"`
			Members   []string `json:"outbounds"`
			Interrupt bool     `json:"interrupt_exist_connections"`
		} `json:"outbounds"`
	}
	_ = json.Unmarshal([]byte(config), &routeConfig)
	r.routes.nodes = map[string]routeNode{}
	r.routes.selectors = map[string]map[string]bool{}
	for i, node := range routeConfig.Outbounds {
		r.routes.nodes[node.Tag] = routeNode{ID: fmt.Sprintf("route-%d", i+1), Detour: node.Detour, Kind: node.Kind}
		if node.Kind == "selector" && !node.Interrupt && len(node.Members) <= 64 {
			members := make(map[string]bool, len(node.Members))
			for _, member := range node.Members {
				members[member] = true
			}
			r.routes.selectors[node.Tag] = members
		}
	}
	return r, nil
}
func (e *Runtime) Start() error { return e.box.Start() }
func (e *Runtime) Cancel()      { e.routes.stop(); e.cancel() }
func (e *Runtime) Close() error { e.Cancel(); return e.box.Close() }

// Bounded asynchronous probes never run on the native control/heartbeat worker.
func (e *Runtime) StartRouteChecks(request string) bool { return e.routes.start(request) }
func (e *Runtime) RouteCheckStatus() string             { return e.routes.snapshot() }
func (e *Runtime) CancelRouteChecks()                   { e.routes.stop() }
func (e *Runtime) SelectVerifiedRoute(request, checkID, group, previous, candidate string) bool {
	return e.routes.selectVerified(request, checkID, group, previous, candidate)
}

// The supervisor additionally checks actual HTTPS data-path progress; this is only runtime liveness.
func (e *Runtime) Pulse() int64 { return 1 }

// The private Android host admits this only for an active session in DEBUG.
// A separate goroutine avoids converting a bridge panic into a Java exception.
func (e *Runtime) DebugFatal() {
	debug.SetTraceback("crash")
	go func() { panic("SYN443 synthetic native failure") }()
}

// No SDK locks on the native host control loop.
func (e *Runtime) NetBirdStatus() string { return netbird.DeferredStatus() }
func (e *Runtime) NetBirdIdentityProof() string {
	if e.platform == nil || !e.platform.lease.allowed() {
		return "{}"
	}
	return netbird.ManagedRegistrationProof()
}
func (e *Runtime) DiagnoseNetBird() bool { return netbird.RequestDiagnostics() }
func (e *Runtime) UpdateNetwork(name string, index int32) {
	e.routes.networkChanged()
	e.platform.mu.Lock()
	e.platform.iface.Name = name
	e.platform.iface.Index = int(index)
	iface := e.platform.iface
	e.platform.mu.Unlock()
	e.platform.mon.update(iface)
	_ = e.box.Network().UpdateInterfaces()
	e.box.Network().ResetNetwork()
}

type platform struct {
	lease     *leaseGuard
	fd        int
	protector Protector
	iface     control.Interface
	addresses []netip.Addr
	mon       *monitor
	mu        sync.Mutex
}

func (p *platform) Initialize(adapter.NetworkManager) error     { return nil }
func (p *platform) UsePlatformAutoDetectInterfaceControl() bool { return true }
func (p *platform) AutoDetectInterfaceControl(fd int) error     { return p.protector.Protect(int32(fd)) }
func (p *platform) UsePlatformInterface() bool                  { return true }
func (p *platform) OpenInterface(o *tun.Options, _ option.TunPlatformOptions) (tun.Tun, error) {
	fd, err := syscall.Dup(p.fd)
	if err != nil {
		return nil, err
	}
	o.FileDescriptor = fd
	for _, a := range o.Inet4Address {
		p.addresses = append(p.addresses, a.Addr())
	}
	for _, a := range o.Inet6Address {
		p.addresses = append(p.addresses, a.Addr())
	}
	t, err := tun.New(*o)
	if err != nil {
		syscall.Close(fd)
	}
	if err != nil {
		return nil, err
	}
	return protectTun(t, p.lease), nil
}
func (p *platform) UsePlatformDefaultInterfaceMonitor() bool { return true }
func (p *platform) CreateDefaultInterfaceMonitor(logger.Logger) tun.DefaultInterfaceMonitor {
	return p.mon
}
func (p *platform) UsePlatformNetworkInterfaces() bool { return true }
func (p *platform) NetworkInterfaces() ([]adapter.NetworkInterface, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return []adapter.NetworkInterface{{Interface: p.iface}}, nil
}
func (p *platform) UnderNetworkExtension() bool              { return false }
func (p *platform) NetworkExtensionIncludeAllNetworks() bool { return false }
func (p *platform) ClearDNSCache()                           {}
func (p *platform) RequestPermissionForWIFIState() error     { return nil }
func (p *platform) ReadWIFIState() adapter.WIFIState         { return adapter.WIFIState{} }
func (p *platform) SystemCertificates() []string             { return nil }
func (p *platform) UsePlatformConnectionOwnerFinder() bool   { return false }
func (p *platform) FindConnectionOwner(*adapter.FindConnectionOwnerRequest) (*adapter.ConnectionOwner, error) {
	return nil, errors.New("owner lookup unavailable")
}
func (p *platform) UsePlatformWIFIMonitor() bool                 { return false }
func (p *platform) UsePlatformNotification() bool                { return false }
func (p *platform) SendNotification(*adapter.Notification) error { return nil }
func (p *platform) MyInterfaceAddress() []netip.Addr             { return p.addresses }

type monitor struct {
	mu        sync.Mutex
	iface     control.Interface
	callbacks list.List[tun.DefaultInterfaceUpdateCallback]
	mine      []string
}

func (m *monitor) Start() error { return nil }
func (m *monitor) Close() error { return nil }
func (m *monitor) DefaultInterface() *control.Interface {
	m.mu.Lock()
	defer m.mu.Unlock()
	copy := m.iface
	return &copy
}
func (m *monitor) OverrideAndroidVPN() bool { return false }
func (m *monitor) AndroidVPNEnabled() bool  { return false }
func (m *monitor) RegisterCallback(c tun.DefaultInterfaceUpdateCallback) *list.Element[tun.DefaultInterfaceUpdateCallback] {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.callbacks.PushBack(c)
}
func (m *monitor) UnregisterCallback(e *list.Element[tun.DefaultInterfaceUpdateCallback]) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.callbacks.Remove(e)
}
func (m *monitor) RegisterMyInterface(s string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.mine = append(m.mine, s)
}
func (m *monitor) MyInterfaces() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.mine...)
}
func (m *monitor) update(iface control.Interface) {
	m.mu.Lock()
	m.iface = iface
	callbacks := m.callbacks.Array()
	m.mu.Unlock()
	for _, callback := range callbacks {
		callback(&iface, 0)
	}
}
