package bridge

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
)

func TestPrivateTrafficRealTCPLeaseAndGracefulDrain(t *testing.T) {
	target := listenWire(t, func(c net.Conn) { _, _ = io.Copy(c, c) })
	address := target.listener.Addr().String()
	exit := httpWire(t, address, "", "")
	entry := socksWire(t, exit.listener.Addr().String())
	instance, parent := wireNetworkBox(t, nil, []map[string]any{{"type": "direct", "tag": "existing"}}, nil)
	lease := privatePoolLease(t)
	scope := strings.Repeat("a", 64)
	p, e := newPrivatePathPool(parent, scope, 3, lease)
	if e != nil {
		t.Fatal(e)
	}
	cleanupPrivatePool(t, p)
	catalogue := map[string]map[string]any{"entry": entry.node("socks", "input-entry"), "exit": exit.node("http", "input-exit")}
	candidate, e := p.prepare(scope, []string{"entry", "exit"}, func(ctx context.Context, id, tag, previous string) (adapter.Outbound, error) {
		raw, _ := json.Marshal(catalogue[id])
		var opts option.Outbound
		if err := opts.UnmarshalJSONContext(ctx, raw); err != nil {
			return nil, err
		}
		wrapper := opts.Options.(option.DialerOptionsWrapper)
		dialer := wrapper.TakeDialerOptions()
		dialer.Detour = previous
		wrapper.ReplaceDialerOptions(dialer)
		return service.FromContext[adapter.OutboundRegistry](ctx).CreateOutbound(ctx, instance.Router(), log.NewNOPFactory().Logger(), tag, opts.Type, opts.Options)
	})
	if e != nil {
		t.Fatal(e)
	}
	flow, e := candidate.dialTCP(scope, context.Background(), "tcp", M.ParseSocksaddr(address))
	if e != nil {
		t.Fatal(e)
	}
	defer flow.Close()
	if e = flow.SetDeadline(time.Now().Add(5 * time.Second)); e != nil {
		t.Fatal(e)
	}
	echo := func(value string) {
		t.Helper()
		if _, e := io.WriteString(flow, value); e != nil {
			t.Fatal(e)
		}
		raw := make([]byte, len(value))
		if _, e := io.ReadFull(flow, raw); e != nil || string(raw) != value {
			t.Fatal("real held payload failed", e)
		}
	}
	echo("before-retirement")
	_ = candidate.Close()
	echo("during-graceful-drain")
	if _, e = candidate.dialTCP(scope, context.Background(), "tcp", M.ParseSocksaddr(address)); e == nil {
		t.Fatal("draining candidate admitted a new flow")
	}
	if entry.calls.Load() == 0 || exit.calls.Load() == 0 || p.snapshot().Holds != 1 {
		t.Fatal("flow lost hop or ownership")
	}
	for _, v := range []any{p, candidate, flow} {
		if s := fmt.Sprintf("%v %#v", v, v); strings.Contains(s, address) || strings.Contains(s, scope) {
			t.Fatal("private diagnostic exposed route details")
		}
	}
	if e = lease.set(bootMillis() - 1); e != nil {
		t.Fatal(e)
	}
	if n, e := flow.Write([]byte("expired")); n != 0 || e != errPrivatePath {
		t.Fatal("expired lease sent data")
	}
	if _, e = candidate.dialTCP(scope, context.Background(), "tcp", M.ParseSocksaddr(address)); e != errPrivatePath {
		t.Fatal("expired lease admitted dial")
	}
	if e = lease.set(bootMillis() + 60_000); e != errLeaseRestart {
		t.Fatal("expired guard was resurrected")
	}
	_ = flow.Close()
	awaitPrivatePool(t, func() bool { return p.snapshot().Dynamic == 0 })
	if e = payloadWire(t, instance.Outbound().Default(), address); e != nil {
		t.Fatal("private flow retirement changed configured parent", e)
	}
}

type privateTrafficTestNode struct {
	adapter.Outbound
	tag    string
	dial   func(context.Context, string, M.Socksaddr) (net.Conn, error)
	packet func(context.Context, M.Socksaddr) (net.PacketConn, error)
}

func (n *privateTrafficTestNode) Type() string                   { return "socks" }
func (n *privateTrafficTestNode) Tag() string                    { return n.tag }
func (n *privateTrafficTestNode) Dependencies() []string         { return nil }
func (n *privateTrafficTestNode) Start(adapter.StartStage) error { return nil }
func (n *privateTrafficTestNode) Close() error                   { return nil }
func (n *privateTrafficTestNode) DialContext(c context.Context, k string, d M.Socksaddr) (net.Conn, error) {
	return n.dial(c, k, d)
}
func (n *privateTrafficTestNode) ListenPacket(c context.Context, d M.Socksaddr) (net.PacketConn, error) {
	return n.packet(c, d)
}

func privateTrafficCandidate(t *testing.T, node *privateTrafficTestNode) (*privatePathPool, *privatePathCandidate, string) {
	t.Helper()
	_, parent := wireNetworkBox(t, nil, []map[string]any{{"type": "direct", "tag": "existing"}}, nil)
	scope := strings.Repeat("a", 64)
	p, e := newPrivatePathPool(parent, scope, 2, privatePoolLease(t))
	if e != nil {
		t.Fatal(e)
	}
	cleanupPrivatePool(t, p)
	c, e := p.prepare(scope, []string{"one"}, func(_ context.Context, _, tag, _ string) (adapter.Outbound, error) { node.tag = tag; return node, nil })
	if e != nil {
		t.Fatal(e)
	}
	return p, c, scope
}

type privateLateReadConn struct {
	net.Conn
	entered chan struct{}
	release <-chan struct{}
	closed  chan struct{}
	once    sync.Once
}

func (c *privateLateReadConn) Read(b []byte) (int, error) {
	close(c.entered)
	<-c.release
	return copy(b, "late"), nil
}
func (c *privateLateReadConn) Write(b []byte) (int, error) { return len(b), nil }
func (c *privateLateReadConn) Close() error                { c.once.Do(func() { close(c.closed) }); return nil }

func TestPrivateTrafficPacketsAndLateReadCannotOutliveContext(t *testing.T) {
	t.Run("real UDP socket ownership", func(t *testing.T) {
		// A real local UDP socket exercises ownership, not SOCKS UDP protocol
		// acceptance. The constructor is an explicit synthetic test adapter.
		echo, e := net.ListenPacket("udp", "127.0.0.1:0")
		if e != nil {
			t.Fatal(e)
		}
		defer echo.Close()
		_ = echo.SetDeadline(time.Now().Add(5 * time.Second))
		node := &privateTrafficTestNode{packet: func(context.Context, M.Socksaddr) (net.PacketConn, error) {
			return net.ListenPacket("udp", "127.0.0.1:0")
		}}
		p, c, scope := privateTrafficCandidate(t, node)
		conn, e := c.listenUDP(scope, context.Background(), M.ParseSocksaddr(echo.LocalAddr().String()))
		if e != nil {
			t.Fatal(e)
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		if _, e = conn.WriteTo([]byte("owned"), echo.LocalAddr()); e != nil {
			t.Fatal(e)
		}
		buf := make([]byte, 32)
		n, a, e := echo.ReadFrom(buf)
		if e != nil || string(buf[:n]) != "owned" {
			t.Fatal("UDP send failed", e)
		}
		if _, e = echo.WriteTo(buf[:n], a); e != nil {
			t.Fatal(e)
		}
		n, _, e = conn.ReadFrom(buf)
		if e != nil || string(buf[:n]) != "owned" {
			t.Fatal("UDP reply failed", e)
		}
		if !p.changeScope(strings.Repeat("b", 64)) {
			t.Fatal("scope did not change")
		}
		if n, e = conn.WriteTo([]byte("stale"), echo.LocalAddr()); n != 0 || e != errPrivatePath {
			t.Fatal("stale UDP sent data")
		}
		awaitPrivatePool(t, func() bool { return p.snapshot().Dynamic == 0 })
	})
	t.Run("late positive read is discarded", func(t *testing.T) {
		release := make(chan struct{})
		var once sync.Once
		unblock := func() { once.Do(func() { close(release) }) }
		t.Cleanup(unblock)
		raw := &privateLateReadConn{entered: make(chan struct{}), release: release, closed: make(chan struct{})}
		p, c, scope := privateTrafficCandidate(t, &privateTrafficTestNode{dial: func(context.Context, string, M.Socksaddr) (net.Conn, error) { return raw, nil }})
		flow, e := c.dialTCP(scope, context.Background(), "tcp", M.ParseSocksaddr("127.0.0.1:12345"))
		if e != nil {
			t.Fatal(e)
		}
		done := make(chan struct{})
		go func() {
			defer close(done)
			buf := make([]byte, 4)
			n, e := flow.Read(buf)
			if n != 0 || e != errPrivatePath {
				t.Error("late positive read escaped changed context")
			}
		}()
		t.Cleanup(func() {
			unblock()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Error("late read fixture did not retire")
			}
		})
		select {
		case <-raw.entered:
		case <-time.After(5 * time.Second):
			t.Fatal("read did not enter")
		}
		p.Close()
		select {
		case <-raw.closed:
		case <-time.After(5 * time.Second):
			t.Fatal("owned flow did not close")
		}
		if s := p.snapshot(); s.Dynamic != 1 || s.Operations != 1 {
			t.Fatal("unfinished read reservation released", s)
		}
		unblock()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("read did not complete")
		}
	})
}

type privateBlockedIOConn struct {
	net.Conn
	entered chan struct{}
	release <-chan struct{}
}

type privateFaultIOConn struct {
	net.Conn
	kind string
}

func (c *privateFaultIOConn) Read([]byte) (int, error) { panic("synthetic read details") }
func (c *privateFaultIOConn) Close() error {
	if c.kind == "panic" {
		panic("synthetic close details")
	}
	if c.kind == "error" {
		return fmt.Errorf("synthetic private close details")
	}
	return nil
}

func (c *privateBlockedIOConn) Read([]byte) (int, error) {
	c.entered <- struct{}{}
	<-c.release
	return 0, io.EOF
}
func (c *privateBlockedIOConn) Close() error { return nil }

func TestPrivateTrafficPartialDialPanicAndLateOwnerKeepCapacity(t *testing.T) {
	t.Run("close failure and read panic retain uncertain resources", func(t *testing.T) {
		for _, kind := range []string{"panic", "error", "read"} {
			t.Run(kind, func(t *testing.T) {
				raw := &privateFaultIOConn{kind: kind}
				p, c, scope := privateTrafficCandidate(t, &privateTrafficTestNode{dial: func(context.Context, string, M.Socksaddr) (net.Conn, error) { return raw, nil }})
				flow, e := c.dialTCP(scope, context.Background(), "tcp", M.ParseSocksaddr("127.0.0.1:12345"))
				if e != nil {
					t.Fatal(e)
				}
				if kind == "read" {
					if n, e := flow.Read(make([]byte, 1)); n != 0 || e != errPrivatePath {
						t.Fatal("read panic escaped")
					}
					_ = flow.Close()
				} else {
					if e := flow.Close(); e != errPrivatePath {
						t.Fatal("close failure escaped or exposed private detail")
					}
				}
				if s := p.snapshot(); s.Retained != 1 || s.Dynamic != 1 || s.Operations != 0 {
					t.Fatal("uncertain IO cleanup released its reservation", s)
				}
			})
		}
	})
	t.Run("invalid or unmanaged lease", func(t *testing.T) {
		_, parent := wireNetworkBox(t, nil, []map[string]any{{"type": "direct", "tag": "existing"}}, nil)
		zero := &leaseGuard{clock: bootMillis}
		_ = zero.set(0)
		expired := &leaseGuard{clock: bootMillis}
		_ = expired.set(bootMillis() - 1)
		for _, lease := range []*leaseGuard{nil, {}, zero, expired} {
			if p, e := newPrivatePathPool(parent, strings.Repeat("a", 64), 2, lease); p != nil || e != errPrivatePath {
				t.Fatal("unmanaged/expired lease admitted")
			}
		}
	})
	t.Run("concurrent operation cap and late IO ownership", func(t *testing.T) {
		release := make(chan struct{})
		var once sync.Once
		unblock := func() { once.Do(func() { close(release) }) }
		t.Cleanup(unblock)
		raw := &privateBlockedIOConn{entered: make(chan struct{}, 4), release: release}
		p, c, scope := privateTrafficCandidate(t, &privateTrafficTestNode{dial: func(context.Context, string, M.Socksaddr) (net.Conn, error) { return raw, nil }})
		flow, e := c.dialTCP(scope, context.Background(), "tcp", M.ParseSocksaddr("127.0.0.1:12345"))
		if e != nil {
			t.Fatal(e)
		}
		done := make(chan struct{})
		var readers sync.WaitGroup
		for i := 0; i < 4; i++ {
			readers.Add(1)
			go func() {
				defer readers.Done()
				n, e := flow.Read(make([]byte, 1))
				if n != 0 || e != errPrivatePath {
					t.Error("late IO was not fenced")
				}
			}()
		}
		go func() { readers.Wait(); close(done) }()
		t.Cleanup(func() {
			unblock()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Error("blocked IO fixture did not retire")
			}
		})
		for i := 0; i < 4; i++ {
			select {
			case <-raw.entered:
			case <-time.After(5 * time.Second):
				t.Fatal("read did not enter")
			}
		}
		if n, e := flow.Read(make([]byte, 1)); n != 0 || e != errPrivatePath {
			t.Fatal("unbounded parallel IO admitted")
		}
		p.Close()
		select {
		case <-p.workerExited:
		case <-time.After(5 * time.Second):
			t.Fatal("adapter retirement stalled")
		}
		if s := p.snapshot(); s.Dynamic != 1 || s.Operations != 4 || s.Holds != 1 {
			t.Fatal("unfinished IO capacity was lent out", s)
		}
		unblock()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("read did not complete")
		}
		if s := p.snapshot(); s.Dynamic != 0 || s.Operations != 0 || s.Holds != 0 {
			t.Fatal("confirmed IO cleanup did not release", s)
		}
	})
	t.Run("partial connection with error is owned", func(t *testing.T) {
		local, peer := net.Pipe()
		defer peer.Close()
		p, c, scope := privateTrafficCandidate(t, &privateTrafficTestNode{dial: func(context.Context, string, M.Socksaddr) (net.Conn, error) { return local, errPrivatePath }})
		if conn, e := c.dialTCP(scope, context.Background(), "tcp", M.ParseSocksaddr("127.0.0.1:12345")); conn != nil || e != errPrivatePath {
			t.Fatal("partial dial became usable")
		}
		if p.snapshot().Holds != 0 {
			t.Fatal("cleaned partial dial retained a reference")
		}
		_ = c.Close()
		awaitPrivatePool(t, func() bool { return p.snapshot().Dynamic == 0 })
	})
	t.Run("dial panic retains uncertain owner", func(t *testing.T) {
		p, c, scope := privateTrafficCandidate(t, &privateTrafficTestNode{dial: func(context.Context, string, M.Socksaddr) (net.Conn, error) { panic("synthetic private endpoint") }})
		if conn, e := c.dialTCP(scope, context.Background(), "tcp", M.ParseSocksaddr("127.0.0.1:12345")); conn != nil || e != errPrivatePath {
			t.Fatal("dial panic escaped")
		}
		if s := p.snapshot(); s.Retained != 1 || s.Dynamic != 1 || s.Holds != 1 {
			t.Fatal("uncertain owner reservation lost", s)
		}
	})
	t.Run("adapter close does not free an unfinished dial", func(t *testing.T) {
		entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
		var once sync.Once
		unblock := func() { once.Do(func() { close(release) }) }
		t.Cleanup(unblock)
		local, peer := net.Pipe()
		defer peer.Close()
		p, c, scope := privateTrafficCandidate(t, &privateTrafficTestNode{dial: func(context.Context, string, M.Socksaddr) (net.Conn, error) {
			close(entered)
			<-release
			return local, nil
		}})
		go func() {
			defer close(done)
			conn, e := c.dialTCP(scope, context.Background(), "tcp", M.ParseSocksaddr("127.0.0.1:12345"))
			if conn != nil || e != errPrivatePath {
				t.Error("late dial acquired authority")
			}
		}()
		t.Cleanup(func() {
			unblock()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Error("late dial fixture did not retire")
			}
		})
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			t.Fatal("dial did not enter")
		}
		p.Close()
		select {
		case <-p.workerExited:
		case <-time.After(5 * time.Second):
			t.Fatal("retirement worker did not finish adapter close")
		}
		if s := p.snapshot(); s.Dynamic != 1 || s.Holds != 1 {
			t.Fatal("unfinished dial capacity was lent out", s)
		}
		unblock()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("late dial did not finish")
		}
		if p.snapshot().Dynamic != 0 {
			t.Fatal("confirmed late cleanup failed to release capacity")
		}
	})
}
