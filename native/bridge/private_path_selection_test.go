package bridge

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
)

func TestPrivateSelectionRealFreshSwitchPinsAndBoundsDrain(t *testing.T) {
	target := listenWire(t, func(c net.Conn) { _, _ = io.Copy(c, c) })
	address := target.listener.Addr().String()
	exitA, exitB := httpWire(t, address, "", ""), httpWire(t, address, "", "")
	entryA, entryB := socksWire(t, exitA.listener.Addr().String()), socksWire(t, exitB.listener.Addr().String())
	instance, parent := wireNetworkBox(t, nil, []map[string]any{{"type": "direct", "tag": "existing"}}, nil)
	scope := strings.Repeat("a", 64)
	var now atomic.Int64
	now.Store(bootMillis())
	lease := &leaseGuard{clock: now.Load}
	if e := lease.set(now.Load() + 1_000_000); e != nil {
		t.Fatal(e)
	}
	p, e := newPrivatePathPool(parent, scope, 5, lease)
	if e != nil {
		t.Fatal(e)
	}
	cleanupPrivatePool(t, p)
	catalogue := map[string]map[string]any{"a1": entryA.node("socks", "input-a1"), "a2": exitA.node("http", "input-a2"), "b1": entryB.node("socks", "input-b1"), "b2": exitB.node("http", "input-b2")}
	create := func(ctx context.Context, id, tag, previous string) (adapter.Outbound, error) {
		raw, _ := json.Marshal(catalogue[id])
		var opts option.Outbound
		if e := opts.UnmarshalJSONContext(ctx, raw); e != nil {
			return nil, e
		}
		wrapper := opts.Options.(option.DialerOptionsWrapper)
		dialer := wrapper.TakeDialerOptions()
		dialer.Detour = previous
		wrapper.ReplaceDialerOptions(dialer)
		return service.FromContext[adapter.OutboundRegistry](ctx).CreateOutbound(ctx, instance.Router(), log.NewNOPFactory().Logger(), tag, opts.Type, opts.Options)
	}
	a, e := p.prepare(scope, []string{"a1", "a2"}, create)
	if e != nil {
		t.Fatal(e)
	}
	b, e := p.prepare(scope, []string{"b1", "b2"}, create)
	if e != nil {
		t.Fatal(e)
	}
	s, e := newPrivatePathSelector(p, scope, "home", []routeCheck{{Method: "tcp", Target: address}})
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if conn, e := s.dialTCP(context.Background(), "tcp", M.ParseSocksaddr(address)); conn != nil || e != errPrivatePath {
		t.Fatal("unverified route gained a direct fallback")
	}
	proof, e := s.probe(context.Background(), a)
	if e != nil || !s.selectVerified(proof, 1000) {
		t.Fatal("actual first path was not selected", e)
	}
	if entryA.calls.Load() == 0 || exitA.calls.Load() == 0 {
		t.Fatal("positive TCP proof did not traverse both real hops")
	}
	if s.selectVerified(proof, 1000) {
		t.Fatal("consumed proof replayed")
	}
	_ = a.Close() // An eviction request cannot retire an actively selected path.
	old, e := s.dialTCP(context.Background(), "tcp", M.ParseSocksaddr(address))
	if e != nil {
		t.Fatal("planner evicted active path", e)
	}
	defer old.Close()
	assertEcho := func(c net.Conn, text string) {
		t.Helper()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		if _, e := io.WriteString(c, text); e != nil {
			t.Fatal(e)
		}
		raw := make([]byte, len(text))
		if _, e := io.ReadFull(c, raw); e != nil || string(raw) != text {
			t.Fatal("selected path payload failed", e)
		}
	}
	assertEcho(old, "first-path")
	proof, e = s.probe(context.Background(), b)
	if e != nil || !s.selectVerified(proof, 1000) {
		t.Fatal("verified replacement was not selected", e)
	}
	if entryB.calls.Load() == 0 || exitB.calls.Load() == 0 {
		t.Fatal("replacement proof did not traverse both real hops")
	}
	assertEcho(old, "old-flow-drains")
	current, e := s.dialTCP(context.Background(), "tcp", M.ParseSocksaddr(address))
	if e != nil {
		t.Fatal(e)
	}
	defer current.Close()
	assertEcho(current, "replacement-path")
	if entryA.calls.Load() == 0 || exitA.calls.Load() == 0 || entryB.calls.Load() == 0 || exitB.calls.Load() == 0 {
		t.Fatal("selected chain bypassed a hop")
	}
	if snapshot := p.snapshot(); snapshot.Dynamic != 4 || snapshot.Holds != 2 {
		t.Fatal("old or active adapter capacity was lent", snapshot)
	}
	// Model elapsed suspend before a Go timer gets CPU. New and in-flight data
	// must obey the boot clock, while the selected replacement remains usable.
	now.Add(1001)
	if n, e := old.Write([]byte("expired-drain")); n != 0 || e != errPrivatePath {
		t.Fatal("suspend extended old drain authority")
	}
	assertEcho(current, "still-selected")
	_ = old.Close()
	awaitPrivatePool(t, func() bool { return p.snapshot().Dynamic == 2 })
	if e = payloadWire(t, instance.Outbound().Default(), address); e != nil {
		t.Fatal("selection changed configured parent", e)
	}
	for _, v := range []any{s, proof} {
		raw := fmt.Sprintf("%v %#v", v, v)
		if strings.Contains(raw, address) || strings.Contains(raw, scope) {
			t.Fatal("selection diagnostics exposed route")
		}
	}
	if !p.changeScope(strings.Repeat("b", 64)) {
		t.Fatal("scope did not change")
	}
	if n, e := current.Write([]byte("stale")); n != 0 || e != errPrivatePath {
		t.Fatal("old-context selection kept authority")
	}
}

func TestPrivateSelectionProofBindingsFreshnessAndSharedPins(t *testing.T) {
	node := &privateTrafficTestNode{dial: func(ctx context.Context, k string, d M.Socksaddr) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, k, d.String())
	}}
	target := listenWire(t, func(c net.Conn) { _, _ = io.Copy(c, c) })
	p, c, scope := privateTrafficCandidate(t, node)
	var now atomic.Int64
	now.Store(bootMillis())
	p.lease.clock = now.Load
	if e := p.lease.set(now.Load() + 1_000_000); e != nil {
		t.Fatal(e)
	}
	checks := []routeCheck{{Method: "tcp", Target: target.listener.Addr().String()}}
	s, e := newPrivatePathSelector(p, scope, "one", checks)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	other, e := newPrivatePathSelector(p, scope, "two", checks)
	if e != nil {
		t.Fatal(e)
	}
	defer other.Close()
	checks[0].Target = "changed-invalid-input"
	if _, e = newPrivatePathSelector(p, scope, "one", s.checks); e == nil {
		t.Fatal("duplicate group admitted")
	}
	proof, e := s.probe(context.Background(), c)
	if e != nil {
		t.Fatal(e)
	}
	copyProof := *proof
	if s.selectVerified(&copyProof, 1000) || other.selectVerified(proof, 1000) || s.selectVerified(proof, 999) || s.selectVerified(proof, 300001) {
		t.Fatal("forged, wrong-group or unbounded selection admitted")
	}
	oldHash := proof.checksHash
	proof.checksHash = "wrong"
	if s.selectVerified(proof, 1000) {
		t.Fatal("wrong check-set admitted")
	}
	proof.checksHash = oldHash
	oldScope := proof.scope
	proof.scope = strings.Repeat("b", 64)
	if s.selectVerified(proof, 1000) {
		t.Fatal("wrong full scope admitted")
	}
	proof.scope = oldScope
	if !s.selectVerified(proof, 1000) {
		t.Fatal("fresh real proof denied")
	}
	proof, e = other.probe(context.Background(), c)
	if e != nil || !other.selectVerified(proof, 1000) {
		t.Fatal("second authorized group could not pin same path", e)
	}
	_ = c.Close()
	s.Close()
	flow, e := other.dialTCP(context.Background(), "tcp", M.ParseSocksaddr(target.listener.Addr().String()))
	if e != nil {
		t.Fatal("one group retired another group's active path", e)
	}
	_ = flow.Close()
	proof, e = other.probe(context.Background(), c)
	if e != nil {
		t.Fatal(e)
	}
	now.Add(15_001)
	if other.selectVerified(proof, 1000) {
		t.Fatal("stale score became selection permission")
	}
	// A proof is an admission token, not a lease on already-selected traffic.
	flow, e = other.dialTCP(context.Background(), "tcp", M.ParseSocksaddr(target.listener.Addr().String()))
	if e != nil {
		t.Fatal("proof age killed an authorized active route", e)
	}
	_ = flow.Close()
	if e = p.lease.set(now.Load() - 1); e != nil {
		t.Fatal(e)
	}
	if proof, e = other.probe(context.Background(), c); proof != nil || e != errPrivatePath {
		t.Fatal("expired authorization minted proof")
	}
	if flow, e = other.dialTCP(context.Background(), "tcp", M.ParseSocksaddr(target.listener.Addr().String())); flow != nil || e != errPrivatePath {
		t.Fatal("expired authorization admitted selected flow")
	}
}

func TestPrivateSelectionBlockedProbeCannotBeReplacedOrPublishLate(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	var calls atomic.Int32
	node := &privateTrafficTestNode{dial: func(context.Context, string, M.Socksaddr) (net.Conn, error) {
		calls.Add(1)
		close(entered)
		<-release
		return nil, errPrivatePath
	}}
	p, c, scope := privateTrafficCandidate(t, node)
	t.Cleanup(unblock)
	checks := []routeCheck{{Method: "tcp", Target: "127.0.0.1:12345"}}
	s, e := newPrivatePathSelector(p, scope, "one", checks)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	other, e := newPrivatePathSelector(p, scope, "two", checks)
	if e != nil {
		t.Fatal(e)
	}
	defer other.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		proof, e := s.probe(ctx, c)
		if proof != nil || e == nil {
			t.Error("late blocked probe minted authority")
		}
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("probe not entered")
	}
	cancel()
	for i := 0; i < 20; i++ {
		if proof, e := other.probe(context.Background(), c); proof != nil || e != errPrivatePath {
			t.Fatal("replacement probe admitted")
		}
	}
	if calls.Load() != 1 || p.snapshot().Holds != 2 {
		t.Fatal("blocked worker lost ownership or was replaced")
	}
	if !p.changeScope(strings.Repeat("b", 64)) {
		t.Fatal("scope did not change")
	}
	unblock()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("probe did not return after release")
	}
	awaitPrivatePool(t, func() bool { return p.snapshot().Dynamic == 0 })
	p.mu.Lock()
	busy := p.probing
	p.mu.Unlock()
	if busy || calls.Load() != 1 || s.selectVerified(&privateSelectionProof{}, 1000) {
		t.Fatal("late probe gained authority or leaked admission")
	}
	t.Run("lazy handshake failure is not a positive TCP proof", func(t *testing.T) {
		node := &privateTrafficTestNode{dial: func(context.Context, string, M.Socksaddr) (net.Conn, error) { return &privateFailedHandshake{}, nil }}
		p, c, scope := privateTrafficCandidate(t, node)
		s, e := newPrivatePathSelector(p, scope, "lazy", checks)
		if e != nil {
			t.Fatal(e)
		}
		defer s.Close()
		proof, e := s.probe(context.Background(), c)
		if proof != nil {
			t.Fatal("lazy unconnected socket minted positive proof")
		}
		requirePrivateCheckedFailure(t, e, "dial_failed")
	})
}

func requirePrivateCheckedFailure(t *testing.T, err error, code string) {
	t.Helper()
	var checked *privateCheckedFailure
	if !errors.As(err, &checked) || checked == nil || checked.code != code || checked.completedBootMS <= 0 {
		t.Fatal("expected exact admitted-check observation was not preserved")
	}
}

type privateFailedHandshake struct{ net.Conn }

func (*privateFailedHandshake) NeedHandshake() bool         { return true }
func (*privateFailedHandshake) Write([]byte) (int, error)   { return 0, errPrivatePath }
func (*privateFailedHandshake) Close() error                { return nil }
func (*privateFailedHandshake) SetDeadline(time.Time) error { return nil }

func TestPrivateCheckedFailureRequiresAdmittedDispatchWithoutRevokingActiveFlows(t *testing.T) {
	t.Run("actual refused TCP target", func(t *testing.T) {
		listener, e := net.Listen("tcp", "127.0.0.1:0")
		if e != nil {
			t.Fatal(e)
		}
		address := listener.Addr().String()
		_ = listener.Close()
		var calls atomic.Int32
		var now atomic.Int64
		now.Store(bootMillis())
		var observed *privateProbeDialObservation
		node := &privateTrafficTestNode{dial: func(ctx context.Context, network string, dst M.Socksaddr) (net.Conn, error) {
			calls.Add(1)
			observed, _ = ctx.Value(privateProbeDialKey{}).(*privateProbeDialObservation)
			conn, err := routeTestDial(ctx, network, dst)
			now.Add(7)
			return conn, err
		}}
		p, c, scope := privateTrafficCandidate(t, node)
		p.lease.clock = now.Load
		if e := p.lease.set(now.Load() + 1_000_000); e != nil {
			t.Fatal(e)
		}
		s, e := newPrivatePathSelector(p, scope, "one", []routeCheck{{Method: "tcp", Target: address}})
		if e != nil {
			t.Fatal(e)
		}
		defer s.Close()
		proof, e := s.probe(context.Background(), c)
		if proof != nil || calls.Load() != 1 {
			t.Fatal("refused target acquired proof or skipped its actual adapter dispatch")
		}
		requirePrivateCheckedFailure(t, e, "dial_failed")
		var checked *privateCheckedFailure
		if !errors.As(e, &checked) || checked.completedBootMS != now.Load() {
			t.Fatal("failure did not preserve the actual guarded BOOTTIME completion")
		}
		if observed == nil || !observed.dispatched.Load() || !observed.completed.Load() || !observed.returnedError.Load() || observed.validConn.Load() {
			t.Fatal("refused TCP outcome was not recorded structurally")
		}
		if text := fmt.Sprintf("%v %#v", e, e); strings.Contains(text, address) || strings.Contains(text, "127.0.0.1") || strings.Contains(text, fmt.Sprint(checked.completedBootMS)) {
			t.Fatal("check error exposed a target")
		}
	})
	for _, method := range []string{"ssh_banner", "tls"} {
		t.Run(method, func(t *testing.T) {
			echo := listenWire(t, func(c net.Conn) { _, _ = io.Copy(c, c) })
			address := echo.listener.Addr().String()
			node := &privateTrafficTestNode{dial: routeTestDial}
			p, c, scope := privateTrafficCandidate(t, node)
			var roots *x509.CertPool
			var target string
			var bad atomic.Bool
			want := "ssh_banner_mismatch"
			if method == "ssh_banner" {
				banner := listenWire(t, func(conn net.Conn) {
					if bad.Load() {
						_, _ = io.WriteString(conn, "WRONG-1.0-fixture\r\n")
					} else {
						_, _ = io.WriteString(conn, "SSH-2.0-fixture\r\n")
					}
				})
				target = banner.listener.Addr().String()
			} else {
				server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
				defer server.Close()
				target = server.URL
				roots = x509.NewCertPool()
				roots.AddCert(server.Certificate())
				want = "tls_failed"
			}
			s, e := newPrivatePathSelector(p, scope, "one", []routeCheck{{Method: method, Target: target}})
			if e != nil {
				t.Fatal(e)
			}
			defer s.Close()
			proof, e := s.probeWithRoots(context.Background(), c, roots)
			if e != nil || !s.selectVerified(proof, 1000) {
				t.Fatal("healthy actual check did not authorize initial selection", e)
			}
			flow, e := s.dialTCP(context.Background(), "tcp", M.ParseSocksaddr(address))
			if e != nil {
				t.Fatal(e)
			}
			defer flow.Close()
			selectionExitEcho(t, flow, "before-observed-target-failure")
			bad.Store(true)
			proof, e = s.probeWithRoots(context.Background(), c, nil)
			if proof != nil {
				t.Fatal("negative target observation minted a selection proof")
			}
			requirePrivateCheckedFailure(t, e, want)
			p.mu.Lock()
			stillSelected := s.active == c.entry && s.flowEpoch == 1
			p.mu.Unlock()
			if !stillSelected {
				t.Fatal("target failure was treated as immediate path withdrawal")
			}
			selectionExitEcho(t, flow, "target-failure-alone-preserves-owned-flow")
		})
	}
	for _, code := range []string{"ok", "unsupported", "cancelled", "outbound_unavailable", "exit_ip_mismatch", "exit_country_mismatch", "unknown-private-target"} {
		if privateCheckedProbeCode(code) {
			t.Fatal("non-attributable result entered the fixed failed-check enum")
		}
	}
	t.Run("late aggregate wrong banner remains unknown", func(t *testing.T) {
		var now atomic.Int64
		now.Store(bootMillis())
		var calls atomic.Int32
		target := listenWire(t, func(conn net.Conn) { now.Add(1000); _, _ = io.WriteString(conn, "WRONG-1.0-fixture\r\n") })
		node := &privateTrafficTestNode{dial: func(ctx context.Context, network string, dst M.Socksaddr) (net.Conn, error) {
			calls.Add(1)
			return routeTestDial(ctx, network, dst)
		}}
		p, c, scope := privateTrafficCandidate(t, node)
		p.lease.clock = now.Load
		if e := p.lease.set(now.Load() + 1_000_000); e != nil {
			t.Fatal(e)
		}
		s, e := newPrivatePathSelector(p, scope, "one", []routeCheck{{Method: "ssh_banner", Target: target.listener.Addr().String()}})
		if e != nil {
			t.Fatal(e)
		}
		defer s.Close()
		before := now.Load()
		work := context.WithValue(context.Background(), privateAdaptiveWorkDeadlineKey{}, before+500)
		if proof, e := s.probe(work, c); proof != nil || e != errPrivatePath || calls.Load() != 1 || now.Load() != before+1000 {
			t.Fatal("aggregate-expired actual target failure gained attribution or skipped its check")
		}
	})
}
