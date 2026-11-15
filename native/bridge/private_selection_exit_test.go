package bridge

import (
	"context"
	"crypto/x509"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

func selectionExitEcho(t *testing.T, c net.Conn, text string) {
	t.Helper()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.WriteString(c, text); err != nil {
		t.Fatal("selected flow could not send real payload", err)
	}
	b := make([]byte, len(text))
	if _, err := io.ReadFull(c, b); err != nil || string(b) != text {
		t.Fatal("selected flow lost real payload", err)
	}
	_ = c.SetDeadline(time.Time{})
}

func selectionExitActivate(t *testing.T, s *privatePathSelector, c *privatePathCandidate, roots *x509.CertPool) {
	t.Helper()
	proof, err := s.probeWithRoots(context.Background(), c, roots)
	if err != nil || !s.selectVerified(proof, 1000) {
		t.Fatal("fresh actual probe could not select candidate", err)
	}
}

func selectionExitFlow(t *testing.T, s *privatePathSelector, address string) net.Conn {
	t.Helper()
	c, err := s.dialTCP(context.Background(), "tcp", M.ParseSocksaddr(address))
	if err != nil {
		t.Fatal("selected candidate did not connect", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestPrivateSelectionHardExitMismatchWithdrawsOnlyItsGroup(t *testing.T) {
	for _, method := range []string{"https_exit_country", "https_exit_ip"} {
		t.Run(method, func(t *testing.T) {
			var body atomic.Value
			good, bad := `{"ip":"192.0.2.1","country":"RU"}`, `{"ip":"192.0.2.1","country":"DE"}`
			if method == "https_exit_ip" {
				good, bad = "192.0.2.1", "192.0.2.2"
			}
			body.Store(good)
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, body.Load().(string)) }))
			defer server.Close()
			roots := x509.NewCertPool()
			roots.AddCert(server.Certificate())
			echo := listenWire(t, func(c net.Conn) { _, _ = io.Copy(c, c) })
			address := echo.listener.Addr().String()
			node := &privateTrafficTestNode{dial: routeTestDial}
			p, candidate, scope := privateTrafficCandidate(t, node)
			check := routeCheck{Method: method, Target: server.URL, ExpectedExitClass: "RU"}
			if method == "https_exit_ip" {
				check.ExpectedExitClass, check.ExpectedIP = "", "192.0.2.1"
			}
			a, err := newPrivatePathSelector(p, scope, "one", []routeCheck{check})
			if err != nil {
				t.Fatal(err)
			}
			defer a.Close()
			b, err := newPrivatePathSelector(p, scope, "two", []routeCheck{{Method: "tcp", Target: address}})
			if err != nil {
				t.Fatal(err)
			}
			defer b.Close()
			selectionExitActivate(t, a, candidate, roots)
			selectionExitActivate(t, b, candidate, nil)
			flowA, flowB := selectionExitFlow(t, a, address), selectionExitFlow(t, b, address)
			selectionExitEcho(t, flowA, "before-hard-exit-evidence")
			selectionExitEcho(t, flowB, "shared-candidate-other-group")
			stale, err := a.probeWithRoots(context.Background(), candidate, roots)
			if err != nil {
				t.Fatal(err)
			}
			readDone := make(chan error, 1)
			go func() { _, err := flowA.Read(make([]byte, 1)); readDone <- err }()
			body.Store(bad)
			if proof, err := a.probeWithRoots(context.Background(), candidate, roots); proof != nil || err != errPrivatePath {
				t.Fatal("wrong public exit minted proof")
			}
			select {
			case err := <-readDone:
				if err != errPrivatePath {
					t.Fatal("revoked group published an in-flight result", err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("wrong-exit evidence did not interrupt existing group socket")
			}
			if c, err := a.dialTCP(context.Background(), "tcp", M.ParseSocksaddr(address)); c != nil || err != errPrivatePath {
				t.Fatal("wrong-exit group retained new-flow authority")
			}
			if a.selectVerified(stale, 1000) {
				t.Fatal("pre-withdrawal proof replayed across group epoch")
			}
			selectionExitEcho(t, flowB, "other-group-existing-socket-remains")
			selectionExitEcho(t, selectionExitFlow(t, b, address), "other-group-new-socket-remains")
			p.mu.Lock()
			valid := a.active == nil && b.active == candidate.entry && candidate.entry.activeHolds == 1 && !candidate.entry.draining
			p.mu.Unlock()
			if !valid {
				t.Fatal("one group's evidence altered another group's candidate ownership")
			}
		})
	}
}

func TestPrivateSelectionUncertainExitEvidenceKeepsCurrentAuthority(t *testing.T) {
	var body atomic.Value
	body.Store(`{"ip":"192.0.2.1","country":"RU"}`)
	var late atomic.Bool
	var now atomic.Int64
	now.Store(bootMillis())
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, body.Load().(string))
		if late.Load() {
			now.Add(4000)
		}
	}))
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	echo := listenWire(t, func(c net.Conn) { _, _ = io.Copy(c, c) })
	address := echo.listener.Addr().String()
	p, candidate, scope := privateTrafficCandidate(t, &privateTrafficTestNode{dial: routeTestDial})
	p.lease.clock = now.Load
	if err := p.lease.set(now.Load() + 1_000_000); err != nil {
		t.Fatal(err)
	}
	s, err := newPrivatePathSelector(p, scope, "one", []routeCheck{{Method: "https_exit_country", Target: server.URL, ExpectedExitClass: "RU"}})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	selectionExitActivate(t, s, candidate, roots)
	flow := selectionExitFlow(t, s, address)
	for _, tc := range []struct {
		name  string
		raw   string
		roots *x509.CertPool
		late  bool
	}{
		{"untrusted TLS", `{"ip":"192.0.2.1","country":"DE"}`, nil, false},
		{"invalid target evidence", `{"ip":"192.0.2.1","country":null}`, roots, false},
		{"late mismatch", `{"ip":"192.0.2.1","country":"DE"}`, roots, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body.Store(tc.raw)
			late.Store(tc.late)
			if proof, err := s.probeWithRoots(context.Background(), candidate, tc.roots); proof != nil || err != errPrivatePath {
				t.Fatal("uncertain target minted positive evidence")
			}
			p.mu.Lock()
			valid := s.active == candidate.entry && s.flowEpoch == 1
			p.mu.Unlock()
			if !valid {
				t.Fatal("uncertain target evidence revoked active route")
			}
			selectionExitEcho(t, flow, "uncertain-evidence-keeps-owned-stream")
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if proof, err := s.probeWithRoots(ctx, candidate, roots); proof != nil || err != errPrivatePath {
		t.Fatal("cancelled probe minted evidence")
	}
	selectionExitEcho(t, flow, "cancelled-probe-preserves-current-stream")
	if !p.changeScope("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb") {
		t.Fatal("scope replacement denied")
	}
	if n, err := flow.Write([]byte("stale")); n != 0 || err != errPrivatePath {
		t.Fatal("group wrapper ignored full-context replacement")
	}
}

type selectionCloseConn struct {
	net.Conn
	once       sync.Once
	afterClose func()
}

func (c *selectionCloseConn) Close() error {
	var err error
	c.once.Do(func() { err = c.Conn.Close(); c.afterClose() })
	return err
}

func TestPrivateSelectionChecksAggregateBootBudgetBeforeNextTarget(t *testing.T) {
	for _, advance := range []int64{12_000, 12_001, -1} {
		t.Run(strconv.FormatInt(advance, 10), func(t *testing.T) {
			var now atomic.Int64
			now.Store(bootMillis())
			var afterFirst atomic.Bool
			var dials atomic.Int32
			echo := listenWire(t, func(c net.Conn) { _, _ = io.Copy(c, c) })
			address := echo.listener.Addr().String()
			node := &privateTrafficTestNode{dial: func(ctx context.Context, network string, dst M.Socksaddr) (net.Conn, error) {
				dials.Add(1)
				conn, err := routeTestDial(ctx, network, dst)
				if err != nil {
					return nil, err
				}
				return &selectionCloseConn{Conn: conn, afterClose: func() { afterFirst.Store(true) }}, nil
			}}
			p, candidate, scope := privateTrafficCandidate(t, node)
			p.lease.clock = func() int64 {
				current := now.Load()
				// Advance immediately after the first check's final sample is read,
				// before the caller can admit another target. Both sockets are real.
				if afterFirst.CompareAndSwap(true, false) {
					now.Add(advance)
				}
				return current
			}
			if err := p.lease.set(now.Load() + 1_000_000); err != nil {
				t.Fatal(err)
			}
			checks := []routeCheck{{Method: "tcp", Target: address}, {Method: "tcp", Target: address}}
			s, err := newPrivatePathSelector(p, scope, "one", checks)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			if proof, err := s.probe(context.Background(), candidate); proof != nil || err != errPrivatePath || dials.Load() != 1 {
				t.Fatal("expired aggregate budget admitted next target or minted proof", dials.Load())
			}
		})
	}
	t.Run("epoch overflow closes authority", func(t *testing.T) {
		p, candidate, scope := privateTrafficCandidate(t, &privateTrafficTestNode{dial: routeTestDial})
		s, err := newPrivatePathSelector(p, scope, "one", []routeCheck{{Method: "tcp", Target: "127.0.0.1:1"}})
		if err != nil {
			t.Fatal(err)
		}
		p.mu.Lock()
		s.flowEpoch = math.MaxUint64
		s.withdrawLocked()
		valid := s.closed && p.selectors[s.group] == nil
		p.mu.Unlock()
		if !valid {
			t.Fatal("epoch overflow reused authority")
		}
		if proof, err := s.probe(context.Background(), candidate); proof != nil || err != errPrivatePath {
			t.Fatal("overflowed selector admitted a probe")
		}
	})
}

type selectionBlockedCloseConn struct {
	net.Conn
	once    sync.Once
	entered chan struct{}
	release <-chan struct{}
}

func (c *selectionBlockedCloseConn) Close() error {
	var err error
	c.once.Do(func() {
		close(c.entered)
		<-c.release
		err = c.Conn.Close()
	})
	return err
}

func TestPrivateSelectionBlockedGroupCloseCannotBlockOtherFlowWithdrawal(t *testing.T) {
	var body atomic.Value
	body.Store(`{"ip":"192.0.2.1","country":"RU"}`)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, body.Load().(string)) }))
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	echo := listenWire(t, func(c net.Conn) { _, _ = io.Copy(c, c) })
	address := echo.listener.Addr().String()
	entered, release := make(chan struct{}), make(chan struct{})
	var unblock sync.Once
	releaseBlocked := func() { unblock.Do(func() { close(release) }) }
	var echoDials atomic.Int32
	node := &privateTrafficTestNode{dial: func(ctx context.Context, network string, dst M.Socksaddr) (net.Conn, error) {
		conn, err := routeTestDial(ctx, network, dst)
		if err != nil {
			return nil, err
		}
		if dst.String() == address && echoDials.Add(1) == 1 {
			return &selectionBlockedCloseConn{Conn: conn, entered: entered, release: release}, nil
		}
		return conn, nil
	}}
	p, candidate, scope := privateTrafficCandidate(t, node)
	// Registered after pool cleanup so failures release only our blocked fixture
	// before waiting for the pool's actual retirement worker to exit.
	t.Cleanup(releaseBlocked)
	s, err := newPrivatePathSelector(p, scope, "one", []routeCheck{{Method: "https_exit_country", Target: server.URL, ExpectedExitClass: "RU"}})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	selectionExitActivate(t, s, candidate, roots)
	blocked, err := s.dialTCP(context.Background(), "tcp", M.ParseSocksaddr(address))
	if err != nil {
		t.Fatal(err)
	}
	selectionExitEcho(t, blocked, "first-real-socket")
	other, err := s.dialTCP(context.Background(), "tcp", M.ParseSocksaddr(address))
	if err != nil {
		t.Fatal(err)
	}
	selectionExitEcho(t, other, "second-real-socket")
	done := make(chan error, 1)
	go func() { _, err := other.Read(make([]byte, 1)); done <- err }()
	body.Store(`{"ip":"192.0.2.1","country":"DE"}`)
	if proof, err := s.probeWithRoots(context.Background(), candidate, roots); proof != nil || err != errPrivatePath {
		t.Fatal("hard mismatch did not revoke group")
	}
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("blocked closer was not invoked")
	}
	select {
	case err := <-done:
		if err != errPrivatePath {
			t.Fatal("another socket published after withdrawal", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("one blocked closer prevented independent socket cancellation")
	}
	if n, err := blocked.Write([]byte("no-authority")); n != 0 || err != errPrivatePath || p.snapshot().Holds == 0 {
		t.Fatal("blocked owner lost its reservation or kept data authority")
	}
	releaseBlocked()
	if err := blocked.Close(); err != nil {
		t.Fatal(err)
	}
	_ = other.Close()
	awaitPrivatePool(t, func() bool { return p.snapshot().Holds == 0 })
}
