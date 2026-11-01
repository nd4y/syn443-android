package bridge

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func routeTestDial(ctx context.Context, _ string, d M.Socksaddr) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, "tcp", d.String())
}
func TestRouteProbeUsesChosenDialerWithoutDirectFallback(t *testing.T) {
	calls := 0
	dial := func(context.Context, string, M.Socksaddr) (net.Conn, error) {
		calls++
		a, b := net.Pipe()
		go func() { defer b.Close(); _, _ = io.WriteString(b, "SSH-2.0-synthetic\r\n") }()
		return a, nil
	}
	code, complete := probeRoute(context.Background(), dial, routeCheck{"ssh_banner", "192.0.2.11:22"})
	if code != "ok" || !complete || calls != 1 {
		t.Fatal("selected dialer was not used")
	}
	code, complete = probeRoute(context.Background(), func(context.Context, string, M.Socksaddr) (net.Conn, error) {
		return nil, errors.New("private endpoint must not escape")
	}, routeCheck{"tcp", "192.0.2.11:22"})
	if code != "dial_failed" || !complete {
		t.Fatal("failed path silently escaped or error text leaked")
	}
}
func TestRouteTLSStrict204AndCertificateFailures(t *testing.T) {
	var status atomic.Int32
	status.Store(204)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(int(status.Load())) }))
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	code, complete := probeRouteWithRoots(context.Background(), routeTestDial, routeCheck{"https_204", server.URL}, roots)
	if code != "ok" || !complete {
		t.Fatalf("trusted204 rejected: %s", code)
	}
	status.Store(302)
	code, _ = probeRouteWithRoots(context.Background(), routeTestDial, routeCheck{"https_204", server.URL}, roots)
	if code != "http_response_mismatch" {
		t.Fatal("redirect accepted")
	}
	code, _ = probeRoute(context.Background(), routeTestDial, routeCheck{"tls", server.URL})
	if code != "tls_failed" {
		t.Fatal("untrusted TLS accepted")
	}
}
func TestRoutePlansRejectUnsupportedOversizedAndCredentialTargets(t *testing.T) {
	// Synthetic userinfo is constructed by the URL library: no credential URL is shipped in source.
	credentialTarget := (&url.URL{Scheme: "https", Host: "example.org", User: url.UserPassword("fixture-user", "fixture-pass")}).String()
	for _, c := range []routeCheck{{"icmp", "192.0.2.1"}, {"https_204", "http://example.org"}, {"https_204", credentialTarget}, {"tcp", "example.org:0"}, {"tcp", "example.org:65536"}, {"tcp", "example.org:ssh"}, {"tls", "https://example.org:65536"}, {"tcp", strings.Repeat("x", 2049)}} {
		if validRouteCheck(c) {
			t.Fatal("invalid check admitted")
		}
	}
	p := routePlan{ID: "route-1", Outbound: "test", Checks: []routeCheck{{"tcp", "example.org:443"}}}
	if !validRouteRequest(routeRequest{"job", []routePlan{p}}) || validRouteRequest(routeRequest{"job", []routePlan{p, p}}) {
		t.Fatal("duplicate boundary invalid")
	}
}

type routeTestOutbound struct {
	adapter.Outbound
	dial routeDial
}

func (o routeTestOutbound) DialContext(c context.Context, n string, a M.Socksaddr) (net.Conn, error) {
	return o.dial(c, n, a)
}
func TestCancelledUninterruptibleRouteCannotAdmitAnotherBatchOrPublishLate(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	o := routeTestOutbound{dial: func(context.Context, string, M.Socksaddr) (net.Conn, error) {
		close(entered)
		<-release
		return nil, errors.New("test")
	}}
	runner := newRouteRunner(context.Background(), func(string) (adapter.Outbound, bool) { return o, true })
	raw := `{"request":"first","routes":[{"id":"route-1","outbound":"test","checks":[{"method":"tcp","target":"192.0.2.1:443"}]}]}`
	if !runner.start(raw) {
		t.Fatal("start rejected")
	}
	<-entered
	runner.stop()
	if runner.start(raw) {
		t.Fatal("cancelled blocked batch expanded worker count")
	}
	close(release)
	deadline := time.Now().Add(time.Second)
	for {
		runner.mu.Lock()
		busy := runner.busy
		runner.mu.Unlock()
		if !busy {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("worker did not drain")
		}
		time.Sleep(time.Millisecond)
	}
	var report routeReport
	if json.Unmarshal([]byte(runner.snapshot()), &report) != nil || report.Request != "" || len(report.Results) != 0 {
		t.Fatal("late cancelled result published")
	}
}
func TestParentCancellationIsIncompleteNotAProxyFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	code, complete := probeRoute(ctx, func(c context.Context, _ string, _ M.Socksaddr) (net.Conn, error) { return nil, c.Err() }, routeCheck{"tcp", "192.0.2.1:443"})
	if code != "cancelled" || complete {
		t.Fatal("cancellation poisoned path health")
	}
}

func TestRouteDialReturningAfterItsDeadlineCannotBecomeSuccess(t *testing.T) {
	var peer net.Conn
	var elapsed int64 = 100
	dial := func(ctx context.Context, _ string, _ M.Socksaddr) (net.Conn, error) {
		<-ctx.Done()
		elapsed += 4000
		a, b := net.Pipe()
		peer = b
		return a, nil
	}
	// The boot-time budget makes late observations incomplete, including when
	// a suspended or uncooperative dial returns a connection after cancellation.
	parent, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	code, complete := probeRouteWithClock(parent, dial, routeCheck{"tcp", "192.0.2.1:443"}, nil, func() int64 { return elapsed })
	if peer != nil {
		peer.Close()
	}
	if code != "check_timeout" || complete {
		t.Fatal("late dial invented a passing observation")
	}
}

type earlyRouteConn struct {
	net.Conn
	peer   net.Conn
	writes int
}

func (c *earlyRouteConn) NeedHandshake() bool { return c.writes == 0 }
func (c *earlyRouteConn) Write(b []byte) (int, error) {
	if len(b) != 0 {
		return c.Conn.Write(b)
	}
	c.writes++
	go func() { defer c.peer.Close(); _, _ = io.WriteString(c.peer, "SSH-2.0-after-proxy-handshake\r\n") }()
	return 0, nil
}
func TestRouteSSHFlushesLazyProxyRequestBeforeReadingServerBanner(t *testing.T) {
	a, b := net.Pipe()
	early := &earlyRouteConn{Conn: a, peer: b}
	code, complete := probeRoute(context.Background(), func(context.Context, string, M.Socksaddr) (net.Conn, error) { return early, nil }, routeCheck{"ssh_banner", "192.0.2.9:22"})
	if code != "ok" || !complete || early.writes != 1 {
		t.Fatal("server-first probe did not complete its lazy proxy handshake")
	}
}

func TestRouteSuspendCannotRefreshAnOldBufferedSuccess(t *testing.T) {
	var now int64 = 100
	dial := func(context.Context, string, M.Socksaddr) (net.Conn, error) {
		a, b := net.Pipe()
		now += 60_000
		go b.Close()
		return a, nil
	}
	code, complete := probeRouteWithClock(context.Background(), dial, routeCheck{"tcp", "192.0.2.1:443"}, nil, func() int64 { return now })
	if code != "check_timeout" || complete {
		t.Fatal("suspend converted old data into a fresh success")
	}
}
func TestRouteLeaseExpiryAfterDialCannotPublishSuccess(t *testing.T) {
	var allowed atomic.Bool
	allowed.Store(true)
	outbound := routeTestOutbound{dial: func(context.Context, string, M.Socksaddr) (net.Conn, error) {
		a, b := net.Pipe()
		allowed.Store(false)
		go b.Close()
		return a, nil
	}}
	r := newRouteRunner(context.Background(), func(string) (adapter.Outbound, bool) { return outbound, true })
	r.limit = func() time.Duration {
		if allowed.Load() {
			return 30 * time.Second
		}
		return 0
	}
	result := r.runPlan(context.Background(), routePlan{ID: "route-1", Outbound: "test", Checks: []routeCheck{{"tcp", "192.0.2.1:443"}}})
	if result.OK || result.Complete || result.Code != "cancelled" {
		t.Fatal("expired authorization published route readiness")
	}
}
func TestRouteExpiredBootBudgetDoesNotDialAndProbePanicCannotKillOtherRoute(t *testing.T) {
	calls := 0
	outbound := routeTestOutbound{dial: func(context.Context, string, M.Socksaddr) (net.Conn, error) {
		calls++
		panic("synthetic probe failure")
	}}
	r := newRouteRunner(context.Background(), func(string) (adapter.Outbound, bool) { return outbound, true })
	p := routePlan{ID: "route-1", Outbound: "test", Checks: []routeCheck{{"tcp", "192.0.2.1:443"}}}
	closed := r.runPlan(context.WithValue(context.Background(), routeDeadlineKey{}, bootMillis()-1), p)
	if closed.OK || closed.Complete || calls != 0 {
		t.Fatal("expired batch admitted work")
	}
	failed := r.runPlan(context.Background(), p)
	if failed.OK || failed.Complete || failed.Code != "probe_unavailable" {
		t.Fatal("probe panic was not contained")
	}
	r.lookup = func(string) (adapter.Outbound, bool) {
		return routeTestOutbound{dial: func(context.Context, string, M.Socksaddr) (net.Conn, error) {
			a, b := net.Pipe()
			go b.Close()
			return a, nil
		}}, true
	}
	if next := r.runPlan(context.Background(), p); !next.OK || !next.Complete {
		t.Fatal("one probe exception poisoned independent work")
	}
}
