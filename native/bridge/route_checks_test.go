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