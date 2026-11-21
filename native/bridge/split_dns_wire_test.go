package bridge

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
)

func splitDNSWire(t *testing.T, tag string, handle mdns.HandlerFunc) map[string]any {
	t.Helper()
	socket, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ready := make(chan struct{})
	server := &mdns.Server{PacketConn: socket, Handler: handle, NotifyStartedFunc: func() { close(ready) }}
	done := make(chan error, 1)
	go func() { done <- server.ActivateAndServe() }()
	select {
	case <-ready:
	case err := <-done:
		t.Fatal("DNS fixture did not start", err)
	case <-time.After(2 * time.Second):
		t.Fatal("DNS fixture startup deadline")
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := server.ShutdownContext(ctx); err != nil {
			t.Error(err)
		}
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-ctx.Done():
			t.Error("DNS fixture failed to stop")
		}
	})
	return map[string]any{"type": "udp", "tag": tag, "server": "127.0.0.1", "server_port": socket.LocalAddr().(*net.UDPAddr).Port}
}

func TestSplitDNSInternalApplicationAndNoPublicFallback(t *testing.T) {
	const zone = "home.example.invalid"
	const inside = "app." + zone
	const outside = "nothome.example.invalid"
	var inner, outer, leaks, wrongPrivate, mode, requests atomic.Int32
	// Negative value models a silent internal resolver with a real listening socket.
	handler := func(private bool) mdns.HandlerFunc {
		return func(w mdns.ResponseWriter, q *mdns.Msg) {
			if len(q.Question) != 1 {
				t.Error("unexpected DNS question count")
				return
			}
			question := q.Question[0]
			scoped := mdns.IsSubDomain(zone+".", question.Name)
			if private {
				inner.Add(1)
				if !scoped {
					wrongPrivate.Add(1)
				}
			} else {
				outer.Add(1)
				if scoped {
					leaks.Add(1)
				}
			}
			reply := new(mdns.Msg)
			reply.SetReply(q)
			code := int32(mdns.RcodeSuccess)
			if private {
				code = mode.Load()
			}
			if code < 0 {
				return
			}
			reply.Rcode = int(code)
			if code == mdns.RcodeSuccess {
				hdr := mdns.RR_Header{Name: question.Name, Rrtype: question.Qtype, Class: mdns.ClassINET, Ttl: 0}
				switch question.Qtype {
				case mdns.TypeA:
					address := net.IPv4(192, 0, 2, 9)
					if private {
						address = net.IPv4(127, 0, 0, 1)
					}
					reply.Answer = []mdns.RR{&mdns.A{Hdr: hdr, A: address}}
				case mdns.TypeAAAA:
					reply.Answer = []mdns.RR{&mdns.AAAA{Hdr: hdr, AAAA: net.ParseIP("2001:db8::19")}}
				}
			}
			if err := w.WriteMsg(reply); err != nil {
				t.Error(err)
			}
		}
	}
	private := splitDNSWire(t, "internal", handler(true))
	public := splitDNSWire(t, "public", handler(false))
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || !strings.HasPrefix(r.Host, inside+":") || r.URL.Path != "/ready" {
			w.WriteHeader(404)
			return
		}
		requests.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(target.Close)
	remote, _ := url.Parse(target.URL)
	entry := httpWire(t, remote.Host, "test-user", "test-pass")
	node := entry.node("http", "entry")
	node["username"], node["password"] = "test-user", "test-pass"
	instance, ctx := wireNetworkBox(t, nil, []map[string]any{{"type": "direct", "tag": "direct"}, node}, map[string]any{"dns": map[string]any{
		"servers": []any{private, public}, "rules": []any{map[string]any{"domain_suffix": []string{zone}, "action": "route", "server": "internal"}}, "final": "public",
	}})
	router := service.FromContext[adapter.DNSRouter](ctx)
	if router == nil {
		t.Fatal("missing native DNS router")
	}
	query := func(name string, kind uint16, deadline time.Duration) (*mdns.Msg, error) {
		q := new(mdns.Msg)
		q.SetQuestion(mdns.Fqdn(name), kind)
		ctx, cancel := context.WithTimeout(context.Background(), deadline)
		defer cancel()
		return router.Exchange(ctx, q, adapter.DNSQueryOptions{DisableCache: true})
	}
	requireA := func(t *testing.T, name, want string) string {
		t.Helper()
		r, err := query(name, mdns.TypeA, 2*time.Second)
		if err != nil || r == nil || r.Rcode != mdns.RcodeSuccess || len(r.Answer) != 1 {
			t.Fatal("expected A answer", err)
		}
		a, ok := r.Answer[0].(*mdns.A)
		if !ok || a.A.String() != want {
			t.Fatal("wrong resolver or answer")
		}
		return a.A.String()
	}
	t.Run("dns_tcp_http", func(t *testing.T) {
		addr := requireA(t, inside, "127.0.0.1")
		r, err := query(zone, mdns.TypeAAAA, 2*time.Second)
		if err != nil || r == nil || r.Rcode != mdns.RcodeSuccess || len(r.Answer) != 1 {
			t.Fatal("zone apex AAAA", err)
		}
		a, ok := r.Answer[0].(*mdns.AAAA)
		if !ok || a.AAAA.String() != "2001:db8::19" {
			t.Fatal("wrong AAAA answer")
		}
		outbound, ok := instance.Outbound().Outbound("entry")
		if !ok {
			t.Fatal("missing configured proxy")
		}
		tr := &http.Transport{DisableKeepAlives: true, DialContext: func(ctx context.Context, network, endpoint string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(endpoint)
			if err != nil || host != inside || port != remote.Port() {
				return nil, fmt.Errorf("unexpected HTTP target")
			}
			return outbound.DialContext(ctx, network, M.ParseSocksaddr(net.JoinHostPort(addr, port)))
		}}
		defer tr.CloseIdleConnections()
		client := http.Client{Transport: tr, Timeout: 2 * time.Second}
		res, err := client.Get("http://" + net.JoinHostPort(inside, remote.Port()) + "/ready")
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		if _, err = io.Copy(io.Discard, res.Body); err != nil || res.StatusCode != 204 || entry.calls.Load() != 1 || requests.Load() != 1 {
			t.Fatal("internal application request", err)
		}
	})
	for _, fault := range []struct {
		name string
		code int32
	}{{"nxdomain", mdns.RcodeNameError}, {"servfail", mdns.RcodeServerFailure}, {"silent", -1}} {
		t.Run(fault.name, func(t *testing.T) {
			mode.Store(fault.code)
			previous := inner.Load()
			r, err := query(fault.name+"."+zone, mdns.TypeA, 750*time.Millisecond)
			if err == nil && (r == nil || r.Rcode == mdns.RcodeSuccess || fault.code >= 0 && r.Rcode != int(fault.code)) {
				t.Fatal("unavailable private name received an unexpected result")
			}
			if inner.Load() <= previous || leaks.Load() != 0 {
				t.Fatal("private query was lost or reached public DNS")
			}
			requireA(t, outside, "192.0.2.9")
		})
	}
	t.Run("recovery", func(t *testing.T) {
		mode.Store(mdns.RcodeSuccess)
		requireA(t, "back."+zone, "127.0.0.1")
		if outer.Load() < 3 || leaks.Load() != 0 || wrongPrivate.Load() != 0 {
			t.Fatal("DNS zone isolation failed")
		}
	})
}
