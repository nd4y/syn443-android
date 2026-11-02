package bridge

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/service"
)

func dnsAnswerWire(raw []byte, calls *atomic.Int32) ([]byte, error) {
	query := new(mdns.Msg)
	if query.Unpack(raw) != nil || len(query.Question) != 1 || query.Question[0].Name != "probe.example.invalid." || query.Question[0].Qtype != mdns.TypeA {
		return nil, errors.New("unexpected synthetic DNS question")
	}
	calls.Add(1)
	reply := new(mdns.Msg)
	reply.SetReply(query)
	reply.Answer = []mdns.RR{&mdns.A{Hdr: mdns.RR_Header{Name: query.Question[0].Name, Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 30}, A: net.IPv4(198, 51, 100, 9)}}
	return reply.Pack()
}

func dnsWire(t *testing.T, transport string) (map[string]any, *atomic.Int32) {
	t.Helper()
	certificate, _, keyPair := wireTLS(t)
	calls := &atomic.Int32{}
	options := map[string]any{"type": transport, "tag": "resolver", "server": "127.0.0.1"}
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{keyPair}, MinVersion: tls.VersionTLS13}
	if transport != "udp" && transport != "tcp" {
		options["tls"] = map[string]any{"enabled": true, "server_name": "wire.example.invalid", "certificate": []string{certificate}}
	}
	var address net.Addr
	switch transport {
	case "udp", "tcp", "tls":
		started := make(chan struct{})
		server := &mdns.Server{NotifyStartedFunc: func() { close(started) }, ReadTimeout: 2 * time.Second, WriteTimeout: 2 * time.Second, Handler: mdns.HandlerFunc(func(writer mdns.ResponseWriter, query *mdns.Msg) {
			raw, err := query.Pack()
			if err != nil {
				return
			}
			reply, err := dnsAnswerWire(raw, calls)
			if err != nil {
				return
			}
			_, _ = writer.Write(reply)
		})}
		if transport == "udp" {
			socket, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			server.Net, server.PacketConn = "udp", socket
			address = socket.LocalAddr()
		} else {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			if transport == "tls" {
				listener = tls.NewListener(listener, tlsConfig)
			}
			server.Net, server.Listener = "tcp", listener
			address = listener.Addr()
		}
		done := make(chan struct{})
		go func() { defer close(done); _ = server.ActivateAndServe() }()
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_ = server.ShutdownContext(ctx)
			select {
			case <-done:
			case <-ctx.Done():
				t.Error("DNS server did not retire")
			}
		})
		select {
		case <-started:
		case <-time.After(2 * time.Second):
			t.Fatal("DNS fixture failed to become ready")
		}
	case "https", "h3":
		handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			if request.URL.Path != "/dns-query" {
				writer.WriteHeader(404)
				return
			}
			var raw []byte
			var err error
			if request.Method == "GET" {
				raw, err = base64.RawURLEncoding.DecodeString(request.URL.Query().Get("dns"))
			} else if request.Method == "POST" && request.Header.Get("Content-Type") == "application/dns-message" {
				raw, err = io.ReadAll(io.LimitReader(request.Body, 4097))
			} else {
				writer.WriteHeader(405)
				return
			}
			if err != nil || len(raw) > 4096 {
				writer.WriteHeader(400)
				return
			}
			answer, err := dnsAnswerWire(raw, calls)
			if err != nil {
				writer.WriteHeader(400)
				return
			}
			writer.Header().Set("Content-Type", "application/dns-message")
			_, _ = writer.Write(answer)
		})
		if transport == "https" {
			server := httptest.NewUnstartedServer(handler)
			server.TLS = tlsConfig
			server.EnableHTTP2 = true
			server.StartTLS()
			address = server.Listener.Addr()
			t.Cleanup(server.Close)
		} else {
			socket, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			address = socket.LocalAddr()
			tlsConfig.NextProtos = []string{"h3"}
			server := &http3.Server{TLSConfig: tlsConfig, Handler: handler, QUICConfig: &quic.Config{MaxIdleTimeout: 2 * time.Second}}
			done := make(chan struct{})
			go func() { defer close(done); _ = server.Serve(socket) }()
			t.Cleanup(func() {
				_ = server.Close()
				_ = socket.Close()
				select {
				case <-done:
				case <-time.After(3 * time.Second):
					t.Error("H3 DNS server did not retire")
				}
			})
		}
		options["path"] = "/dns-query"
	case "quic":
		tlsConfig.NextProtos = []string{"doq"}
		listener, err := quic.ListenAddr("127.0.0.1:0", tlsConfig, &quic.Config{MaxIdleTimeout: 2 * time.Second})
		if err != nil {
			t.Fatal(err)
		}
		address = listener.Addr()
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			defer close(done)
			conn, err := listener.Accept(ctx)
			if err != nil {
				return
			}
			defer conn.CloseWithError(0, "")
			stream, err := conn.AcceptStream(ctx)
			if err != nil {
				return
			}
			defer stream.CancelRead(0)
			_ = stream.SetDeadline(time.Now().Add(2 * time.Second))
			var length [2]byte
			if _, err = io.ReadFull(stream, length[:]); err != nil {
				return
			}
			size := int(binary.BigEndian.Uint16(length[:]))
			if size < 1 || size > 4096 {
				return
			}
			raw := make([]byte, size)
			if _, err = io.ReadFull(stream, raw); err != nil {
				return
			}
			answer, err := dnsAnswerWire(raw, calls)
			if err != nil {
				return
			}
			binary.BigEndian.PutUint16(length[:], uint16(len(answer)))
			_, _ = stream.Write(append(length[:], answer...))
			_ = stream.Close()
			// A QUIC stream Close sends FIN asynchronously. Keep the connection
			// alive until the client/fixture retires instead of racing the reply.
			select {
			case <-ctx.Done():
			case <-conn.Context().Done():
			}
		}()
		t.Cleanup(func() {
			cancel()
			_ = listener.Close()
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Error("QUIC DNS server did not retire")
			}
		})
	default:
		t.Fatal("unknown DNS fixture transport")
	}
	_, port, err := net.SplitHostPort(address.String())
	if err != nil {
		t.Fatal(err)
	}
	var number int
	for _, c := range port {
		number = number*10 + int(c-'0')
	}
	options["server_port"] = number
	return options, calls
}

func TestRegisteredDNSTransportsActualQuestionAnswerAndTLSBoundary(t *testing.T) {
	for _, transport := range []string{"udp", "tcp", "tls", "https", "quic", "h3"} {
		t.Run(transport, func(t *testing.T) {
			for _, badTLS := range []bool{false, true} {
				if badTLS && (transport == "udp" || transport == "tcp") {
					continue
				}
				t.Run(map[bool]string{false: "valid", true: "wrong-trust-root"}[badTLS], func(t *testing.T) {
					server, calls := dnsWire(t, transport)
					if badTLS {
						certificate, _, _ := wireTLS(t)
						server["tls"].(map[string]any)["certificate"] = []string{certificate}
					}
					_, ctx := wireNetworkBox(t, nil, []map[string]any{{"type": "direct", "tag": "direct"}}, map[string]any{"dns": map[string]any{"servers": []any{server}, "final": "resolver", "strategy": "ipv4_only"}})
					router := service.FromContext[adapter.DNSRouter](ctx)
					if router == nil {
						t.Fatal("actual DNS router missing")
					}
					query := new(mdns.Msg)
					query.SetQuestion("probe.example.invalid.", mdns.TypeA)
					deadline, cancel := context.WithTimeout(context.Background(), 2*time.Second)
					defer cancel()
					reply, err := router.Exchange(deadline, query, adapter.DNSQueryOptions{DisableCache: true})
					if badTLS {
						if err == nil || calls.Load() != 0 {
							t.Fatal("untrusted DNS TLS delivered a question")
						}
						return
					}
					if err != nil || reply == nil || reply.Id != query.Id || len(reply.Answer) != 1 || calls.Load() != 1 {
						t.Fatal("actual DNS transport failed", err)
					}
					answer, ok := reply.Answer[0].(*mdns.A)
					if !ok || !answer.A.Equal(net.IPv4(198, 51, 100, 9)) {
						t.Fatal("DNS answer mismatch")
					}
				})
			}
		})
	}
}

func TestDNSOverHTTPEntryUsesExactProxyAndCannotEscapeAuthenticationFailure(t *testing.T) {
	for _, denied := range []bool{false, true} {
		t.Run(strconv.FormatBool(denied), func(t *testing.T) {
			server, calls := dnsWire(t, "tls")
			endpoint := net.JoinHostPort("127.0.0.1", strconv.Itoa(server["server_port"].(int)))
			entry := httpWire(t, endpoint, "fixture-user", "fixture-pass")
			node := entry.node("http", "entry")
			node["username"] = "fixture-user"
			node["password"] = "fixture-pass"
			if denied {
				node["password"] = "wrong-pass"
			}
			server["detour"] = "entry"
			_, ctx := wireNetworkBox(t, nil, []map[string]any{{"type": "direct", "tag": "direct"}, node}, map[string]any{"dns": map[string]any{"servers": []any{server}, "final": "resolver"}})
			query := new(mdns.Msg)
			query.SetQuestion("probe.example.invalid.", mdns.TypeA)
			deadline, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			reply, err := service.FromContext[adapter.DNSRouter](ctx).Exchange(deadline, query, adapter.DNSQueryOptions{DisableCache: true})
			if denied {
				if err == nil || calls.Load() != 0 || entry.calls.Load() < 1 {
					t.Fatal("failed DNS entry bypassed its authentication")
				}
				return
			}
			if err != nil || reply == nil || len(reply.Answer) != 1 || calls.Load() != 1 || entry.calls.Load() != 1 {
				t.Fatal("DNS did not use the complete configured proxy path", err)
			}
		})
	}
}
