package bridge

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	boxservice "github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/direct"
	proxyhttp "github.com/sagernet/sing-box/protocol/http"
	"github.com/sagernet/sing-box/protocol/socks"
	proxyssh "github.com/sagernet/sing-box/protocol/ssh"
	"github.com/sagernet/sing-box/protocol/vless"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
)

// Real proxy client modules, real loopback handshakes and payloads. No TUN or
// external provider is needed, so these run with the ordinary native Actions gate.
func wireBox(t *testing.T, nodes ...map[string]any) *box.Box {
	t.Helper()
	return wireConfiguredBox(t, nil, nodes)
}
func wireConfiguredBox(t *testing.T, listeners, nodes []map[string]any) *box.Box {
	t.Helper()
	registry := outbound.NewRegistry()
	direct.RegisterOutbound(registry)
	proxyhttp.RegisterOutbound(registry)
	socks.RegisterOutbound(registry)
	vless.RegisterOutbound(registry)
	proxyssh.RegisterOutbound(registry)
	ir := inbound.NewRegistry()
	vless.RegisterInbound(ir)
	dr := dns.NewTransportRegistry()
	registerPhysicalDNS(dr, dnsProtector{exchange: func([]byte) ([]byte, error) {
		t.Error("IP-only wire fixture attempted DNS")
		return nil, errors.New("unexpected fixture DNS")
	}})
	ctx := box.Context(context.Background(), ir, registry,
		endpoint.NewRegistry(), dr, boxservice.NewRegistry())
	ctx = service.ContextWithDefaultRegistry(ctx)
	raw, err := json.Marshal(map[string]any{"log": map[string]any{"disabled": true}, "outbounds": nodes, "inbounds": listeners})
	if err != nil {
		t.Fatal(err)
	}
	var options option.Options
	if err = options.UnmarshalJSONContext(ctx, raw); err != nil {
		t.Fatal(err)
	}
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = instance.Close() })
	if err = instance.Start(); err != nil {
		t.Fatal(err)
	}
	return instance
}

type wireFixture struct {
	listener    net.Listener
	calls       atomic.Int32
	mu          sync.Mutex
	connections map[net.Conn]bool
	workers     sync.WaitGroup
}

func listenWire(t *testing.T, handle func(net.Conn)) *wireFixture {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &wireFixture{listener: listener, connections: map[net.Conn]bool{}}
	f.workers.Add(1)
	go func() {
		defer f.workers.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			f.calls.Add(1)
			f.mu.Lock()
			f.connections[conn] = true
			f.mu.Unlock()
			f.workers.Add(1)
			go func() {
				defer f.workers.Done()
				defer func() { _ = conn.Close(); f.mu.Lock(); delete(f.connections, conn); f.mu.Unlock() }()
				_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
				handle(conn)
			}()
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		f.mu.Lock()
		for c := range f.connections {
			_ = c.Close()
		}
		f.mu.Unlock()
		done := make(chan struct{})
		go func() { f.workers.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("wire fixture did not retire")
		}
	})
	return f
}
func (f *wireFixture) node(kind, tag string) map[string]any {
	host, port, _ := net.SplitHostPort(f.listener.Addr().String())
	n, _ := strconv.Atoi(port)
	value := map[string]any{"type": kind, "tag": tag, "server": host, "server_port": n}
	if kind == "socks" {
		value["version"] = "5"
	}
	return value
}
func relayWire(client net.Conn, reader io.Reader, address string) {
	upstream, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		return
	}
	defer upstream.Close()
	_ = upstream.SetDeadline(time.Now().Add(3 * time.Second))
	done := make(chan struct{})
	go func() { _, _ = io.Copy(upstream, reader); _ = upstream.Close(); close(done) }()
	_, _ = io.Copy(client, upstream)
	_ = client.Close()
	_ = upstream.Close()
	<-done
}
func httpWire(t *testing.T, destination, username, password string) *wireFixture {
	return listenWire(t, func(conn net.Conn) {
		reader := bufio.NewReader(conn)
		request, err := http.ReadRequest(reader)
		if err != nil {
			return
		}
		if request.Method != "CONNECT" || request.Host != destination {
			_, _ = io.WriteString(conn, "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
			return
		}
		if username != "" && request.Header.Get("Proxy-Authorization") != "Basic "+base64.StdEncoding.EncodeToString([]byte(username+":"+password)) {
			_, _ = io.WriteString(conn, "HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n")
			return
		}
		_, _ = io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
		relayWire(conn, reader, destination)
	})
}
func socksWire(t *testing.T, destination string) *wireFixture {
	return listenWire(t, func(conn net.Conn) {
		var start [2]byte
		if _, err := io.ReadFull(conn, start[:]); err != nil || start[0] != 5 || start[1] < 1 {
			return
		}
		methods := make([]byte, int(start[1]))
		if _, err := io.ReadFull(conn, methods); err != nil {
			return
		}
		found := false
		for _, v := range methods {
			found = found || v == 0
		}
		if !found {
			_, _ = conn.Write([]byte{5, 255})
			return
		}
		_, _ = conn.Write([]byte{5, 0})
		var header [4]byte
		if _, err := io.ReadFull(conn, header[:]); err != nil || header[0] != 5 || header[1] != 1 || header[2] != 0 || header[3] != 1 {
			return
		}
		var target [6]byte
		if _, err := io.ReadFull(conn, target[:]); err != nil {
			return
		}
		address := net.JoinHostPort(net.IP(target[:4]).String(), strconv.Itoa(int(binary.BigEndian.Uint16(target[4:]))))
		if address != destination {
			_, _ = conn.Write([]byte{5, 2, 0, 1, 0, 0, 0, 0, 0, 0})
			return
		}
		_, _ = conn.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0})
		relayWire(conn, conn, address)
	})
}
func payloadWire(t *testing.T, proxy adapter.Outbound, address string) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := proxy.DialContext(ctx, "tcp", M.ParseSocksaddr(address))
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	// Some registered modules deliberately emit their handshake on first write.
	if _, err = io.WriteString(conn, "syn443-wire"); err != nil {
		return err
	}
	reply := make([]byte, len("syn443-wire"))
	_, err = io.ReadFull(conn, reply)
	if err == nil && string(reply) != "syn443-wire" {
		t.Fatal("proxy payload changed")
	}
	return err
}
func TestRegisteredHTTPAndSOCKSActualWireAndDetour(t *testing.T) {
	for _, kind := range []string{"http", "socks", "http-over-socks"} {
		t.Run(kind, func(t *testing.T) {
			target := listenWire(t, func(c net.Conn) { _, _ = io.Copy(c, c) })
			destination := target.listener.Addr().String()
			var nodes []map[string]any
			var hops []*wireFixture
			if kind == "socks" {
				proxy := socksWire(t, destination)
				nodes = []map[string]any{proxy.node("socks", "exit")}
				hops = []*wireFixture{proxy}
			} else {
				proxy := httpWire(t, destination, "fixture-user", "fixture-pass")
				node := proxy.node("http", "exit")
				node["username"] = "fixture-user"
				node["password"] = "fixture-pass"
				nodes = []map[string]any{node}
				hops = []*wireFixture{proxy}
				if kind == "http-over-socks" {
					first := socksWire(t, proxy.listener.Addr().String())
					node["detour"] = "entry"
					nodes = append(nodes, first.node("socks", "entry"))
					hops = append(hops, first)
				}
			}
			instance := wireBox(t, nodes...)
			proxy, ok := instance.Outbound().Outbound("exit")
			if !ok {
				t.Fatal("registered outbound missing")
			}
			if err := payloadWire(t, proxy, destination); err != nil {
				t.Fatal(err)
			}
			if target.calls.Load() != 1 {
				t.Fatal("payload did not use target exactly once")
			}
			for _, hop := range hops {
				if hop.calls.Load() != 1 {
					t.Fatal("actual proxy hop bypassed")
				}
			}
		})
	}
}
func TestRegisteredHTTPAuthAndRefusedProxyNeverDialTargetDirectly(t *testing.T) {
	for _, failure := range []string{"bad-auth", "refused-http", "refused-socks"} {
		t.Run(failure, func(t *testing.T) {
			target := listenWire(t, func(c net.Conn) { _, _ = io.Copy(c, c) })
			fixture := httpWire(t, target.listener.Addr().String(), "fixture-user", "fixture-pass")
			kind := "http"
			if failure == "refused-socks" {
				kind = "socks"
			}
			node := fixture.node(kind, "exit")
			if failure == "bad-auth" {
				node["username"] = "fixture-user"
				node["password"] = "wrong-pass"
			} else {
				_ = fixture.listener.Close()
			}
			instance := wireBox(t, node)
			proxy, ok := instance.Outbound().Outbound("exit")
			if !ok {
				t.Fatal("registered outbound missing")
			}
			if err := payloadWire(t, proxy, target.listener.Addr().String()); err == nil {
				t.Fatal("failed proxy returned a working connection")
			}
			if target.calls.Load() != 0 {
				t.Fatal("failed proxy escaped through direct fallback")
			}
			if failure == "bad-auth" && fixture.calls.Load() != 1 {
				t.Fatal("authentication did not cross actual proxy")
			}
		})
	}
}
