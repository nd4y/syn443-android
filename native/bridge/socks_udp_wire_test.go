package bridge

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/interrupt"
	M "github.com/sagernet/sing/common/metadata"
)

func udpEchoWire(t *testing.T) (*net.UDPConn, *atomic.Int32) {
	t.Helper()
	socket, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if e != nil {
		t.Fatal(e)
	}
	calls := &atomic.Int32{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buffer := make([]byte, 2048)
		for {
			n, source, e := socket.ReadFromUDP(buffer)
			if e != nil {
				return
			}
			calls.Add(1)
			_, _ = socket.WriteToUDP(buffer[:n], source)
		}
	}()
	t.Cleanup(func() {
		_ = socket.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("UDP echo did not retire")
		}
	})
	return socket, calls
}
func socksUDPWire(t *testing.T, destination *net.UDPAddr) (*wireFixture, *atomic.Int32) {
	t.Helper()
	forwarded := &atomic.Int32{}
	proxy := listenWire(t, func(c net.Conn) {
		var greeting [2]byte
		if _, e := io.ReadFull(c, greeting[:]); e != nil || greeting[0] != 5 || greeting[1] < 1 {
			return
		}
		methods := make([]byte, int(greeting[1]))
		if _, e := io.ReadFull(c, methods); e != nil || !bytes.Contains(methods, []byte{0}) {
			return
		}
		if _, e := c.Write([]byte{5, 0}); e != nil {
			return
		}
		var header [4]byte
		if _, e := io.ReadFull(c, header[:]); e != nil || header[0] != 5 || header[1] != 3 || header[2] != 0 {
			return
		}
		// The pinned sing client deliberately sends IPv6 unspecified for a
		// loopback UDP ASSOCIATE. This is a bind request, not the datagram's
		// destination; support both valid IP address families without allowing
		// another command, nonzero client port or a nonlocal bind address.
		size := 0
		switch header[3] {
		case 1:
			size = 4
		case 4:
			size = 16
		default:
			return
		}
		address := make([]byte, size+2)
		if _, e := io.ReadFull(c, address); e != nil {
			return
		}
		ip := net.IP(address[:size])
		if (!ip.IsUnspecified() && !ip.IsLoopback()) || binary.BigEndian.Uint16(address[size:]) != 0 {
			return
		}
		relay, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if e != nil {
			return
		}
		reply := []byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0}
		binary.BigEndian.PutUint16(reply[8:], uint16(relay.LocalAddr().(*net.UDPAddr).Port))
		if _, e = c.Write(reply); e != nil {
			relay.Close()
			return
		}
		done := make(chan struct{})
		go func() {
			defer close(done)
			buffer := make([]byte, 2048)
			for {
				n, source, e := relay.ReadFromUDP(buffer)
				if e != nil {
					return
				}
				if n < 10 || !bytes.Equal(buffer[:4], []byte{0, 0, 0, 1}) || !net.IP(buffer[4:8]).Equal(destination.IP) || int(binary.BigEndian.Uint16(buffer[8:10])) != destination.Port {
					continue
				}
				upstream, e := net.DialUDP("udp4", nil, destination)
				if e != nil {
					continue
				}
				_ = upstream.SetDeadline(time.Now().Add(time.Second))
				forwarded.Add(1)
				_, e = upstream.Write(buffer[10:n])
				if e != nil {
					upstream.Close()
					continue
				}
				answer := make([]byte, 2048)
				count, e := upstream.Read(answer)
				upstream.Close()
				if e != nil {
					continue
				}
				packet := append(append([]byte(nil), buffer[:10]...), answer[:count]...)
				_, _ = relay.WriteToUDP(packet, source)
			}
		}()
		_, _ = io.Copy(io.Discard, c)
		_ = relay.Close()
		<-done
	})
	return proxy, forwarded
}
func udpPayloadWire(proxy adapter.Outbound, destination *net.UDPAddr) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	packets, e := proxy.ListenPacket(ctx, M.ParseSocksaddr(destination.String()))
	if e != nil {
		return e
	}
	defer packets.Close()
	_ = packets.SetDeadline(time.Now().Add(2 * time.Second))
	message := []byte("syn443-udp-wire")
	if _, e = packets.WriteTo(message, destination); e != nil {
		return e
	}
	buffer := make([]byte, 128)
	n, _, e := packets.ReadFrom(buffer)
	if e == nil && !bytes.Equal(buffer[:n], message) {
		return io.ErrUnexpectedEOF
	}
	return e
}
func TestRegisteredSOCKSUDPAssociationActualDatagramAndNoHTTPDetourEscape(t *testing.T) {
	for _, mode := range []string{"direct-relay", "http-entry", "refused"} {
		t.Run(mode, func(t *testing.T) {
			target, calls := udpEchoWire(t)
			destination := target.LocalAddr().(*net.UDPAddr)
			socks, forwarded := socksUDPWire(t, destination)
			exit := socks.node("socks", "exit")
			nodes := []map[string]any{exit}
			if mode == "http-entry" {
				entry := httpWire(t, socks.listener.Addr().String(), "", "")
				exit["detour"] = "entry"
				nodes = append(nodes, entry.node("http", "entry"))
			}
			if mode == "refused" {
				_ = socks.listener.Close()
			}
			client := wireBox(t, nodes...)
			proxy, _ := client.Outbound().Outbound("exit")
			e := udpPayloadWire(proxy, destination)
			if mode == "direct-relay" {
				if e != nil {
					t.Fatal(e)
				}
				if calls.Load() != 1 || forwarded.Load() != 1 {
					t.Fatal("SOCKS UDP did not traverse actual relay exactly once")
				}
			} else {
				if e == nil {
					t.Fatal("unsupported or refused UDP path succeeded")
				}
				if calls.Load() != 0 || forwarded.Load() != 0 {
					t.Fatal("unsupported UDP detour escaped to physical UDP")
				}
			}
		})
	}
}

func TestUDPSelectorKeepsOpenAssociationUntilCloseAndUsesCurrentExitOnReopen(t *testing.T) {
	target, received := udpEchoWire(t)
	destination := target.LocalAddr().(*net.UDPAddr)
	primary, first := socksUDPWire(t, destination)
	reserve, second := socksUDPWire(t, destination)
	box := wireBox(t, primary.node("socks", "primary"), reserve.node("socks", "reserve"),
		map[string]any{"type": "selector", "tag": "group", "default": "primary",
			"outbounds": []string{"primary", "reserve"}, "interrupt_exist_connections": false})
	group, ok := box.Outbound().Outbound("group")
	if !ok {
		t.Fatal("no configured selector")
	}
	selector := group.(interface{ SelectOutbound(string) bool })
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	open := func() net.PacketConn {
		t.Helper()
		conn, err := group.ListenPacket(interrupt.ContextWithIsExternalConnection(ctx), M.ParseSocksaddr(destination.String()))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		return conn
	}
	exchange := func(conn net.PacketConn, payload string, wantFirst, wantSecond int32) {
		t.Helper()
		if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Fatal(err)
		}
		if _, err := conn.WriteTo([]byte(payload), destination); err != nil {
			t.Fatal(err)
		}
		var answer [64]byte
		n, _, err := conn.ReadFrom(answer[:])
		if err != nil || string(answer[:n]) != payload {
			t.Fatalf("missing echo for %q: %v", payload, err)
		}
		if first.Load() != wantFirst || second.Load() != wantSecond || received.Load() != wantFirst+wantSecond {
			t.Fatalf("unexpected UDP relay counts: primary %d, reserve %d, target %d", first.Load(), second.Load(), received.Load())
		}
	}
	original := open()
	exchange(original, "original-before-change", 1, 0)
	if selector.SelectOutbound("unassigned") || !selector.SelectOutbound("reserve") {
		t.Fatal("selector membership or reselection failed")
	}
	exchange(original, "original-after-change", 2, 0)
	next := open()
	exchange(next, "new-after-change", 2, 1)
	if err := original.Close(); err != nil {
		t.Fatal(err)
	}
	exchange(open(), "reopened-after-close", 2, 2)
}
