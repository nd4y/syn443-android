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
		if _, e := io.ReadFull(c, header[:]); e != nil || header != [4]byte{5, 3, 0, 1} {
			return
		}
		var address [6]byte
		if _, e := io.ReadFull(c, address[:]); e != nil {
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
