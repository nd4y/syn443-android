package netbird

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

type resolverFunc func(context.Context, string) ([]net.IP, error)

func (f resolverFunc) LookupIP(ctx context.Context, name string) ([]net.IP, error) {
	return f(ctx, name)
}

type capturePacketConn struct {
	address net.Addr
	writes  int
}

func (c *capturePacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.address = addr
	c.writes++
	return len(p), nil
}
func (*capturePacketConn) ReadFrom([]byte) (int, net.Addr, error) { return 0, nil, net.ErrClosed }
func (*capturePacketConn) Close() error                           { return nil }
func (*capturePacketConn) LocalAddr() net.Addr                    { return &net.UDPAddr{} }
func (*capturePacketConn) SetDeadline(time.Time) error            { return nil }
func (*capturePacketConn) SetReadDeadline(time.Time) error        { return nil }
func (*capturePacketConn) SetWriteDeadline(time.Time) error       { return nil }

type namedAddr string

func (a namedAddr) Network() string { return "udp" }
func (a namedAddr) String() string  { return string(a) }

func TestPacketResolvesOnlyInsideOverlay(t *testing.T) {
	raw := &capturePacketConn{}
	ctx, cancel := context.WithCancel(context.Background())
	c := &packetConn{PacketConn: raw, ctx: ctx, cancel: cancel, resolver: resolverFunc(func(_ context.Context, name string) ([]net.IP, error) {
		if name != "private.invalid" {
			t.Fatal(name)
		}
		return []net.IP{net.ParseIP("198.51.100.7")}, nil
	})}
	defer c.Close()
	if _, err := c.WriteTo([]byte("DNS"), namedAddr("private.invalid:53")); err != nil {
		t.Fatal(err)
	}
	if raw.address.String() != "198.51.100.7:53" {
		t.Fatal(raw.address)
	}
}

func TestPacketResolutionFailureDoesNotSend(t *testing.T) {
	raw := &capturePacketConn{}
	ctx, cancel := context.WithCancel(context.Background())
	want := errors.New("overlay DNS unavailable")
	c := &packetConn{PacketConn: raw, ctx: ctx, cancel: cancel, resolver: resolverFunc(func(context.Context, string) ([]net.IP, error) { return nil, want })}
	defer c.Close()
	if _, err := c.WriteTo([]byte("DNS"), namedAddr("private.invalid:53")); !errors.Is(err, want) {
		t.Fatal(err)
	}
	if raw.writes != 0 {
		t.Fatal("sent after lookup failure")
	}
}
