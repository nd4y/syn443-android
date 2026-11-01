package netbird

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"
)

type overlayResolver interface {
	LookupIP(context.Context, string) ([]net.IP, error)
}

// Overlay names must be resolved by NetBird, never by the host's DNS resolver.
type packetConn struct {
	net.PacketConn
	ctx      context.Context
	cancel   context.CancelFunc
	resolver overlayResolver
}

func (c *packetConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	host, portString, err := net.SplitHostPort(addr.String())
	if err != nil {
		return 0, err
	}
	port, err := strconv.ParseUint(portString, 10, 16)
	if err != nil {
		return 0, err
	}
	ip := net.ParseIP(host)
	if ip == nil {
		ctx, cancel := context.WithTimeout(c.ctx, 10*time.Second)
		defer cancel()
		ips, err := c.resolver.LookupIP(ctx, host)
		if err != nil {
			return 0, err
		}
		if len(ips) == 0 {
			return 0, fmt.Errorf("netbird: no overlay address for %s", host)
		}
		ip = ips[0]
	}
	return c.PacketConn.WriteTo(p, &net.UDPAddr{IP: ip, Port: int(port)})
}

func (c *packetConn) Close() error {
	c.cancel()
	return c.PacketConn.Close()
}
