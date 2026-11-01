package bridge

import (
	"context"
	"errors"
	"net"

	mdns "github.com/miekg/dns"
	netbird "io.syn443/engine-netbird"
)

func installOverlayResolver(protector Protector) {
	netbird.PhysicalResolver = func(ctx context.Context, host string) ([]net.IPAddr, error) {
		if ip := net.ParseIP(host); ip != nil {
			return []net.IPAddr{{IP: ip}}, nil
		}
		var addresses []net.IPAddr
		// Sequential requests preserve Android's bounded DNS admission budget.
		for _, kind := range []uint16{mdns.TypeA, mdns.TypeAAAA} {
			query := new(mdns.Msg).SetQuestion(mdns.Fqdn(host), kind)
			reply, err := (&physicalDNS{resolver: protector}).Exchange(ctx, query)
			if err != nil {
				if ctx.Err() != nil {
					return nil, ctx.Err()
				}
				continue
			}
			if reply.Rcode != mdns.RcodeSuccess {
				continue
			}
			for _, answer := range reply.Answer {
				switch record := answer.(type) {
				case *mdns.A:
					addresses = append(addresses, net.IPAddr{IP: record.A})
				case *mdns.AAAA:
					addresses = append(addresses, net.IPAddr{IP: record.AAAA})
				}
			}
		}
		if len(addresses) == 0 {
			return nil, errors.New("physical DNS returned no address")
		}
		return addresses, nil
	}
}
