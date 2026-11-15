package bridge

import (
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport"
	"github.com/sagernet/sing-box/dns/transport/quic"
)

func registerRemoteDNS(registry *dns.TransportRegistry) {
	transport.RegisterUDP(registry)
	transport.RegisterTCP(registry)
	transport.RegisterTLS(registry)
	transport.RegisterHTTPS(registry)
	quic.RegisterTransport(registry)
	quic.RegisterHTTP3Transport(registry)
}
