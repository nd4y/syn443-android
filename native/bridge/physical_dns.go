package bridge

import (
	"context"
	"errors"
	mdns "github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
)

// Android resolves on the currently selected physical Network, never the VPN
// default resolver or a DNS server saved from the previous Wi-Fi/LTE epoch.
func registerPhysicalDNS(registry *dns.TransportRegistry, resolver Protector) {
	dns.RegisterTransport[option.LocalDNSServerOptions](registry, "local",
		func(_ context.Context, _ log.ContextLogger, tag string, opts option.LocalDNSServerOptions) (adapter.DNSTransport, error) {
			if opts.Detour != "" || opts.BindInterface != "" || opts.PreferGo {
				return nil, errors.New("physical DNS does not support a detour, interface override or Go resolver")
			}
			return &physicalDNS{TransportAdapter: dns.NewTransportAdapterWithLocalOptions("local", tag, opts), resolver: resolver}, nil
		})
}

type physicalDNS struct {
	dns.TransportAdapter
	resolver Protector
}

func (d *physicalDNS) Start(adapter.StartStage) error { return nil }
func (d *physicalDNS) Close() error                   { return nil }
func (d *physicalDNS) Reset()                         {}
func (d *physicalDNS) Exchange(ctx context.Context, query *mdns.Msg) (*mdns.Msg, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(query.Question) != 1 {
		return nil, errors.New("one DNS question is required")
	}
	raw, err := query.Pack()
	if err != nil {
		return nil, err
	}
	if len(raw) > 4096 {
		return nil, errors.New("DNS query exceeded bound")
	}
	answer, err := d.resolver.ExchangeDNS(raw)
	if err != nil {
		return nil, errors.New("physical DNS query failed")
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	response := new(mdns.Msg)
	if len(answer) > 65535 {
		return nil, errors.New("DNS answer exceeded bound")
	}
	if err = response.Unpack(answer); err != nil {
		return nil, err
	}
	if !response.Response || response.Id != query.Id || len(response.Question) != 1 || response.Question[0] != query.Question[0] {
		return nil, errors.New("DNS answer does not match query")
	}
	return response, nil
}
