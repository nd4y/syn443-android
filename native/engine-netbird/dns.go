package netbird

import (
	"context"
	"errors"
	"fmt"
	"time"

	mDNS "github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/service"
)

type DNSOptions struct {
	Outbound string `json:"outbound"`
}

func RegisterDNSTransport(registry *dns.TransportRegistry) {
	dns.RegisterTransport[DNSOptions](registry, Type, newDNSTransport)
}

type dnsTransport struct {
	dns.TransportAdapter
	manager     adapter.OutboundManager
	outboundTag string
	peer        interface{ getClient() (peerClient, error) }
}

func newDNSTransport(ctx context.Context, _ log.ContextLogger, tag string, options DNSOptions) (adapter.DNSTransport, error) {
	if options.Outbound == "" {
		return nil, errors.New("netbird DNS requires an outbound reference")
	}
	manager := service.FromContext[adapter.OutboundManager](ctx)
	if manager == nil {
		return nil, errors.New("netbird DNS outbound manager is unavailable")
	}
	return &dnsTransport{
		TransportAdapter: dns.NewTransportAdapter(Type, tag, nil),
		manager:          manager,
		outboundTag:      options.Outbound,
	}, nil
}

func (t *dnsTransport) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	outbound, ok := t.manager.Outbound(t.outboundTag)
	if !ok {
		return errors.New("netbird DNS outbound not found")
	}
	t.peer, ok = outbound.(interface{ getClient() (peerClient, error) })
	if !ok {
		return errors.New("netbird DNS reference must point to a netbird outbound")
	}
	return nil
}

func (*dnsTransport) Close() error { return nil }
func (*dnsTransport) Reset()       {}

func (t *dnsTransport) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	if t.peer == nil {
		return nil, errors.New("netbird DNS is not initialized")
	}
	client, err := t.peer.getClient()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return exchangeDNS(ctx, client, message)
}

type dnsExchanger interface {
	ExchangeDNS(context.Context, []byte) ([]byte, error)
}

func exchangeDNS(ctx context.Context, client dnsExchanger, message *mDNS.Msg) (*mDNS.Msg, error) {
	if len(message.Question) != 1 || message.Response {
		return nil, errors.New("netbird DNS expects a single-question query")
	}
	wire, err := message.Pack()
	if err != nil {
		return nil, err
	}
	wire, err = client.ExchangeDNS(ctx, wire)
	if err != nil {
		return nil, err
	}
	var response mDNS.Msg
	if err := response.Unpack(wire); err != nil {
		return nil, fmt.Errorf("invalid netbird DNS response: %w", err)
	}
	if response.Id != message.Id || !response.Response || len(response.Question) != 1 || response.Question[0] != message.Question[0] {
		return nil, errors.New("netbird DNS response does not match query")
	}
	return &response, nil
}
