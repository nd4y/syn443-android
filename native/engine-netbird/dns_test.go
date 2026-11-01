package netbird

import (
	"context"
	"errors"
	"testing"

	"github.com/miekg/dns"
)

type dnsExchangeFunc func(context.Context, []byte) ([]byte, error)

func (f dnsExchangeFunc) ExchangeDNS(ctx context.Context, b []byte) ([]byte, error) { return f(ctx, b) }

func TestDNSPreservesRecordsAndTTL(t *testing.T) {
	query := new(dns.Msg).SetQuestion("private.invalid.", dns.TypeTXT)
	client := dnsExchangeFunc(func(_ context.Context, packet []byte) ([]byte, error) {
		var request dns.Msg
		if err := request.Unpack(packet); err != nil {
			t.Fatal(err)
		}
		response := new(dns.Msg).SetReply(&request)
		rr, err := dns.NewRR("private.invalid. 123 IN TXT \"from overlay\"")
		if err != nil {
			t.Fatal(err)
		}
		response.Answer = []dns.RR{rr}
		return response.Pack()
	})
	response, err := exchangeDNS(context.Background(), client, query)
	if err != nil {
		t.Fatal(err)
	}
	if len(response.Answer) != 1 || response.Answer[0].Header().Ttl != 123 || response.Answer[0].(*dns.TXT).Txt[0] != "from overlay" {
		t.Fatalf("unexpected response %v", response)
	}
}

func TestDNSFailureIsReturnedWithoutFallback(t *testing.T) {
	want := errors.New("overlay disconnected")
	query := new(dns.Msg).SetQuestion("private.invalid.", dns.TypeA)
	_, err := exchangeDNS(context.Background(), dnsExchangeFunc(func(context.Context, []byte) ([]byte, error) { return nil, want }), query)
	if !errors.Is(err, want) {
		t.Fatal(err)
	}
}

func TestDNSRejectsMismatchedResponse(t *testing.T) {
	query := new(dns.Msg).SetQuestion("private.invalid.", dns.TypeA)
	_, err := exchangeDNS(context.Background(), dnsExchangeFunc(func(context.Context, []byte) ([]byte, error) {
		r := new(dns.Msg).SetReply(query)
		r.Id++
		return r.Pack()
	}), query)
	if err == nil {
		t.Fatal("accepted another query's answer")
	}
}
