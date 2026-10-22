package bridge

import (
	"context"
	"errors"
	mdns "github.com/miekg/dns"
	"testing"
)

type dnsProtector struct{ exchange func([]byte) ([]byte, error) }

func (d dnsProtector) Protect(int32) error                  { return nil }
func (d dnsProtector) ExchangeDNS(q []byte) ([]byte, error) { return d.exchange(q) }
func TestPhysicalDNSPreservesQuestionAndRejectsMismatchedReplies(t *testing.T) {
	q := new(mdns.Msg)
	q.SetQuestion("example.invalid.", mdns.TypeA)
	mismatch := false
	transport := physicalDNS{resolver: dnsProtector{func(raw []byte) ([]byte, error) {
		request := new(mdns.Msg)
		if err := request.Unpack(raw); err != nil {
			return nil, err
		}
		response := new(mdns.Msg)
		response.SetReply(request)
		if mismatch {
			response.Id++
		}
		return response.Pack()
	}}}
	response, err := transport.Exchange(context.Background(), q)
	if err != nil || response.Id != q.Id || response.Question[0] != q.Question[0] {
		t.Fatal("valid response lost")
	}
	mismatch = true
	if _, err = transport.Exchange(context.Background(), q); err == nil {
		t.Fatal("mismatched response accepted")
	}
}
func TestPhysicalDNSCancellationAndFailuresFailClosed(t *testing.T) {
	calls := 0
	transport := physicalDNS{resolver: dnsProtector{func([]byte) ([]byte, error) { calls++; return nil, errors.New("unavailable") }}}
	q := new(mdns.Msg)
	q.SetQuestion("example.invalid.", mdns.TypeAAAA)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := transport.Exchange(ctx, q); err == nil || calls != 0 {
		t.Fatal("cancelled query crossed platform")
	}
	if _, err := transport.Exchange(context.Background(), q); err == nil || calls != 1 {
		t.Fatal("platform failure ignored")
	}
	q.Question = nil
	if _, err := transport.Exchange(context.Background(), q); err == nil || calls != 1 {
		t.Fatal("empty query crossed platform")
	}
}
func TestPhysicalDNSRejectsMalformedAndOversizedPlatformAnswers(t *testing.T) {
	for _, answer := range [][]byte{{1, 2, 3}, make([]byte, 65536)} {
		transport := physicalDNS{resolver: dnsProtector{func([]byte) ([]byte, error) { return answer, nil }}}
		q := new(mdns.Msg)
		q.SetQuestion("example.invalid.", mdns.TypeA)
		if _, err := transport.Exchange(context.Background(), q); err == nil {
			t.Fatal("invalid answer accepted")
		}
	}
}
