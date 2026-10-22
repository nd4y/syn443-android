package netbird

import (
	"context"
	"encoding/json"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/netbirdio/netbird/client/embed"
	"github.com/sagernet/sing-box/adapter/outbound"
)

type diagnosticPeer struct {
	peerClient
	concurrent, maximum atomic.Int32
}

func (p *diagnosticPeer) ConnectionSnapshot() embed.ConnectionSnapshot {
	s := embed.ConnectionSnapshot{ManagementConnected: true, Peers: []embed.PeerSnapshot{}}
	for i := 0; i < 12; i++ {
		s.Peers = append(s.Peers, embed.PeerSnapshot{IP: fmt.Sprintf("198.51.100.%d", i+1), FQDN: fmt.Sprintf("peer%d.example", i)})
	}
	return s
}
func (p *diagnosticPeer) ProbePeer(ctx context.Context, _ string) (time.Duration, error) {
	current := p.concurrent.Add(1)
	defer p.concurrent.Add(-1)
	for old := p.maximum.Load(); current > old; old = p.maximum.Load() {
		if p.maximum.CompareAndSwap(old, current) {
			break
		}
	}
	<-ctx.Done()
	return 0, ctx.Err()
}
func (*diagnosticPeer) NotifyNetworkChange() {}

func TestNetworkChangeInvalidatesDiagnosticEvidence(t *testing.T) {
	o := &Outbound{job: DiagnosticJob{State: "completed", Results: []ProbeResult{{IP: "192.0.2.4", State: "reply"}}}}
	o.InterfaceUpdated()
	if !o.job.Stale || o.job.Results[0].State != "reply" {
		t.Fatal("network change must mark retained evidence stale", o.job)
	}
}

type blockedSnapshotPeer struct {
	peerClient
	entered, release chan struct{}
}

func (p *blockedSnapshotPeer) ConnectionSnapshot() embed.ConnectionSnapshot {
	close(p.entered)
	<-p.release
	return embed.ConnectionSnapshot{}
}
func (p *blockedSnapshotPeer) ProbePeer(context.Context, string) (time.Duration, error) {
	return 0, context.Canceled
}
func (p *blockedSnapshotPeer) NotifyNetworkChange() {}
func TestBlockedSdkSnapshotCannotHoldNetworkChangeOrCommitOldEvidence(t *testing.T) {
	peer := &blockedSnapshotPeer{entered: make(chan struct{}), release: make(chan struct{})}
	o := &Outbound{ctx: context.Background(), client: peer, ready: true, options: OutboundOptions{ConnectionMode: "direct"}}
	runtimePeer.Lock()
	runtimePeer.outbound = o
	runtimePeer.Unlock()
	defer func() { runtimePeer.Lock(); runtimePeer.outbound = nil; runtimePeer.Unlock() }()
	done := make(chan string, 1)
	go func() { done <- StartDiagnostics() }()
	select {
	case <-peer.entered:
	case <-time.After(time.Second):
		t.Fatal("snapshot did not start")
	}
	changed := make(chan struct{})
	go func() { o.InterfaceUpdated(); close(changed) }()
	select {
	case <-changed:
	case <-time.After(time.Second):
		close(peer.release)
		t.Fatal("SDK snapshot blocked network change")
	}
	close(peer.release)
	select {
	case result := <-done:
		if result != `{"state":"stale","results":[]}` {
			t.Fatal("stale diagnostic snapshot was committed")
		}
	case <-time.After(time.Second):
		t.Fatal("snapshot did not finish")
	}
}
func TestDiagnosticsAreAsynchronousBoundedAndCancellable(t *testing.T) {
	peer := new(diagnosticPeer)
	o := &Outbound{Adapter: outbound.NewAdapter("netbird", "mesh", nil, nil), ctx: context.Background(), client: peer, ready: true, options: OutboundOptions{ConnectionMode: "direct"}}
	runtimePeer.Lock()
	runtimePeer.outbound = o
	runtimePeer.Unlock()
	defer func() { runtimePeer.Lock(); runtimePeer.outbound = nil; runtimePeer.Unlock() }()
	started := time.Now()
	if !json.Valid([]byte(StartDiagnostics())) {
		t.Fatal("invalid JSON")
	}
	if time.Since(started) > time.Second {
		t.Fatal("start blocked on peer probes")
	}
	var status map[string]any
	if err := json.Unmarshal([]byte(RuntimeStatus()), &status); err != nil {
		t.Fatal(err)
	}
	if status["mode"] != "direct" || status["selected_proxy"] != "" {
		t.Fatal(status)
	}
	deadline := time.Now().Add(time.Second)
	for peer.maximum.Load() < 4 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if peer.maximum.Load() != 4 {
		t.Fatal("worker limit", peer.maximum.Load())
	}
	CancelDiagnostics()
	for time.Now().Before(deadline) {
		o.diagMu.Lock()
		state := o.job.State
		o.diagMu.Unlock()
		if state == "cancelled" {
			break
		}
		time.Sleep(time.Millisecond)
	}
	o.diagMu.Lock()
	defer o.diagMu.Unlock()
	if o.job.State != "cancelled" || len(o.job.Results) != 12 {
		t.Fatal(o.job)
	}
	for _, result := range o.job.Results {
		if result.State != "cancelled" {
			t.Fatal(result)
		}
	}
}
