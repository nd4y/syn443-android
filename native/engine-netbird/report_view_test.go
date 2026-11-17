package netbird

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/netbirdio/netbird/client/embed"
)

type reportTestPeer struct {
	peerClient
	snapshot                                   embed.ConnectionSnapshot
	snapshotFn                                 func() embed.ConnectionSnapshot
	probeFn                                    func(context.Context, string) (time.Duration, error)
	snapshotCalls, probeCalls, active, maximum atomic.Int32
	mu                                         sync.Mutex
	targets                                    []string
}

func (p *reportTestPeer) ConnectionSnapshot() embed.ConnectionSnapshot {
	p.snapshotCalls.Add(1)
	if p.snapshotFn != nil {
		return p.snapshotFn()
	}
	return p.snapshot
}
func (p *reportTestPeer) ProbePeer(ctx context.Context, ip string) (time.Duration, error) {
	p.probeCalls.Add(1)
	n := p.active.Add(1)
	defer p.active.Add(-1)
	for old := p.maximum.Load(); n > old; old = p.maximum.Load() {
		if p.maximum.CompareAndSwap(old, n) {
			break
		}
	}
	p.mu.Lock()
	if len(p.targets) < 2048 {
		p.targets = append(p.targets, ip)
	}
	p.mu.Unlock()
	if p.probeFn != nil {
		return p.probeFn(ctx, ip)
	}
	return time.Millisecond, nil
}
func (*reportTestPeer) NotifyNetworkChange() {}
func reportRoster(n int) embed.ConnectionSnapshot {
	s := embed.ConnectionSnapshot{ManagementConnected: true, SignalConnected: true, IP: "192.0.2.1", FQDN: "local.example.invalid", Peers: make([]embed.PeerSnapshot, n)}
	for i := range s.Peers {
		s.Peers[i] = embed.PeerSnapshot{IP: fmt.Sprintf("2001:db8::%x", i+1), FQDN: fmt.Sprintf("peer-%d.example.invalid", i), State: "connected"}
	}
	return s
}
func reportOwner(t *testing.T, p *reportTestPeer) *Outbound {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	o := &Outbound{ctx: ctx, client: p, ready: true, options: OutboundOptions{ConnectionMode: "direct"}}
	runtimePeer.Lock()
	previous := runtimePeer.outbound
	runtimePeer.outbound = o
	runtimePeer.Unlock()
	t.Cleanup(func() {
		cancel()
		reportWait(t, func() bool { o.diagMu.Lock(); defer o.diagMu.Unlock(); return !o.diagBusy })
		runtimePeer.Lock()
		runtimePeer.outbound = previous
		runtimePeer.Unlock()
	})
	return o
}
func reportWait(t *testing.T, ready func() bool) {
	t.Helper()
	until := time.Now().Add(5 * time.Second)
	for !ready() {
		if time.Now().After(until) {
			t.Fatal("owned report fixture did not finish")
		}
		time.Sleep(time.Millisecond)
	}
}
func reportRead(t *testing.T, o *Outbound) diagnosticReport {
	t.Helper()
	var result diagnosticReport
	if !decodeReport(o.diagnosticsSnapshot(), &result) || !validDiagnosticReport(result) {
		t.Fatal("invalid bounded diagnostic projection")
	}
	return result
}
func reportViewRequest(section string, page int, request string) string {
	return fmt.Sprintf(`{"kind":"overlay-view","section":%q,"page":%d,"request":%q}`, section, page, request)
}

func TestReportViewStrictRequestsCannotMutateOwnerOrCallSDK(t *testing.T) {
	p := &reportTestPeer{snapshot: reportRoster(17)}
	o := reportOwner(t, p)
	oldAllowed := DiagnosticsAllowed
	DiagnosticsAllowed = func() bool { return false }
	defer func() { DiagnosticsAllowed = oldAllowed }()
	if !RequestView(reportViewRequest("peers", 1, "read-only")) {
		t.Fatal("read-only view incorrectly requires diagnostic admission")
	}
	before := o.reportViews()
	invalid := []string{
		`null`, `{}`, `{"kind":"overlay-view","section":"peers","page":0,"request":"a","page":1}`,
		`{"kind":"overlay-view","section":"peers","page":0,"request":"a","\u0070age":1}`,
		`{"kind":"overlay-view","section":"peers","Page":0,"request":"a"}`,
		`{"kind":"overlay-view","section":"peers","page":0,"request":"a","extra":0}`,
		`{"kind":"overlay-view","section":"peers","page":null,"request":"a"}`,
		`{"kind":"overlay-view","section":"peers","page":"0","request":"a"}`,
		`{"kind":"overlay-view","section":"peers","page":1.0,"request":"a"}`,
		`{"kind":"overlay-view","section":"peers","page":1e0,"request":"a"}`,
		`{"kind":"overlay-view","section":"peers","page":64,"request":"a"}`,
		`{"kind":"overlay-view","section":"peers","page":-1,"request":"a"}`,
		`{"kind":"overlay-view","section":"other","page":0,"request":"a"}`,
		`{"kind":"overlay-view","section":"peers","page":0,"request":""}`,
		reportViewRequest("peers", 0, strings.Repeat("x", 65)), reportViewRequest("peers", 0, "non-ascii-ю"),
		reportViewRequest("peers", 0, "space value"), reportViewRequest("peers", 0, "a") + ` {}`,
		reportViewRequest("peers", 0, "dot.value"), reportViewRequest("peers", 0, "slash/value"),
		reportViewRequest("peers", 0, "colon:value"), reportViewRequest("peers", 0, "at@value"), reportViewRequest("peers", 0, "tilde~value"),
		strings.Repeat(" ", 1025), string([]byte{0xff}),
	}
	for i, raw := range invalid {
		if RequestView(raw) || o.reportViews() != before {
			t.Fatalf("invalid request changed owner: case%d", i)
		}
	}
	if p.snapshotCalls.Load() != 0 || p.probeCalls.Load() != 0 || diagnosticAdmission.Load() {
		t.Fatal("page request performed diagnostic work")
	}
	o.mu.Lock()
	o.closed = true
	o.mu.Unlock()
	if RequestView(reportViewRequest("diagnostics", 0, "closed")) || o.reportViews() != before {
		t.Fatal("closed owner accepted a page")
	}
}

func TestReportViewPeersPageRealRosterWithoutWholeSliceRetention(t *testing.T) {
	for _, n := range []int{0, 1, 16, 17, 1024, 1025, 4096} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			p := &reportTestPeer{snapshot: reportRoster(n)}
			reportOwner(t, p)
			if !RequestView(reportViewRequest("peers", 63, "page")) {
				t.Fatal("view admission")
			}
			var r connectionReport
			if !decodeReport(RuntimeStatus(), &r) || !validConnectionReport(r) {
				t.Fatal("bounded peer projection invalid")
			}
			if r.View.Total != n || r.View.Retained != min(n, 1024) || r.View.Omitted != max(0, n-1024) || len(r.Peers) > 16 || r.View.Request != "page" {
				t.Fatal("roster metadata mismatch")
			}
			wantPage := max(0, r.View.Pages-1)
			if r.View.Page != wantPage {
				t.Fatal("page was not clamped")
			}
			if n > 0 {
				original := r.Peers[0].FQDN
				p.snapshot.Peers[r.View.Page*16].FQDN = "changed.example.invalid"
				if r.Peers[0].FQDN != original {
					t.Fatal("owned projection aliases SDK data")
				}
			}
			if p.probeCalls.Load() != 0 {
				t.Fatal("status page probed peers")
			}
		})
	}
}

func TestReportViewDiagnosticTargetsAndCoverageRemainBounded(t *testing.T) {
	p := &reportTestPeer{snapshot: reportRoster(1025)}
	entered := make(chan struct{}, 4)
	release := make(chan struct{})
	var once sync.Once
	// Notify only the first four active calls; later calls must not block on the fixture channel.
	var announced atomic.Int32
	p.probeFn = func(context.Context, string) (time.Duration, error) {
		if announced.Add(1) <= 4 {
			entered <- struct{}{}
		}
		<-release
		return time.Millisecond, nil
	}
	o := reportOwner(t, p)
	defer once.Do(func() { close(release) })
	StartDiagnostics()
	for i := 0; i < 4; i++ {
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			t.Fatal("four bounded workers did not start")
		}
	}
	for i := range p.snapshot.Peers {
		p.snapshot.Peers[i].IP = "invalid-after-capture"
		p.snapshot.Peers[i].FQDN = strings.Repeat("z", 4096)
	}
	once.Do(func() { close(release) })
	reportWait(t, func() bool { o.diagMu.Lock(); defer o.diagMu.Unlock(); return !o.diagBusy })
	r := reportRead(t, o)
	if r.State != "partial" || r.Coverage != (reportCoverage{1025, 1024, 1024, 1, 1}) || len(o.job.Results) != 1024 || len(r.Results) != 16 {
		t.Fatal("bounded job coverage was lost")
	}
	if p.probeCalls.Load() != 1024 || p.maximum.Load() > 4 {
		t.Fatal("active target/worker bound exceeded")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, target := range p.targets {
		if _, ok := reportIP(target); !ok {
			t.Fatal("worker borrowed a mutated SDK target")
		}
	}
}

func TestReportViewPartialCancelledAndInvalidTargetsNeverClaimComplete(t *testing.T) {
	for _, invalid := range []bool{false, true} {
		t.Run(fmt.Sprint(invalid), func(t *testing.T) {
			p := &reportTestPeer{snapshot: reportRoster(2), probeFn: func(context.Context, string) (time.Duration, error) { return 0, errors.New("synthetic no reply") }}
			if invalid {
				p.snapshot.Peers[1].IP = "not-an-ip"
			}
			o := reportOwner(t, p)
			StartDiagnostics()
			reportWait(t, func() bool { o.diagMu.Lock(); defer o.diagMu.Unlock(); return !o.diagBusy })
			r := reportRead(t, o)
			checked := 2
			if invalid {
				checked = 1
			}
			if r.Coverage.Checked != checked || r.Coverage.Planned != checked || r.Coverage.Unprobed != 2-checked {
				t.Fatal("attempted versus unchecked coverage mismatch")
			}
			if invalid {
				if r.State != "partial" || r.Results[1].State != "invalid_target" || r.Results[1].IPValid {
					t.Fatal("invalid target became a completed probe")
				}
			} else if r.State != "completed" || r.Results[0].State != "no_reply" {
				t.Fatal("a real no-reply attempt was not counted")
			}
		})
	}
}

func TestReportViewUTF8IdentifiersAndNumericBoundsAreOwned(t *testing.T) {
	p := &reportTestPeer{snapshot: reportRoster(16)}
	o := reportOwner(t, p)
	p.snapshot.FQDN = strings.Repeat("😀", 10000)
	for i := range p.snapshot.Peers {
		p.snapshot.Peers[i].FQDN = strings.Repeat("<", 96) + "unretained-tail"
		p.snapshot.Peers[i].BytesTx = -1
		p.snapshot.Peers[i].BytesRx = int64(^uint64(0) >> 1)
		p.snapshot.Peers[i].LastHandshake = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
	}
	p.snapshot.Peers[0].IP = "::FFFF:192.0.2.1"
	p.snapshot.Peers[1].IP = "fe80::1%zone"
	r := projectConnection(o, p.snapshot, reportSelection{})
	if len(r.FQDN) != 96 || !r.FQDNTruncated || !utf8.ValidString(r.FQDN) || r.Peers[0].IP != "::FFFF:192.0.2.1" || !r.Peers[0].IPValid || r.Peers[1].IP != "" || r.Peers[1].IPValid {
		t.Fatal("identifier ownership/validation mismatch")
	}
	for _, peer := range r.Peers {
		if len(peer.FQDN) > 96 || !peer.FQDNTruncated || peer.BytesTx != 0 || peer.BytesRx != reportMaximumInteger || !peer.LastHandshake.IsZero() {
			t.Fatal("scalar bound mismatch")
		}
	}
	if raw := marshal(r); len(raw) > reportSectionBytes || !json.Valid([]byte(raw)) {
		t.Fatal("worst bounded page exceeded its section")
	}
	text, truncated := reportFQDN(string([]byte{'a', 0xff, 0, 'b'}))
	if !truncated || !utf8.ValidString(text) || strings.ContainsRune(text, 0) {
		t.Fatal("invalid UTF8/control escaped the DTO")
	}
	for _, total := range []int{-1, reportMaximumTotal + 1} {
		if _, ok := makeReportView(total, reportSelection{}); ok {
			t.Fatal("invalid total accepted")
		}
	}
	o.options.ConnectionMode = "vless"
	o.options.Detour = strings.Repeat("unretained", 10000)
	bounded := projectConnection(o, p.snapshot, reportSelection{})
	if !bounded.MetadataUnknown || bounded.ProxyGroup != "" || bounded.SelectedProxy != "" || len(marshal(bounded)) > reportSectionBytes {
		t.Fatal("oversized display tag escaped its owned bound")
	}
}

func TestReportViewConcurrentSectionsClampAndEchoIndependentRequests(t *testing.T) {
	p := &reportTestPeer{snapshot: reportRoster(17)}
	o := reportOwner(t, p)
	o.job = DiagnosticJob{State: "completed", total: 17, planned: 17, Results: make([]ProbeResult, 17)}
	for i := range o.job.Results {
		o.job.Results[i] = ProbeResult{IP: fmt.Sprintf("2001:db8::%x", i+1), IPValid: true, State: "reply"}
	}
	started := time.Now()
	o.job.Started = started
	o.job.Finished = started
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			section := "peers"
			if i%2 != 0 {
				section = "diagnostics"
			}
			RequestView(reportViewRequest(section, i%64, fmt.Sprintf("request-%d", i)))
			_ = o.diagnosticsSnapshot()
		}(i)
	}
	wg.Wait()
	if !RequestView(reportViewRequest("peers", 63, "peer-last")) || !RequestView(reportViewRequest("diagnostics", 0, "diag-last")) {
		t.Fatal("final independent requests rejected")
	}
	var peers connectionReport
	if !decodeReport(RuntimeStatus(), &peers) {
		t.Fatal("peer page invalid")
	}
	diag := reportRead(t, o)
	if peers.View.Page != 1 || peers.View.Shown != 1 || peers.View.Request != "peer-last" || diag.View.Page != 0 || diag.View.Request != "diag-last" || !diag.Started.Equal(started) || !diag.Finished.Equal(started) {
		t.Fatal("page request mixed sections or refreshed probe time")
	}
	if p.probeCalls.Load() != 0 {
		t.Fatal("view change probed peers")
	}
}

func TestReportViewDeferredFallbackPreservesCriticalConnectionHeader(t *testing.T) {
	p := &reportTestPeer{snapshot: reportRoster(17)}
	o := reportOwner(t, p)
	projected := projectConnection(o, p.snapshot, reportSelection{})
	header := projected.connectionHeader
	d := &Deferred{ctx: context.Background(), current: o, options: OutboundOptions{ConnectionMode: "direct"}}
	d.header.Store(header)
	d.state.Store(moduleState{Active: true, Phase: "Started", Mode: "direct"})
	d.startupCodes.Store([]string{"client_started"})
	peerJSON := marshal(projected)
	o.job = DiagnosticJob{State: "completed", total: 17, planned: 17, Results: make([]ProbeResult, 17)}
	for i := range o.job.Results {
		o.job.Results[i] = ProbeResult{IP: fmt.Sprintf("2001:db8::%x", i+1), IPValid: true, State: "reply"}
	}
	diagnosticJSON := o.diagnosticsSnapshot()
	deferredPeer.Lock()
	previous := deferredPeer.current
	deferredPeer.current = d
	deferredPeer.Unlock()
	defer func() { deferredPeer.Lock(); deferredPeer.current = previous; deferredPeer.Unlock() }()
	drop := func(raw, key, nested string) string {
		var fields map[string]json.RawMessage
		if json.Unmarshal([]byte(raw), &fields) != nil {
			t.Fatal("fixture JSON")
		}
		if nested == "" {
			delete(fields, key)
		} else {
			var sub map[string]json.RawMessage
			if json.Unmarshal(fields[nested], &sub) != nil {
				t.Fatal("fixture nested JSON")
			}
			delete(sub, key)
			fields[nested], _ = json.Marshal(sub)
		}
		data, _ := json.Marshal(fields)
		return string(data)
	}
	cases := []struct {
		name string
		peer bool
		raw  string
	}{
		{"oversize-diagnostics", false, strings.Repeat("x", reportSectionBytes+1)},
		{"oversize-peers", true, strings.Repeat("x", reportSectionBytes+1)},
		{"missing-management", true, drop(peerJSON, "management_connected", "")},
		{"missing-signal", true, drop(peerJSON, "signal_connected", "")},
		{"missing-sampled", true, drop(peerJSON, "sampled_at", "")},
		{"missing-connection-known", true, drop(peerJSON, "connection_unknown", "")},
		{"missing-view-request", true, drop(peerJSON, "request", "view")},
		{"missing-stale", false, drop(diagnosticJSON, "stale", "")},
		{"missing-coverage-planned", false, drop(diagnosticJSON, "planned", "coverage")},
		{"missing-metadata-known", false, drop(diagnosticJSON, "metadata_unknown", "")},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			d.report.Store(peerJSON)
			d.diagnostics.Store(diagnosticJSON)
			if test.peer {
				d.report.Store(test.raw)
			} else {
				d.diagnostics.Store(test.raw)
			}
			var raw struct {
				moduleState
				PeerState   connectionReport `json:"peer_state"`
				Diagnostics diagnosticReport `json:"diagnostics"`
			}
			text := DeferredStatus()
			if len(text) > ReportMaximumBytes || json.Unmarshal([]byte(text), &raw) != nil {
				t.Fatal("deferred bounded frame invalid")
			}
			if !raw.Active || raw.Phase != "Started" || raw.Mode != "direct" || !raw.PeerState.ManagementConnected || !raw.PeerState.SignalConnected || raw.PeerState.Mode != "direct" || !raw.PeerState.Sampled.Equal(header.Sampled) {
				t.Fatal("component failure erased connection header")
			}
			if test.peer && !raw.PeerState.MetadataUnknown || !test.peer && !raw.Diagnostics.MetadataUnknown {
				t.Fatal("corrupt component gained known counters")
			}
		})
	}
	newOwner := &Outbound{ctx: context.Background(), options: OutboundOptions{ConnectionMode: "direct"}}
	d.mu.Lock()
	d.resetReportViewsLocked()
	d.current = newOwner
	d.mu.Unlock()
	if d.publishConnectionReport(o, peerJSON) {
		t.Fatal("old owner published after replacement")
	}
	var after struct {
		PeerState   connectionReport `json:"peer_state"`
		Diagnostics diagnosticReport `json:"diagnostics"`
	}
	if json.Unmarshal([]byte(DeferredStatus()), &after) != nil || after.PeerState.View.Request != "" || after.Diagnostics.View.Request != "" || !after.PeerState.ConnectionUnknown || !after.PeerState.MetadataUnknown || !after.Diagnostics.MetadataUnknown || !after.Diagnostics.Stale || !after.PeerState.Sampled.Equal(header.Sampled) {
		t.Fatal("replacement imported old request or refreshed sample age")
	}
}

func TestReportViewBlockedSnapshotAndCancelledWorkerRetainAdmission(t *testing.T) {
	t.Run("epoch-after-watcher-stop", func(t *testing.T) {
		p := &reportTestPeer{snapshot: reportRoster(1)}
		o := reportOwner(t, p)
		foreignPeer := &reportTestPeer{snapshot: reportRoster(1)}
		foreign := &Outbound{ctx: context.Background(), client: foreignPeer, ready: true, options: OutboundOptions{ConnectionMode: "direct"}}
		var captured, foreignStarted time.Time
		raw := startDiagnostics(func(stopped bool) {
			if !stopped {
				t.Fatal("fixture did not retire watcher before epoch change")
			}
			o.diagMu.Lock()
			captured = o.job.Started
			busy := o.diagBusy
			o.diagMu.Unlock()
			if !busy {
				t.Fatal("snapshot worker released admission before its transition")
			}
			o.InterfaceUpdated()
			foreignStarted = captured.Add(time.Second)
			foreign.job = DiagnosticJob{State: "preparing", Started: foreignStarted, Results: []ProbeResult{}, unknown: true}
			runtimePeer.Lock()
			runtimePeer.outbound = foreign
			runtimePeer.Unlock()
		})
		var returned diagnosticReport
		if !decodeReport(raw, &returned) || returned.State != "stale" {
			t.Fatal("old epoch did not return unknown stale result")
		}
		old := reportRead(t, o)
		if old.State != "cancelled" || !old.Stale || !old.MetadataUnknown || !old.Started.Equal(captured) || old.Finished.IsZero() || p.probeCalls.Load() != 0 {
			t.Fatal("captured preparing job did not terminate without late probes")
		}
		if foreign.job.State != "preparing" || !foreign.job.Started.Equal(foreignStarted) || !foreign.job.Finished.IsZero() || foreign.job.Stale || foreignPeer.snapshotCalls.Load() != 0 || foreignPeer.probeCalls.Load() != 0 {
			t.Fatal("old completion changed a replacement owner")
		}
		o.diagMu.Lock()
		busy := o.diagBusy
		o.diagMu.Unlock()
		if busy {
			t.Fatal("finished snapshot retained its worker slot")
		}
		runtimePeer.Lock()
		runtimePeer.outbound = o
		runtimePeer.Unlock()
		StartDiagnostics()
		reportWait(t, func() bool { o.diagMu.Lock(); defer o.diagMu.Unlock(); return !o.diagBusy })
		fresh := reportRead(t, o)
		if fresh.State != "completed" || fresh.Stale || fresh.Coverage.Checked != 1 || p.snapshotCalls.Load() != 2 || p.probeCalls.Load() != 1 {
			t.Fatal("epoch transition permanently blocked the next real job")
		}
	})
	t.Run("mismatched-preparing-record", func(t *testing.T) {
		p := &reportTestPeer{snapshot: reportRoster(1)}
		o := reportOwner(t, p)
		var replacementStarted time.Time
		startDiagnostics(func(stopped bool) {
			if !stopped {
				t.Fatal("fixture watcher was not stopped")
			}
			o.InterfaceUpdated()
			o.diagMu.Lock()
			replacementStarted = o.job.Started.Add(time.Second)
			o.job = DiagnosticJob{State: "preparing", Started: replacementStarted, Results: []ProbeResult{}, unknown: true}
			o.diagMu.Unlock()
		})
		o.diagMu.Lock()
		state, started, finished, stale, busy := o.job.State, o.job.Started, o.job.Finished, o.job.Stale, o.diagBusy
		o.diagMu.Unlock()
		if state != "preparing" || !started.Equal(replacementStarted) || !finished.IsZero() || stale || busy || p.probeCalls.Load() != 0 {
			t.Fatal("stale completion terminalized another preparing record")
		}
	})
	t.Run("snapshot", func(t *testing.T) {
		entered := make(chan struct{})
		release := make(chan struct{})
		var once sync.Once
		p := &reportTestPeer{snapshotFn: func() embed.ConnectionSnapshot { close(entered); <-release; return reportRoster(1) }}
		o := reportOwner(t, p)
		o.diagnosticSnapshotTimeout = 5 * time.Millisecond
		defer once.Do(func() { close(release) })
		if !RequestDiagnostics() {
			t.Fatal("snapshot admission denied")
		}
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			t.Fatal("snapshot worker did not start")
		}
		reportWait(t, func() bool { return reportRead(t, o).State == "unavailable" })
		if RequestDiagnostics() || !diagnosticAdmission.Load() || p.snapshotCalls.Load() != 1 {
			t.Fatal("snapshot timeout released actual worker")
		}
		once.Do(func() { close(release) })
		reportWait(t, func() bool { return !diagnosticAdmission.Load() })
	})
	t.Run("worker", func(t *testing.T) {
		entered := make(chan struct{}, 4)
		release := make(chan struct{})
		var once sync.Once
		p := &reportTestPeer{snapshot: reportRoster(4), probeFn: func(ctx context.Context, _ string) (time.Duration, error) {
			entered <- struct{}{}
			<-ctx.Done()
			<-release
			return 0, ctx.Err()
		}}
		o := reportOwner(t, p)
		defer once.Do(func() { close(release) })
		StartDiagnostics()
		for i := 0; i < 4; i++ {
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("owned probe did not start")
			}
		}
		CancelDiagnostics()
		StartDiagnostics()
		o.diagMu.Lock()
		busy := o.diagBusy
		o.diagMu.Unlock()
		if !busy || p.snapshotCalls.Load() != 1 || p.probeCalls.Load() != 4 {
			t.Fatal("cancel replaced an actual probe worker")
		}
		once.Do(func() { close(release) })
		reportWait(t, func() bool { o.diagMu.Lock(); defer o.diagMu.Unlock(); return !o.diagBusy })
		r := reportRead(t, o)
		if r.State != "cancelled" || r.Coverage.Checked != 0 || r.Coverage.Unprobed != 4 {
			t.Fatal("cancelled attempts became checked")
		}
	})
}
