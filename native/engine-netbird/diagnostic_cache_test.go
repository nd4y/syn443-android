package netbird

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

func diagnosticCacheState(t *testing.T, d *Deferred, expected string) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		var job DiagnosticJob
		if json.Unmarshal([]byte(d.diagnostics.Load().(string)), &job) == nil && job.State == expected {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("local diagnostic progress missing")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestLocalDiagnosticCacheProgressDoesNotWaitForBlockedSdkRoster(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client := &blockedSnapshotPeer{entered: make(chan struct{}), release: make(chan struct{})}
	peer := &Outbound{ctx: ctx, client: client, ready: true, options: OutboundOptions{ConnectionMode: "direct"}}
	peer.job = DiagnosticJob{State: "running", Started: time.Now(), Results: []ProbeResult{{State: "checking"}}}
	d := &Deferred{ctx: ctx}
	d.diagnostics.Store(`{}`)
	runtimePeer.Lock()
	previous := runtimePeer.outbound
	runtimePeer.outbound = peer
	runtimePeer.Unlock()
	defer func() { runtimePeer.Lock(); runtimePeer.outbound = previous; runtimePeer.Unlock() }()
	sdkDone := make(chan struct{})
	go func() { RuntimeStatus(); close(sdkDone) }()
	defer func() {
		close(client.release)
		select {
		case <-sdkDone:
		case <-time.After(time.Second):
			t.Error("owned synthetic SDK worker did not retire")
		}
	}()
	select {
	case <-client.entered:
	case <-time.After(time.Second):
		t.Fatal("synthetic recorder did not block")
	}
	done := make(chan struct{})
	go func() { d.sampleDiagnostics(peer, 5*time.Millisecond); close(done) }()
	diagnosticCacheState(t, d, "running")
	peer.diagMu.Lock()
	peer.job.State = "completed"
	peer.job.Results[0].State = "reply"
	peer.diagMu.Unlock()
	diagnosticCacheState(t, d, "completed")
	select {
	case <-sdkDone:
		t.Fatal("test did not preserve the recorder stall")
	default:
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("local sampler did not stop independently")
	}
}

func TestDiagnosticCacheCannotBorrowTheGlobalReplacementOutbound(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	own := &Outbound{job: DiagnosticJob{State: "cancelled"}}
	foreign := &Outbound{job: DiagnosticJob{State: "completed"}}
	d := &Deferred{ctx: ctx}
	d.diagnostics.Store(`{}`)
	runtimePeer.Lock()
	previous := runtimePeer.outbound
	runtimePeer.outbound = foreign
	runtimePeer.Unlock()
	defer func() { runtimePeer.Lock(); runtimePeer.outbound = previous; runtimePeer.Unlock() }()
	done := make(chan struct{})
	go func() { d.sampleDiagnostics(own, 5*time.Millisecond); close(done) }()
	diagnosticCacheState(t, d, "cancelled")
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("own sampler did not retire")
	}
}

type pendingLocalDiagnosticRead struct{ entered, release chan struct{} }

func (p *pendingLocalDiagnosticRead) diagnosticsSnapshot() string {
	close(p.entered)
	<-p.release
	return `{"state":"completed"}`
}

func TestDiagnosticCacheCannotPublishAfterStopWhileLocalReadIsPending(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	peer := &pendingLocalDiagnosticRead{entered: make(chan struct{}), release: make(chan struct{})}
	d := &Deferred{ctx: ctx}
	d.diagnostics.Store(`{}`)
	done := make(chan struct{})
	go func() { d.sampleDiagnostics(peer, 5*time.Millisecond); close(done) }()
	select {
	case <-peer.entered:
	case <-time.After(time.Second):
		close(peer.release)
		t.Fatal("local read did not enter")
	}
	cancel()
	close(peer.release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cancelled local sampler did not retire")
	}
	if d.diagnostics.Load().(string) != `{}` {
		t.Fatal("stopped owner published late diagnostic data")
	}
}

func TestBlockedDiagnosticRosterReportsTimeoutWithoutReplacementWorkersOrLateSuccess(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client := &blockedSnapshotPeer{entered: make(chan struct{}), release: make(chan struct{})}
	peer := &Outbound{ctx: ctx, client: client, ready: true, diagnosticSnapshotTimeout: 15 * time.Millisecond}
	runtimePeer.Lock()
	previous := runtimePeer.outbound
	runtimePeer.outbound = peer
	runtimePeer.Unlock()
	guard := DiagnosticsAllowed
	DiagnosticsAllowed = func() bool { return true }
	defer func() {
		DiagnosticsAllowed = guard
		runtimePeer.Lock()
		runtimePeer.outbound = previous
		runtimePeer.Unlock()
	}()
	defer func() {
		close(client.release)
		deadline := time.Now().Add(time.Second)
		for diagnosticAdmission.Load() && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		if diagnosticAdmission.Load() {
			t.Error("owned synthetic SDK reader did not finish")
		}
		var retained DiagnosticJob
		if json.Unmarshal([]byte(peer.diagnosticsSnapshot()), &retained) != nil || retained.State != "unavailable" {
			t.Error("late SDK return replaced timeout with success")
		}
	}()
	if !RequestDiagnostics() {
		t.Fatal("first diagnostic was not admitted")
	}
	select {
	case <-client.entered:
	case <-time.After(time.Second):
		t.Fatal("recorder did not enter")
	}
	d := &Deferred{ctx: ctx}
	d.diagnostics.Store(`{}`)
	done := make(chan struct{})
	go func() { d.sampleDiagnostics(peer, time.Millisecond); close(done) }()
	diagnosticCacheState(t, d, "unavailable")
	if RequestDiagnostics() || !diagnosticAdmission.Load() {
		t.Fatal("timeout admitted a second uninterruptible reader")
	}
	var before DiagnosticJob
	json.Unmarshal([]byte(peer.diagnosticsSnapshot()), &before)
	if before.Started.IsZero() || before.Finished.IsZero() || len(before.Results) != 0 {
		t.Fatal("timeout invented successful probe evidence")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("diagnostic cache waited for blocked SDK on Stop")
	}
}

func TestDiagnosticCancellationBeforeRosterReturnsCannotStartLateProbes(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client := &blockedSnapshotPeer{entered: make(chan struct{}), release: make(chan struct{})}
	peer := &Outbound{ctx: ctx, client: client, ready: true}
	runtimePeer.Lock()
	previous := runtimePeer.outbound
	runtimePeer.outbound = peer
	runtimePeer.Unlock()
	defer func() { runtimePeer.Lock(); runtimePeer.outbound = previous; runtimePeer.Unlock() }()
	done := make(chan string, 1)
	go func() { done <- StartDiagnostics() }()
	select {
	case <-client.entered:
	case <-time.After(time.Second):
		close(client.release)
		t.Fatal("recorder did not enter")
	}
	CancelDiagnostics()
	deadline := time.Now().Add(time.Second)
	for {
		var job DiagnosticJob
		json.Unmarshal([]byte(peer.diagnosticsSnapshot()), &job)
		if job.State == "cancelled" {
			break
		}
		if time.Now().After(deadline) {
			close(client.release)
			t.Fatal("cancellation waited for SDK roster")
		}
		time.Sleep(time.Millisecond)
	}
	close(client.release)
	select {
	case raw := <-done:
		var job DiagnosticJob
		if json.Unmarshal([]byte(raw), &job) != nil || job.State != "cancelled" || len(job.Results) != 0 {
			t.Fatal("late roster revived cancelled probe work")
		}
	case <-time.After(time.Second):
		t.Fatal("released reader did not finish")
	}
}
