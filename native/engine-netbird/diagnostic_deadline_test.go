package netbird

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestDiagnosticDeadlineIncludesRosterAndFreezesHungPeerReport(t *testing.T) {
	probeDeadline := make(chan time.Time, 1)
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	p := &reportTestPeer{snapshot: reportRoster(1), probeFn: func(ctx context.Context, _ string) (time.Duration, error) {
		limit, _ := ctx.Deadline()
		probeDeadline <- limit
		<-release // Model an SDK that ignores cancellation and later returns success.
		return time.Millisecond, nil
	}}
	o := reportOwner(t, p)
	defer unblock()
	const limit = 500 * time.Millisecond
	startDiagnosticJob(nil, limit, 2*time.Second)
	select {
	case deadline := <-probeDeadline:
		o.diagMu.Lock()
		elapsed := deadline.Sub(o.job.Started)
		o.diagMu.Unlock()
		if elapsed != limit {
			t.Fatal("probe deadline did not include roster time", elapsed)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("probe did not start")
	}
	reportWait(t, func() bool { return reportRead(t, o).State == "partial" })
	ended := reportRead(t, o)
	if ended.JobID != "" || ended.Finished.IsZero() || ended.Coverage.Checked != 0 || ended.Coverage.Unprobed != 1 || ended.Results[0].State != "cancelled" {
		t.Fatal("incomplete evidence was presented as a live or successful probe")
	}
	StartDiagnostics()
	if p.snapshotCalls.Load() != 1 || p.probeCalls.Load() != 1 {
		t.Fatal("replacement admitted while original SDK call was outstanding")
	}
	unblock()
	reportWait(t, func() bool { o.diagMu.Lock(); defer o.diagMu.Unlock(); return !o.diagBusy })
	final := reportRead(t, o)
	if final.State != ended.State || !final.Finished.Equal(ended.Finished) || final.Results[0] != ended.Results[0] || final.Coverage != ended.Coverage {
		t.Fatal("late SDK success rewrote the terminal report")
	}
}

func TestDiagnosticPeerTimeoutCannotPublishLateSDKSuccess(t *testing.T) {
	p := &reportTestPeer{snapshot: reportRoster(1), probeFn: func(ctx context.Context, _ string) (time.Duration, error) {
		<-ctx.Done()
		return 9 * time.Millisecond, nil
	}}
	o := reportOwner(t, p)
	startDiagnosticJob(nil, 3*time.Second, 20*time.Millisecond)
	reportWait(t, func() bool { o.diagMu.Lock(); defer o.diagMu.Unlock(); return !o.diagBusy })
	report := reportRead(t, o)
	if report.State != "completed" || report.Coverage.Checked != 1 || report.Results[0].State != "no_reply" || report.Results[0].RTTMillis != 0 {
		t.Fatal("expired peer response changed reachability or latency", report)
	}
}
