package netbird

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/netbirdio/netbird/client/embed"
)

// PhysicalResolver is installed by the Android bridge before a core is created.
// It must resolve on the physical Network, never on the VPN's DNS listener.
var PhysicalResolver func(context.Context, string) ([]net.IPAddr, error)

// Installed once by the single owning runtime; reads only its atomic lease guard.
var DiagnosticsAllowed func() bool

var diagnosticAdmission atomic.Bool

// One optional worker; a blocked SDK snapshot never blocks host control or
// creates an unbounded queue of jobs from repeated UI taps.
func RequestDiagnostics() bool {
	if DiagnosticsAllowed != nil && !DiagnosticsAllowed() {
		return false
	}
	if !diagnosticAdmission.CompareAndSwap(false, true) {
		return false
	}
	go func() { defer diagnosticAdmission.Store(false); StartDiagnostics() }()
	return true
}

var runtimePeer struct {
	sync.RWMutex
	outbound *Outbound
}

type observablePeer interface {
	ConnectionSnapshot() embed.ConnectionSnapshot
	ProbePeer(context.Context, string) (time.Duration, error)
	NotifyNetworkChange()
}
type ProbeResult struct {
	IP            string `json:"ip"`
	FQDN          string `json:"fqdn"`
	State         string `json:"state"`
	RTTMillis     int64  `json:"rtt_ms,omitempty"`
	IPValid       bool   `json:"ip_valid"`
	FQDNTruncated bool   `json:"fqdn_truncated"`
}
type DiagnosticJob struct {
	Stale          bool          `json:"stale"`
	State          string        `json:"state"`
	Started        time.Time     `json:"started,omitempty"`
	Finished       time.Time     `json:"finished,omitempty"`
	Results        []ProbeResult `json:"results"`
	id             string
	total, planned int
	unknown        bool
}

func activeOutbound() *Outbound {
	runtimePeer.RLock()
	defer runtimePeer.RUnlock()
	return runtimePeer.outbound
}
func marshal(v any) string { b, _ := json.Marshal(v); return string(b) }

// RuntimeStatus only reads recorder state. No network requests run on a UI poll.
func RuntimeStatus() string {
	o := activeOutbound()
	if o == nil {
		return marshal(unknownConnection(connectionHeader{Mode: "unknown", ConnectionUnknown: true}, reportSelection{}))
	}
	return runtimeStatusFor(o)
}

func runtimeStatusFor(o *Outbound) string {
	client, err := o.getClient()
	if err != nil {
		return marshal(unknownConnection(connectionHeader{Mode: reportMode(o.options.ConnectionMode), ConnectionUnknown: true}, o.reportViews().Peers))
	}
	p, ok := client.(observablePeer)
	if !ok {
		return marshal(unknownConnection(connectionHeader{Mode: reportMode(o.options.ConnectionMode), ConnectionUnknown: true}, o.reportViews().Peers))
	}
	// The SDK owns its full snapshot allocation. Our DTO copies only one page.
	snapshot := p.ConnectionSnapshot()
	return marshal(projectConnection(o, snapshot, o.reportViews().Peers))
}
func RuntimeDiagnostics() string {
	o := activeOutbound()
	if o == nil {
		return unavailableDiagnosticReport(nil, "unavailable")
	}
	return o.diagnosticsSnapshot()
}

// Local job state only. It must remain independent of the SDK recorder and
// belong to this exact outbound, even while another owner is being retired.
func (o *Outbound) diagnosticsSnapshot() string {
	o.diagMu.Lock()
	defer o.diagMu.Unlock()
	return marshal(o.diagnosticReportLocked())
}
func validDiagnosticID(id string) bool {
	if len(id) != 32 {
		return false
	}
	for _, ch := range id {
		if (ch < '0' || ch > '9') && (ch < 'a' || ch > 'f') {
			return false
		}
	}
	return true
}

// Cancel only the job observed by the caller. Cancellation never frees an occupied worker.
func CancelDiagnosticJob(id string) bool {
	if !validDiagnosticID(id) {
		return false
	}
	o := activeOutbound()
	if o == nil {
		return false
	}
	o.diagMu.Lock()
	defer o.diagMu.Unlock()
	if o.job.id != id || o.job.Stale || (o.job.State != "preparing" && o.job.State != "running") || o.diagCancel == nil {
		return false
	}
	o.diagCancel()
	return true
}

func CancelDiagnostics() string {
	o := activeOutbound()
	if o != nil {
		o.diagMu.Lock()
		if o.diagCancel != nil {
			o.diagCancel()
		}
		o.diagMu.Unlock()
	}
	return RuntimeDiagnostics()
}
func StartDiagnostics() string {
	return startDiagnostics(nil)
}

// The nil production path has no callback. Tests can order a physical epoch
// change precisely after watcher retirement, without a scheduling sleep.
func startDiagnostics(afterSnapshot func(bool)) string {
	o := activeOutbound()
	if o == nil {
		return unavailableDiagnosticReport(nil, "unavailable")
	}
	client, err := o.getClient()
	if err != nil {
		return unavailableDiagnosticReport(o, "unavailable")
	}
	p, ok := client.(observablePeer)
	if !ok {
		return unavailableDiagnosticReport(o, "unavailable")
	}
	o.diagMu.Lock()
	if _, err := o.getClient(); err != nil {
		o.diagMu.Unlock()
		return unavailableDiagnosticReport(o, "unavailable")
	}
	if o.diagBusy || o.job.State == "running" || o.job.State == "preparing" {
		result := marshal(o.diagnosticReportLocked())
		o.diagMu.Unlock()
		return result
	}
	epoch := o.diagEpoch
	o.diagBusy = true
	handedOff := false
	defer func() {
		if !handedOff {
			o.diagMu.Lock()
			o.diagBusy = false
			o.diagMu.Unlock()
		}
	}()
	var idBytes [16]byte
	rand.Read(idBytes[:])
	id := hex.EncodeToString(idBytes[:])
	started := time.Now()
	limit := o.diagnosticSnapshotTimeout
	if limit <= 0 || limit > 10*time.Second {
		limit = 10 * time.Second
	}
	snapshotContext, snapshotCancel := context.WithTimeout(o.ctx, limit)
	o.diagCancel = snapshotCancel
	o.job = DiagnosticJob{id: id, State: "preparing", Started: started, Results: []ProbeResult{}, unknown: true}
	o.diagMu.Unlock()
	stopSnapshotWatch := context.AfterFunc(snapshotContext, func() {
		o.diagMu.Lock()
		defer o.diagMu.Unlock()
		if o.job.State == "preparing" && o.job.Started.Equal(started) {
			o.job.State = "cancelled"
			if errors.Is(snapshotContext.Err(), context.DeadlineExceeded) {
				o.job.State = "unavailable"
			}
			o.job.Finished = time.Now()
		}
	})
	// The SDK recorder may block. Never hold the lock also used by network
	// updates, teardown or cached diagnostics across an SDK call. Admission
	// remains occupied until this single worker actually returns; the timer only
	// publishes local unavailability and never spawns a replacement SDK reader.
	snapshot := p.ConnectionSnapshot()
	watchStopped := stopSnapshotWatch()
	if afterSnapshot != nil {
		afterSnapshot(watchStopped)
	}
	o.diagMu.Lock()
	snapshotError := snapshotContext.Err()
	late := time.Since(started) >= limit
	snapshotCancel()
	if epoch != o.diagEpoch {
		// The watcher may already have been stopped when InterfaceUpdated cancels
		// the snapshot. Retire only this captured preparing record; otherwise it
		// would block every later request after the actual worker exits.
		if o.job.State == "preparing" && o.job.Started.Equal(started) {
			o.job.State = "cancelled"
			o.job.Stale = true
			o.job.unknown = true
			o.job.Finished = time.Now()
		}
		o.diagMu.Unlock()
		// Preserve the legacy ephemeral acknowledgement. Cached/readback state
		// still uses the complete bounded diagnostic projection above.
		return `{"state":"stale","results":[]}`
	}
	if snapshotError != nil || late {
		o.job.State = "cancelled"
		if errors.Is(snapshotError, context.DeadlineExceeded) || snapshotError == nil && late {
			o.job.State = "unavailable"
		}
		o.job.Finished = time.Now()
		result := marshal(o.diagnosticReportLocked())
		o.diagMu.Unlock()
		return result
	}
	if o.job.State == "running" {
		result := marshal(o.diagnosticReportLocked())
		o.diagMu.Unlock()
		return result
	}
	if _, err := o.getClient(); err != nil {
		o.diagMu.Unlock()
		return unavailableDiagnosticReport(o, "unavailable")
	}
	// A network restart can briefly expose an empty recorder while the control
	// connection is already up. Zero attempted probes is not a completed health
	// check; make this condition explicit and allow a fresh subsequent request.
	if len(snapshot.Peers) == 0 {
		now := time.Now()
		o.job = DiagnosticJob{State: "no_peers", Started: now, Finished: now, Results: []ProbeResult{}}
		o.diagMu.Unlock()
		return RuntimeDiagnostics()
	}
	if len(snapshot.Peers) > reportMaximumTotal {
		o.job = DiagnosticJob{State: "unavailable", Started: started, Finished: time.Now(), Results: []ProbeResult{}, unknown: true}
		result := marshal(o.diagnosticReportLocked())
		o.diagMu.Unlock()
		return result
	}
	// Retain only bounded, owned DTOs and exact valid target strings. Workers do
	// not capture the SDK's full slice or any unbounded FQDN backing allocation.
	type target struct {
		index int
		ip    string
	}
	retained := min(len(snapshot.Peers), ReportRetainedLimit)
	results := make([]ProbeResult, retained)
	targets := make([]target, 0, retained)
	for i := 0; i < retained; i++ {
		peer := snapshot.Peers[i]
		ip, valid := reportIP(peer.IP)
		fqdn, truncated := reportFQDN(peer.FQDN)
		state := "invalid_target"
		if valid {
			state = "queued"
			targets = append(targets, target{i, ip})
		}
		results[i] = ProbeResult{IP: ip, IPValid: valid, FQDN: fqdn, FQDNTruncated: truncated, State: state}
	}
	ctx, cancel := context.WithTimeout(o.ctx, 2*time.Minute)
	o.diagCancel = cancel
	o.job = DiagnosticJob{id: id, State: "running", Started: started, Results: results, total: len(snapshot.Peers), planned: len(targets)}
	snapshot.Peers = nil
	handedOff = true
	o.diagMu.Unlock()
	go func() {
		defer cancel()
		var wg sync.WaitGroup
		queue := make(chan target)
		for worker := 0; worker < 4; worker++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for target := range queue {
					i := target.index
					state := "cancelled"
					var rtt time.Duration
					if ctx.Err() == nil && (DiagnosticsAllowed == nil || DiagnosticsAllowed()) {
						o.diagMu.Lock()
						o.job.Results[i].State = "checking"
						o.diagMu.Unlock()
						probeCtx, stop := context.WithTimeout(ctx, 12*time.Second)
						var err error
						rtt, err = p.ProbePeer(probeCtx, target.ip)
						stop()
						state = "reply"
						if err != nil || ctx.Err() != nil {
							state = "no_reply"
							if errors.Is(err, context.Canceled) || ctx.Err() != nil {
								state = "cancelled"
							}
						}
					}
					o.diagMu.Lock()
					o.job.Results[i].State = state
					o.job.Results[i].RTTMillis = min(reportNumber(rtt.Milliseconds()), 12000)
					o.diagMu.Unlock()
				}
			}()
		}
		for _, target := range targets {
			queue <- target
		}
		close(queue)
		wg.Wait()
		o.diagMu.Lock()
		o.job.State = "completed"
		if ctx.Err() != nil {
			o.job.State = "cancelled"
		} else if report := o.diagnosticReportLocked(); report.MetadataUnknown || report.Coverage.Checked != report.Coverage.Total || report.Coverage.Planned != report.Coverage.Total || report.Coverage.Omitted != 0 {
			o.job.State = "partial"
		}
		o.job.Finished = time.Now()
		o.diagCancel = nil
		o.diagBusy = false
		o.diagMu.Unlock()
	}()
	return RuntimeDiagnostics()
}
