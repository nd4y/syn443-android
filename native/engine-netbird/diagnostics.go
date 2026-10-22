package netbird

import (
	"context"
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

var diagnosticAdmission atomic.Bool

// One optional worker; a blocked SDK snapshot never blocks host control or
// creates an unbounded queue of jobs from repeated UI taps.
func RequestDiagnostics() bool {
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
	IP        string `json:"ip"`
	FQDN      string `json:"fqdn"`
	State     string `json:"state"`
	RTTMillis int64  `json:"rtt_ms,omitempty"`
}
type DiagnosticJob struct {
	Stale    bool          `json:"stale"`
	State    string        `json:"state"`
	Started  time.Time     `json:"started,omitempty"`
	Finished time.Time     `json:"finished,omitempty"`
	Results  []ProbeResult `json:"results"`
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
		return `{"active":false,"peers":[]}`
	}
	client, err := o.getClient()
	if err != nil {
		return `{"active":false,"peers":[]}`
	}
	p, ok := client.(observablePeer)
	if !ok {
		return `{"active":false,"peers":[]}`
	}
	mode := "vless"
	if o.options.ConnectionMode == "direct" {
		mode = "direct"
	}
	selected := o.options.Detour
	if mode == "direct" {
		selected = ""
	} else {
		seen := map[string]bool{}
		for selected != "" && !seen[selected] && len(seen) < 64 {
			seen[selected] = true
			out, ok := o.manager.Outbound(selected)
			if !ok {
				break
			}
			group, ok := out.(interface{ Now() string })
			if !ok {
				break
			}
			selected = group.Now()
		}
	}
	return marshal(struct {
		Active        bool      `json:"active"`
		Mode          string    `json:"mode"`
		Tag           string    `json:"tag"`
		ProxyGroup    string    `json:"proxy_group"`
		SelectedProxy string    `json:"selected_proxy"`
		Sampled       time.Time `json:"sampled_at"`
		embed.ConnectionSnapshot
	}{true, mode, o.Tag(), o.options.Detour, selected, time.Now(), p.ConnectionSnapshot()})
}
func RuntimeDiagnostics() string {
	o := activeOutbound()
	if o == nil {
		return `{"state":"unavailable","results":[]}`
	}
	o.diagMu.Lock()
	defer o.diagMu.Unlock()
	return marshal(o.job)
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
	o := activeOutbound()
	if o == nil {
		return `{"state":"unavailable","results":[]}`
	}
	client, err := o.getClient()
	if err != nil {
		return `{"state":"unavailable","results":[]}`
	}
	p, ok := client.(observablePeer)
	if !ok {
		return `{"state":"unavailable","results":[]}`
	}
	o.diagMu.Lock()
	if _, err := o.getClient(); err != nil {
		o.diagMu.Unlock()
		return `{"state":"unavailable","results":[]}`
	}
	if o.job.State == "running" {
		result := marshal(o.job)
		o.diagMu.Unlock()
		return result
	}
	epoch := o.diagEpoch
	o.diagMu.Unlock()
	// The SDK recorder may block. Never hold the lock also used by network
	// updates, teardown or cached diagnostics across an SDK call.
	peers := p.ConnectionSnapshot().Peers
	o.diagMu.Lock()
	if epoch != o.diagEpoch {
		o.diagMu.Unlock()
		return `{"state":"stale","results":[]}`
	}
	if o.job.State == "running" {
		result := marshal(o.job)
		o.diagMu.Unlock()
		return result
	}
	if _, err := o.getClient(); err != nil {
		o.diagMu.Unlock()
		return `{"state":"unavailable","results":[]}`
	}
	// Avoid unbounded jobs for a pathological roster. Every peer is listed, with a
	// distinct limit result beyond the supported active probe budget.
	ctx, cancel := context.WithTimeout(o.ctx, 2*time.Minute)
	o.diagCancel = cancel
	o.job = DiagnosticJob{State: "running", Started: time.Now(), Results: make([]ProbeResult, len(peers))}
	for i, p := range peers {
		state := "queued"
		if i >= 1024 {
			state = "limit"
		}
		o.job.Results[i] = ProbeResult{IP: p.IP, FQDN: p.FQDN, State: state}
	}
	o.diagMu.Unlock()
	go func() {
		defer cancel()
		var wg sync.WaitGroup
		queue := make(chan int)
		for worker := 0; worker < 4; worker++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := range queue {
					state := "cancelled"
					var rtt time.Duration
					if ctx.Err() == nil {
						o.diagMu.Lock()
						o.job.Results[i].State = "checking"
						o.diagMu.Unlock()
						probeCtx, stop := context.WithTimeout(ctx, 12*time.Second)
						var err error
						rtt, err = p.ProbePeer(probeCtx, peers[i].IP)
						stop()
						state = "reply"
						if err != nil {
							state = "no_reply"
							if errors.Is(err, context.Canceled) || ctx.Err() != nil {
								state = "cancelled"
							}
						}
					}
					o.diagMu.Lock()
					o.job.Results[i].State = state
					o.job.Results[i].RTTMillis = rtt.Milliseconds()
					o.diagMu.Unlock()
				}
			}()
		}
		for i := range peers {
			if i >= 1024 {
				break
			}
			queue <- i
		}
		close(queue)
		wg.Wait()
		o.diagMu.Lock()
		o.job.State = "completed"
		if ctx.Err() != nil {
			o.job.State = "cancelled"
		}
		o.job.Finished = time.Now()
		o.diagCancel = nil
		o.diagMu.Unlock()
	}()
	return RuntimeDiagnostics()
}
