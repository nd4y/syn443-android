package bridge

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"sync"
	"time"
)

type privateAdaptiveOwnerKey struct{}
type privateAdaptiveAdmission func(recovery bool) (release func(), ok bool)

// Local native ownership only. No policy/JNI registration or common scheduler
// is implied. A compiled admission callback must be nonblocking; nil conserves
// resources using this owner's single worker and the hub/pool's hard limits.
type privateAdaptiveOwner struct {
	mu                    sync.Mutex // owner -> reference -> hub -> pool
	ref                   *privateAdaptiveReference
	hub                   *privateAdaptiveHub
	ctx                   context.Context
	cancel                context.CancelFunc
	stopParent            func() bool
	nonce                 [32]byte
	epoch                 uint64
	modeUntilBootMS       int64
	policyScope, wireHash string
	scope, mode           string
	ready, closed, busy   bool
	uncertainPermit       bool
	workerDone            chan struct{}
	workStarted           int64
	cancelWork            context.CancelFunc
	admit                 privateAdaptiveAdmission
	report                privateAdaptiveOwnerReport
	receipt               *privateAdaptiveReceipt
}

type privateAdaptiveOwnerReport struct {
	Request              string                   `json:"request"`
	Running              bool                     `json:"running"`
	NativeEpoch          uint64                   `json:"nativeEpoch"`
	Scope                string                   `json:"scope"`
	ModeUntilBootMS      int64                    `json:"modeUntilBootMs,omitempty"`
	HomeUntilBootMS      int64                    `json:"homeProofUntilBootMs,omitempty"`
	PolicyScope          string                   `json:"policyScope"`
	Ready                bool                     `json:"ready"`
	Group                string                   `json:"group"`
	Hops                 []string                 `json:"hops"`
	Code                 string                   `json:"code"`
	CheckCode            string                   `json:"checkCode"`
	CheckCompletedBootMS int64                    `json:"checkCompletedBootMs,omitempty"`
	ElapsedMS            int64                    `json:"elapsedMs"`
	ProbeMS              int64                    `json:"probeMs"`
	Receipt              string                   `json:"receipt"`
	GroupSelected        bool                     `json:"groupSelected"`
	WorkAgeMS            int64                    `json:"workAgeMs"`
	SelectionToken       uint64                   `json:"selectionToken,omitempty"`
	RecheckHints         []privatePathRecheckHint `json:"recheckHints"`
	CheckPlan            *routeCheckPlanReport    `json:"checkPlan,omitempty"`
}

func (privateAdaptiveOwnerReport) String() string     { return "PrivateAdaptiveOwnerReport([redacted])" }
func (r privateAdaptiveOwnerReport) GoString() string { return r.String() }

func newPrivateAdaptiveOwner(r *privateAdaptiveReference, policyScope, mode, wireHash string, admit privateAdaptiveAdmission) (*privateAdaptiveOwner, error) {
	if r == nil || !privateScopeID.MatchString(policyScope) || !privateScopeID.MatchString(wireHash) || !privateAdaptiveMode(mode) {
		return nil, errPrivatePath
	}
	o := &privateAdaptiveOwner{ref: r, epoch: 1, policyScope: policyScope, mode: mode, wireHash: wireHash, admit: admit}
	if _, err := rand.Read(o.nonce[:]); err != nil {
		return nil, errPrivatePath
	}
	r.mu.Lock()
	if r.closed || r.ctx.Err() != nil || r.hub == nil || r.ctx.Value(privateAdaptiveOwnerKey{}) != nil {
		r.mu.Unlock()
		return nil, errPrivatePath
	}
	o.hub = r.hub
	h := o.hub
	h.mu.Lock()
	h.pool.mu.Lock()
	fresh := !h.closed && !h.busy && h.receipt == nil && !h.pool.closed && !h.pool.building && !h.pool.probing &&
		len(h.pool.entries) == 0 && h.pool.used == 0 && h.pool.holds == 0 && privateManagedLease(h.pool.lease)
	h.pool.mu.Unlock()
	h.mu.Unlock()
	o.scope = o.deriveScope()
	if !fresh || !h.changeScope(o.scope, mode) || r.ctx.Err() != nil {
		r.mu.Unlock()
		return nil, errPrivatePath
	}
	// The reference is still before Start and no data owner exists. Preserve its
	// registry/cancellation lineage while preventing a second owner of this box.
	r.ctx = context.WithValue(r.ctx, privateAdaptiveOwnerKey{}, o)
	o.ctx, o.cancel = context.WithCancel(r.ctx)
	r.mu.Unlock()
	o.ready = true
	o.resetReportLocked("idle")
	o.mu.Lock()
	o.stopParent = context.AfterFunc(o.ctx, o.Close)
	o.mu.Unlock()
	return o, nil
}

func (o *privateAdaptiveOwner) deriveScope() string {
	var epoch [8]byte
	binary.BigEndian.PutUint64(epoch[:], o.epoch)
	h := sha256.New()
	_, _ = h.Write(o.nonce[:])
	_, _ = h.Write(epoch[:])
	_, _ = h.Write([]byte(o.policyScope))
	_, _ = h.Write([]byte(o.wireHash))
	_, _ = h.Write([]byte(o.mode))
	return hex.EncodeToString(h.Sum(nil))
}

// Busy remains occupied after cancellation until the worker has finished all
// hub work and its actual admission release. No timer creates a replacement.
func (o *privateAdaptiveOwner) refreshWorkerLocked() {
	if o.busy && o.workerDone != nil {
		select {
		case <-o.workerDone:
			o.busy, o.cancelWork = false, nil
		default:
		}
	}
}

func (o *privateAdaptiveOwner) currentLocked() bool {
	if o.closed || o.ctx.Err() != nil || !o.ready {
		return false
	}
	o.ref.mu.Lock()
	valid := !o.ref.closed && o.ref.hub == o.hub && o.ref.ctx.Value(privateAdaptiveOwnerKey{}) == o
	o.ref.mu.Unlock()
	if !valid {
		return false
	}
	o.hub.mu.Lock()
	defer o.hub.mu.Unlock()
	p := o.hub.pool
	p.mu.Lock()
	defer p.mu.Unlock()
	return !o.hub.closed && p.modeCurrent() && o.hub.scope == o.scope && o.hub.mode == o.mode && !p.closed && p.ctx.Err() == nil &&
		p.scope == o.scope && privateManagedLease(p.lease)
}

func (o *privateAdaptiveOwner) resetReportLocked(code string) {
	o.receipt = nil
	o.report = privateAdaptiveOwnerReport{NativeEpoch: o.epoch, Scope: o.scope, Hops: []string{}, Code: code}
}

func (o *privateAdaptiveOwner) context() (uint64, string, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.refreshWorkerLocked()
	return o.epoch, o.scope, o.currentLocked()
}

// Called from actual native network observation before accepting another local
// policy frame. Revoke the old hub scope immediately, retaining its busy owner.
func (o *privateAdaptiveOwner) invalidate() bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed {
		return false
	}
	o.ready = false
	o.modeUntilBootMS = 0
	if o.cancelWork != nil {
		o.cancelWork()
	}
	if o.epoch == math.MaxInt64 {
		o.closed = true
		o.cancel()
		o.ref.Close()
		o.resetReportLocked("closed")
		return false
	}
	o.epoch++
	o.scope = o.deriveScope()
	if !o.hub.changeScope(o.scope, o.mode) {
		o.closed = true
		o.cancel()
		o.ref.Close()
	}
	o.resetReportLocked("not_ready")
	return !o.closed
}

func (o *privateAdaptiveOwner) configure(expectedEpoch uint64, policyScope, mode string) bool {
	return o.configureModeDeadline(expectedEpoch, policyScope, mode, 0)
}

func (o *privateAdaptiveOwner) configureModeDeadline(expectedEpoch uint64, policyScope, mode string, deadline int64) bool {
	if !privateScopeID.MatchString(policyScope) || !privateAdaptiveMode(mode) {
		return false
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed || o.ctx.Err() != nil || expectedEpoch != o.epoch {
		return false
	}
	if o.ready && o.policyScope == policyScope && o.mode == mode {
		if !o.hub.setModeDeadline(o.scope, mode, deadline) {
			return false
		}
		o.modeUntilBootMS = deadline
		return o.currentLocked()
	}
	if o.cancelWork != nil {
		o.cancelWork()
	}
	o.policyScope, o.mode = policyScope, mode
	scope := o.deriveScope()
	if scope != o.scope && !o.hub.changeScope(scope, mode) {
		o.ready = false
		return false
	}
	if !o.hub.setModeDeadline(scope, mode, deadline) {
		o.ready = false
		return false
	}
	o.modeUntilBootMS = deadline
	o.scope, o.ready = scope, true
	o.resetReportLocked("idle")
	if !o.currentLocked() {
		o.ready = false
		return false
	}
	return true
}

func (o *privateAdaptiveOwner) start(request string, expectedEpoch uint64, scope, group string, hops []string) bool {
	return o.startUntil(request, expectedEpoch, scope, group, hops, 0)
}

func (o *privateAdaptiveOwner) startUntil(request string, expectedEpoch uint64, scope, group string, hops []string, retryUntil int64) bool {
	if !privateGroupID.MatchString(request) || len(hops) < 1 || len(hops) > 4 {
		return false
	}
	owned := append([]string(nil), hops...)
	o.mu.Lock()
	defer o.mu.Unlock()
	o.refreshWorkerLocked()
	if !o.currentLocked() || o.busy || o.receipt != nil || expectedEpoch != o.epoch || scope != o.scope ||
		!o.hub.graph.Allows(group, o.mode, owned) {
		return false
	}
	started := o.hub.pool.lease.clock()
	if started < 0 || started > math.MaxInt64-30_000 {
		return false
	}
	deadline := started + 30_000
	if retryUntil != 0 {
		if retryUntil <= started || retryUntil > started+15_000 {
			return false
		}
		deadline = retryUntil
	}
	o.hub.mu.Lock()
	o.hub.pool.mu.Lock()
	selector := o.hub.groups[group]
	recovery := selector != nil && selector.active == nil
	o.hub.pool.mu.Unlock()
	o.hub.mu.Unlock()
	if selector == nil {
		return false
	}
	var token [32]byte
	if _, err := rand.Read(token[:]); err != nil {
		return false
	}
	release := func() {}
	if o.admit != nil {
		var ok bool
		func() {
			defer func() {
				if recover() != nil {
					o.uncertainPermit = true
				}
			}()
			release, ok = o.admit(recovery)
		}()
		if !ok || release == nil || o.uncertainPermit {
			if ok || o.uncertainPermit {
				o.uncertainPermit, o.closed, o.ready = true, true, false
				o.cancel()
				o.ref.Close()
				o.resetReportLocked("closed")
			}
			return false
		}
	}
	ctx, cancel := context.WithTimeout(o.ctx, time.Duration(deadline-started)*time.Millisecond)
	ctx = context.WithValue(ctx, privateAdaptiveWorkDeadlineKey{}, deadline)
	done := make(chan struct{})
	o.busy, o.workerDone, o.cancelWork = true, done, cancel
	o.workStarted = started
	o.report = privateAdaptiveOwnerReport{Request: request, Running: true, NativeEpoch: o.epoch, Scope: o.scope,
		Group: group, Hops: owned, Code: "checking"}
	epoch := o.epoch
	go o.run(ctx, cancel, done, release, request, epoch, scope, group, owned, hex.EncodeToString(token[:]), started)
	return true
}

func (o *privateAdaptiveOwner) run(ctx context.Context, cancel context.CancelFunc, done chan struct{}, release func(), request string, epoch uint64, scope, group string, hops []string, token string, started int64) {
	defer close(done)
	defer cancel()
	var receipt *privateAdaptiveReceipt
	var err error
	defer func() {
		panicked := recover() != nil
		released := false
		func() {
			defer func() { _ = recover() }()
			release()
			released = true
		}()
		o.mu.Lock()
		defer o.mu.Unlock()
		if !released {
			o.uncertainPermit, o.closed, o.ready = true, true, false
			o.cancel()
			o.ref.Close()
			o.resetReportLocked("closed")
		}
		now := o.hub.pool.lease.clock()
		if o.epoch != epoch || o.scope != scope || o.report.Request != request || !o.currentLocked() {
			if o.epoch == epoch && o.scope == scope && o.report.Request == request {
				o.report.Code, o.report.Receipt = "probe_unavailable", ""
			}
			if receipt != nil {
				o.hub.discard(receipt)
			}
			return
		}
		o.report.Code, o.report.CheckCode, o.report.CheckCompletedBootMS, o.report.ElapsedMS = "probe_unavailable", "", 0, 0
		o.report.CheckPlan = nil
		fresh := !panicked && released && ctx.Err() == nil && started >= 0 && now >= started && now-started < 30_000 && privateAdaptiveWorkCurrent(ctx, o.hub.pool.lease.clock)
		profileReport := profileErrorReport(err)
		if receipt != nil && receipt.proof != nil {
			profileReport = receipt.proof.checkPlan.clone()
		}
		if profileReport != nil {
			if !fresh {
				profileReport = profileReport.unknown()
			}
			o.report.CheckPlan = profileReport.clone()
		}
		if errors.Is(err, errPrivateExitMismatch) && fresh {
			o.report.Code = "exit_mismatch"
		}
		var failure *privateCheckedFailure
		if fresh && errors.As(err, &failure) && failure != nil && privateCheckedProbeCode(failure.code) &&
			failure.completedBootMS > 0 && failure.completedBootMS >= started && failure.completedBootMS <= now && now-failure.completedBootMS <= 30_000 {
			o.report.Code, o.report.CheckCode, o.report.CheckCompletedBootMS = "check_failed", failure.code, failure.completedBootMS
		}
		if now >= started && now-started <= 30_000 {
			o.report.ElapsedMS = now - started
		}
		if fresh && err == nil && receipt != nil {
			o.receipt, o.report.Receipt, o.report.Code = receipt, token, "verified"
			o.report.CheckCompletedBootMS = receipt.proof.completed
			o.report.ProbeMS = receipt.proof.completed - receipt.proof.started
		} else if receipt != nil {
			o.hub.discard(receipt)
		}
	}()
	o.mu.Lock()
	current := o.epoch == epoch && o.scope == scope && o.currentLocked() && ctx.Err() == nil
	o.mu.Unlock()
	if !current || started < 0 || started > math.MaxInt64-30_000 {
		err = errPrivatePath
		return
	}
	receipt, err = o.hub.prepareProbe(ctx, group, hops)
}

func (o *privateAdaptiveOwner) snapshot() string {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.refreshWorkerLocked()
	report := o.report
	report.CheckPlan = report.CheckPlan.clone()
	report.NativeEpoch, report.Scope, report.Running, report.Ready = o.epoch, o.scope, o.busy, o.currentLocked()
	report.PolicyScope = o.policyScope
	if o.mode == "HOME_WIFI" {
		report.HomeUntilBootMS = o.modeUntilBootMS
	} else {
		report.ModeUntilBootMS = o.modeUntilBootMS
	}
	if report.Code == "check_failed" {
		now := o.hub.pool.lease.clock()
		if !report.Ready || report.CheckCompletedBootMS <= 0 || now < report.CheckCompletedBootMS || now-report.CheckCompletedBootMS > 30_000 {
			// A delayed read cannot restart the freshness window. Retire the
			// observation metadata permanently, while retaining actual flows.
			o.report.Code, o.report.CheckCode, o.report.CheckCompletedBootMS = "probe_unavailable", "", 0
			report.Code, report.CheckCode, report.CheckCompletedBootMS = "probe_unavailable", "", 0
			o.report.CheckPlan, report.CheckPlan = o.report.CheckPlan.unknown(), report.CheckPlan.unknown()
		}
	}
	if o.busy {
		now := o.hub.pool.lease.clock()
		if now < o.workStarted || now-o.workStarted > 60_000 {
			report.WorkAgeMS = 60_000
		} else {
			report.WorkAgeMS = now - o.workStarted
		}
	}
	o.hub.mu.Lock()
	o.hub.pool.mu.Lock()
	report.RecheckHints = []privatePathRecheckHint{}
	if report.Ready {
		report.RecheckHints = o.hub.pool.recheckHintsLocked(o.hub.pool.lease.clock())
	}
	if selector := o.hub.groups[report.Group]; selector != nil {
		report.GroupSelected = selector.validLocked() && selector.active != nil
	}
	o.hub.pool.mu.Unlock()
	o.hub.mu.Unlock()
	if !report.Ready {
		report.Receipt = ""
		report.SelectionToken = 0
		o.report.CheckPlan, report.CheckPlan = o.report.CheckPlan.unknown(), report.CheckPlan.unknown()
	}
	raw, err := json.Marshal(report)
	if err != nil || len(raw) > 32768 {
		return `{"request":"","running":false,"ready":false,"code":"unavailable"}`
	}
	return string(raw)
}

func (o *privateAdaptiveOwner) receiptMatchesLocked(request, token string, expectedEpoch uint64, scope string) bool {
	o.refreshWorkerLocked()
	return !o.busy && o.currentLocked() && o.receipt != nil && request == o.report.Request && token != "" &&
		token == o.report.Receipt && expectedEpoch == o.epoch && scope == o.scope
}

func (o *privateAdaptiveOwner) commit(request, token string, expectedEpoch uint64, scope string, graceMS int64) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.receiptMatchesLocked(request, token, expectedEpoch, scope) {
		return false
	}
	r := o.receipt
	o.receipt, o.report.Receipt, o.report.Code = nil, "", "commit_rejected"
	if !o.hub.commit(r, graceMS) {
		return false
	}
	o.report.Code = "selected"
	// Echo the consumed receipt in this acknowledgement only. o.receipt stays
	// nil, so the diagnostic echo cannot authorize a second commit.
	o.report.Receipt = token
	o.report.SelectionToken = r.proof.selectionToken
	return true
}

func (o *privateAdaptiveOwner) discard(request, token string, expectedEpoch uint64, scope string) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.receiptMatchesLocked(request, token, expectedEpoch, scope) {
		return false
	}
	r := o.receipt
	o.receipt, o.report.Receipt, o.report.Code = nil, "", "discarded"
	return o.hub.discard(r)
}

func (o *privateAdaptiveOwner) Close() {
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.closed {
		o.closed, o.ready = true, false
		if o.stopParent != nil {
			o.stopParent()
			o.stopParent = nil
		}
		o.cancel()
		if o.cancelWork != nil {
			o.cancelWork()
		}
		o.resetReportLocked("closed")
	}
	o.ref.Close()
}

func (o *privateAdaptiveOwner) stopped() bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.refreshWorkerLocked()
	return o.closed && !o.busy && !o.uncertainPermit && o.ref.stopped() && o.hub.stopped()
}

func (*privateAdaptiveOwner) String() string     { return "PrivateAdaptiveOwner([redacted])" }
func (o *privateAdaptiveOwner) GoString() string { return o.String() }
