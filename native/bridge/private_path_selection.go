package bridge

import (
	"context"
	"crypto/x509"
	"errors"
	"math"
	"net"
	"regexp"
	"sync"
	"sync/atomic"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

var errPrivateExitMismatch = errors.New("verified exit predicate mismatch")

// An observed failed check, never a proxy verdict or a selection proof. The
// only payload is a compiled finite code and its actual BOOTTIME completion;
// source errors/targets are not kept.
type privateCheckedFailure struct {
	code            string
	completedBootMS int64
	checkPlan       *routeCheckPlanReport
}

type privateProbeDialKey struct{}

// Ephemeral evidence of admitted final-adapter dispatch, not proof that bytes
// reached a physical network. No endpoint, raw error or credentials are kept.
type privateProbeDialObservation struct {
	dispatched, completed, returnedError, validConn, localRefusal atomic.Bool
}

func (o *privateProbeDialObservation) observedFailure() bool {
	return o != nil && !o.localRefusal.Load() && o.dispatched.Load() && o.completed.Load() && (o.validConn.Load() || o.returnedError.Load())
}

func privateCheckedProbeCode(code string) bool {
	switch code {
	case "dial_failed", "check_timeout", "tls_failed", "ssh_banner_mismatch", "request_failed", "response_failed", "exit_evidence_invalid", "http_response_mismatch":
		return true
	}
	return false
}
func (*privateCheckedFailure) Error() string      { return "private route check failed" }
func (*privateCheckedFailure) String() string     { return "PrivateCheckedFailure([redacted])" }
func (e *privateCheckedFailure) GoString() string { return e.String() }

var privateGroupID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)

// Internal primitive only. The authorized catalogue, shared priority scheduler
// and signed capability gate must all be wired before exposing this to Runtime.
// All mutable fields are guarded by pool.mu; no I/O runs under that lock.
type privatePathSelector struct {
	pool                     *privatePathPool
	group, scope, checksHash string
	checks                   []routeCheck
	program                  *routeCheckProgram
	active                   *privatePoolEntry
	proof                    *privateSelectionProof
	flowEpoch                uint64
	flowContext              context.Context
	cancelFlows              context.CancelFunc
	closed                   bool
	hint                     privatePathHintSlot
}

// A pointer minted only by successful real probes, consumed exactly once. A
// copied struct, score, caller supplied result or old context is not authority.
type privateSelectionProof struct {
	selector                 *privatePathSelector
	entry, previous          *privatePoolEntry
	scope, group, checksHash string
	started, completed       int64
	workDeadline             int64
	flowEpoch                uint64
	selectionToken           uint64 // captured only by the exact successful commit
	checkPlan                *routeCheckPlanReport
}

func newPrivatePathSelector(p *privatePathPool, scope, group string, checks []routeCheck) (*privatePathSelector, error) {
	program, err := newRouteCheckProgram(checks, nil)
	if err != nil {
		return nil, errPrivatePath
	}
	return newPrivatePathSelectorProgram(p, scope, group, program)
}
func newPrivatePathSelectorProgram(p *privatePathPool, scope, group string, program *routeCheckProgram) (*privatePathSelector, error) {
	if p == nil || program == nil || !privateGroupID.MatchString(group) {
		return nil, errPrivatePath
	}
	owned, err := newRouteCheckProgram(program.checks, program.profile)
	if err != nil {
		return nil, errPrivatePath
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.ctx.Err() != nil || !privateManagedLease(p.lease) || scope != p.scope || len(p.selectors) >= privateGroupLimit || p.selectors[group] != nil {
		return nil, errPrivatePath
	}
	flowContext, cancelFlows := context.WithCancel(p.ctx)
	s := &privatePathSelector{pool: p, scope: scope, group: group, checks: owned.checks, program: owned, checksHash: owned.hash,
		flowEpoch: 1, flowContext: flowContext, cancelFlows: cancelFlows}
	p.selectors[group] = s
	return s, nil
}

func (s *privatePathSelector) validLocked() bool {
	p := s.pool
	return !s.closed && !p.closed && p.ctx.Err() == nil && privateManagedLease(p.lease) && p.modeCurrent() && p.scope == s.scope && p.selectors[s.group] == s
}

// Synchronous admission on an owned caller worker: one probe for the entire
// pool. A blocked adapter cannot create a replacement probe, even after scope
// replacement. Deadline/cancellation also gate the final proof publication.
func (s *privatePathSelector) probe(parent context.Context, candidate *privatePathCandidate) (proof *privateSelectionProof, err error) {
	return s.probeWithRoots(parent, candidate, nil)
}

// An internal fixture seam only. Runtime callers never supply custom roots.
func (s *privatePathSelector) probeWithRoots(parent context.Context, candidate *privatePathCandidate, roots *x509.CertPool) (proof *privateSelectionProof, err error) {
	if s.program != nil && s.program.profile != nil {
		defer func() {
			if err != nil && profileErrorReport(err) == nil {
				err = &routeCheckProfileError{cause: err, report: s.program.profile.emptyReport()}
			}
		}()
	}
	if parent == nil || parent.Err() != nil || candidate == nil || candidate.pool != s.pool {
		return nil, errPrivatePath
	}
	p := s.pool
	p.mu.Lock()
	if !s.validLocked() || p.probing {
		p.mu.Unlock()
		return nil, errPrivatePath
	}
	h, holdErr := candidate.holdLocked(s.scope)
	if holdErr != nil {
		p.mu.Unlock()
		return nil, errPrivatePath
	}
	started, previous, epoch := p.lease.clock(), s.active, s.flowEpoch
	if started < 0 || started > math.MaxInt64-15_000 {
		p.mu.Unlock()
		_ = h.Close()
		return nil, errPrivatePath
	}
	p.probing = true
	s.proof = nil
	p.mu.Unlock()
	duration := 12 * time.Second
	if deadline, ok := parent.Value(privateAdaptiveWorkDeadlineKey{}).(int64); ok {
		remaining := deadline - p.lease.clock()
		if remaining < 0 {
			remaining = 0
		}
		if remaining < 12_000 {
			duration = time.Duration(remaining) * time.Millisecond
		}
	}
	ctx, cancel := context.WithTimeout(parent, duration)
	stop := context.AfterFunc(candidate.entry.path.ctx, cancel)
	defer func() {
		stop()
		cancel()
		_ = h.Close()
		p.mu.Lock()
		p.probing = false
		p.mu.Unlock()
		if recover() != nil {
			proof, err = nil, errPrivatePath
		}
	}()
	var profileReport *routeCheckPlanReport
	if s.program.profile != nil {
		current := func() bool {
			p.mu.Lock()
			defer p.mu.Unlock()
			now, fresh := s.freshProbeLocked(ctx, candidate.entry, previous, epoch, started)
			return fresh && now-started < s.program.profile.DeadlineMS
		}
		evaluation := evaluateRouteCheckProfile(ctx, s.program.profile, p.lease.clock, current, func(checkContext context.Context, check routeCheck) routeCheckProbeResult {
			observation := &privateProbeDialObservation{}
			checkContext = context.WithValue(checkContext, privateProbeDialKey{}, observation)
			code, complete := probeRouteWithClock(checkContext, func(dialContext context.Context, network string, dst M.Socksaddr) (net.Conn, error) {
				return candidate.dialTCP(s.scope, dialContext, network, dst)
			}, check, roots, p.lease.clock)
			return routeCheckProbeResult{code: code, complete: complete, witness: observation.observedFailure()}
		})
		profileReport = evaluation.report
		if profileReport.Outcome != checkTrue {
			p.mu.Lock()
			completed, fresh := s.freshProbeLocked(ctx, candidate.entry, previous, epoch, started)
			fresh = fresh && completed-started < s.program.profile.DeadlineMS
			if fresh && evaluation.hardExit && profileReport.Outcome == checkFalse && previous == candidate.entry {
				s.withdrawLocked()
			}
			p.mu.Unlock()
			if !fresh {
				return nil, &routeCheckProfileError{cause: errPrivatePath, report: profileReport.unknown()}
			}
			if evaluation.hardExit && profileReport.Outcome == checkFalse {
				return nil, &routeCheckProfileError{cause: errPrivateExitMismatch, report: profileReport}
			}
			if profileReport.Outcome == checkFalse && evaluation.witness >= 0 && privateCheckedProbeCode(evaluation.code) {
				return nil, &privateCheckedFailure{code: evaluation.code, completedBootMS: completed, checkPlan: profileReport}
			}
			return nil, &routeCheckProfileError{cause: errPrivatePath, report: profileReport}
		}
	} else {
		for _, check := range s.checks {
			// A normal timer may not advance while suspended. Check the aggregate
			// BOOTTIME budget before every target, not only before publishing proof.
			now := p.lease.clock()
			if !privateAdaptiveWorkCurrent(ctx, p.lease.clock) || now < started || now-started >= 12_000 {
				return nil, errPrivatePath
			}
			observation := &privateProbeDialObservation{}
			checkContext := context.WithValue(ctx, privateProbeDialKey{}, observation)
			code, complete := probeRouteWithClock(checkContext, func(ctx context.Context, network string, dst M.Socksaddr) (net.Conn, error) {
				return candidate.dialTCP(s.scope, ctx, network, dst)
			}, check, roots, p.lease.clock)
			if !complete || code != "ok" || ctx.Err() != nil {
				if complete && ctx.Err() == nil && (check.Method == "https_exit_country" && code == "exit_country_mismatch" ||
					check.Method == "https_exit_ip" && code == "exit_ip_mismatch") {
					p.mu.Lock()
					_, fresh := s.freshProbeLocked(ctx, candidate.entry, previous, epoch, started)
					if previous == candidate.entry && fresh {
						s.withdrawLocked()
					}
					p.mu.Unlock()
					if fresh {
						return nil, errPrivateExitMismatch
					}
				}
				if complete && ctx.Err() == nil && observation.observedFailure() && privateCheckedProbeCode(code) {
					p.mu.Lock()
					completed, fresh := s.freshProbeLocked(ctx, candidate.entry, previous, epoch, started)
					p.mu.Unlock()
					if fresh {
						return nil, &privateCheckedFailure{code: code, completedBootMS: completed}
					}
				}
				return nil, errPrivatePath
			}
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	e := candidate.entry
	now, fresh := s.freshProbeLocked(ctx, e, previous, epoch, started)
	if s.program.profile != nil && now-started >= s.program.profile.DeadlineMS {
		fresh = false
	}
	if !fresh {
		if profileReport != nil {
			return nil, &routeCheckProfileError{cause: errPrivatePath, report: profileReport.unknown()}
		}
		return nil, errPrivatePath
	}
	deadline, _ := parent.Value(privateAdaptiveWorkDeadlineKey{}).(int64)
	proof = &privateSelectionProof{workDeadline: deadline, selector: s, entry: e, previous: previous, scope: s.scope, group: s.group, checksHash: s.checksHash, started: started, completed: now, flowEpoch: epoch, checkPlan: profileReport}
	s.proof = proof
	return proof, nil
}

// Called with pool.mu held. Neither a late observation nor a probe of a reserve
// can revoke the independently selected current candidate.
func (s *privatePathSelector) freshProbeLocked(ctx context.Context, e, previous *privatePoolEntry, epoch uint64, started int64) (int64, bool) {
	p := s.pool
	now := p.lease.clock()
	return now, s.validLocked() && privateAdaptiveWorkCurrent(ctx, p.lease.clock) && s.active == previous && s.flowEpoch == epoch &&
		now >= started && now-started < 12_000 && e.scope == s.scope && p.entries[e.id] == e &&
		!e.draining && !e.queued && !e.retained && !e.closed && e.path.ctx.Err() == nil
}

func (s *privatePathSelector) withdrawLocked() {
	p := s.pool
	s.proof = nil
	s.hint.clearLocked()
	s.cancelFlows()
	if s.flowEpoch == math.MaxUint64 {
		s.closed = true
		delete(p.selectors, s.group)
	} else {
		s.flowEpoch++
		s.flowContext, s.cancelFlows = context.WithCancel(p.ctx)
	}
	if old := s.active; old != nil {
		s.active = nil
		old.activeHolds--
		old.closeRequested = true
		if old.activeHolds == 0 {
			p.drainLocked(old, 120_000)
		}
	}
}

func (s *privatePathSelector) selectVerified(proof *privateSelectionProof, graceMS int64) bool {
	if proof == nil || graceMS < 1000 || graceMS > 300_000 {
		return false
	}
	p := s.pool
	p.mu.Lock()
	defer p.mu.Unlock()
	p.expireDrainsLocked()
	now := p.lease.clock()
	if !s.validLocked() || s.proof != proof || proof.selector != s || proof.scope != s.scope || proof.group != s.group || proof.checksHash != s.checksHash || proof.previous != s.active || proof.flowEpoch != s.flowEpoch {
		return false
	}
	if now < proof.completed || proof.completed < proof.started || now-proof.started > 15_000 ||
		(proof.workDeadline != 0 && now >= proof.workDeadline) {
		return false
	}
	s.proof = nil
	e := proof.entry
	if e == nil || p.entries[e.id] != e || e.scope != s.scope || e.draining || e.queued || e.retained || e.closed || e.path == nil || e.path.ctx.Err() != nil {
		return false
	}
	old := s.active
	proof.selectionToken = s.hint.selectedLocked(now)
	if old == e {
		return true
	}
	e.activeHolds++
	s.active = e
	if old != nil {
		old.activeHolds--
		old.closeRequested = true
		if old.activeHolds == 0 {
			p.drainLocked(old, graceMS)
		}
	}
	return true
}

func (s *privatePathSelector) dialTCP(parent context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if parent == nil || parent.Err() != nil {
		return nil, errPrivatePath
	}
	p := s.pool
	p.mu.Lock()
	if !s.validLocked() || s.active == nil {
		p.mu.Unlock()
		return nil, errPrivatePath
	}
	c := &privatePathCandidate{pool: p, entry: s.active}
	h, err := c.holdLocked(s.scope)
	epoch, groupContext, selectionToken := s.flowEpoch, s.flowContext, s.hint.token
	p.mu.Unlock()
	if err != nil {
		return nil, errPrivatePath
	}
	// This context has no dial deadline: a successfully connected stream must
	// survive the bounded 30s construction/dial phase until its actual owner ends.
	ctx, cancel := context.WithCancel(parent)
	stopDial := context.AfterFunc(groupContext, cancel)
	conn, err := h.dialTCP(s.scope, ctx, network, destination)
	unlinked := stopDial()
	if err != nil {
		cancel()
		return nil, errPrivatePath
	}
	p.mu.Lock()
	if !unlinked || ctx.Err() != nil || !s.validLocked() || s.flowEpoch != epoch || groupContext.Err() != nil {
		p.mu.Unlock()
		cancel()
		_ = conn.Close()
		return nil, errPrivatePath
	}
	f := &privateSelectedTCPFlow{Conn: conn, selector: s, epoch: epoch, groupContext: groupContext, cancel: cancel}
	if base, ok := conn.(*privateTCPFlow); ok && base != nil && base.owner != nil && base.owner.hold.entry == c.entry &&
		s.active == c.entry && selectionToken != 0 && s.hint.token == selectionToken && s.hint.clockLocked(p.lease.clock()) {
		base.owner.hint = privatePathHintFlow{selector: s, entry: c.entry, token: selectionToken, lifetime: ctx}
	}
	// Assign both hooks while holding the same mutex Close uses to read them.
	// A cancelled context can run its callback immediately on another goroutine.
	f.stopGroup = context.AfterFunc(groupContext, func() { _ = f.Close() })
	f.stopPath = context.AfterFunc(c.entry.path.ctx, func() { _ = f.Close() })
	p.mu.Unlock()
	return f, nil
}

func (s *privatePathSelector) Close() {
	p := s.pool
	p.mu.Lock()
	defer p.mu.Unlock()
	if s.closed {
		return
	}
	s.closed, s.proof = true, nil
	s.hint.clearLocked()
	s.cancelFlows()
	delete(p.selectors, s.group)
	if old := s.active; old != nil {
		s.active = nil
		old.activeHolds--
		old.closeRequested = true
		if old.activeHolds == 0 {
			p.drainLocked(old, 120_000)
		}
	}
}

// Per-group authorization wraps, but never replaces, the candidate's existing
// flow/adapter ownership. Each wrapper owns one of at most128 pool holds. Its
// two cancellation hooks are removed only by actual Close; a blocked closer
// keeps that reservation and does not prevent other flows' independent hooks.
type privateSelectedTCPFlow struct {
	net.Conn
	selector     *privatePathSelector
	epoch        uint64
	groupContext context.Context
	cancel       context.CancelFunc
	stopGroup    func() bool
	stopPath     func() bool
	once         sync.Once
	closed       atomic.Bool
	err          error
}

func (f *privateSelectedTCPFlow) valid() bool {
	p := f.selector.pool
	p.mu.Lock()
	defer p.mu.Unlock()
	return !f.closed.Load() && f.groupContext.Err() == nil && f.selector.validLocked() && f.selector.flowEpoch == f.epoch
}

func (f *privateSelectedTCPFlow) Close() error {
	f.once.Do(func() {
		f.closed.Store(true)
		p := f.selector.pool
		p.mu.Lock()
		stopGroup, stopPath := f.stopGroup, f.stopPath
		p.mu.Unlock()
		stopGroup()
		stopPath()
		f.cancel()
		f.err = f.Conn.Close()
	})
	return f.err
}

func (f *privateSelectedTCPFlow) Read(b []byte) (int, error) {
	if !f.valid() {
		return 0, errPrivatePath
	}
	n, err := f.Conn.Read(b)
	if !f.valid() {
		return 0, errPrivatePath
	}
	return n, err
}

func (f *privateSelectedTCPFlow) Write(b []byte) (int, error) {
	if !f.valid() {
		return 0, errPrivatePath
	}
	n, err := f.Conn.Write(b)
	if !f.valid() {
		return 0, errPrivatePath
	}
	return n, err
}

func (f *privateSelectedTCPFlow) NeedHandshake() bool { return N.NeedHandshakeForWrite(f.Conn) }
func (f *privateSelectedTCPFlow) String() string      { return "PrivateSelectedFlow([redacted])" }
func (f *privateSelectedTCPFlow) GoString() string    { return f.String() }

func (s *privatePathSelector) String() string     { return "PrivatePathSelector([redacted])" }
func (s *privatePathSelector) GoString() string   { return s.String() }
func (p *privateSelectionProof) String() string   { return "PrivateSelectionProof([redacted])" }
func (p *privateSelectionProof) GoString() string { return p.String() }
