package bridge

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"math"
	"net"
	"regexp"
	"sync"
	"sync/atomic"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

var privateGroupID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)

// Internal primitive only. The authorized catalogue, shared priority scheduler
// and signed capability gate must all be wired before exposing this to Runtime.
// All mutable fields are guarded by pool.mu; no I/O runs under that lock.
type privatePathSelector struct {
	pool                     *privatePathPool
	group, scope, checksHash string
	checks                   []routeCheck
	active                   *privatePoolEntry
	proof                    *privateSelectionProof
	flowEpoch                uint64
	flowContext              context.Context
	cancelFlows              context.CancelFunc
	closed                   bool
}

// A pointer minted only by successful real probes, consumed exactly once. A
// copied struct, score, caller supplied result or old context is not authority.
type privateSelectionProof struct {
	selector                 *privatePathSelector
	entry, previous          *privatePoolEntry
	scope, group, checksHash string
	started, completed       int64
	flowEpoch                uint64
}

func newPrivatePathSelector(p *privatePathPool, scope, group string, checks []routeCheck) (*privatePathSelector, error) {
	if p == nil || !privateGroupID.MatchString(group) || len(checks) < 1 || len(checks) > 4 {
		return nil, errPrivatePath
	}
	owned := append([]routeCheck(nil), checks...)
	for _, c := range owned {
		if !validRouteCheck(c) {
			return nil, errPrivatePath
		}
	}
	raw, err := json.Marshal(owned)
	if err != nil {
		return nil, errPrivatePath
	}
	digest := sha256.Sum256(raw)
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.ctx.Err() != nil || !privateManagedLease(p.lease) || scope != p.scope || len(p.selectors) >= privateGroupLimit || p.selectors[group] != nil {
		return nil, errPrivatePath
	}
	flowContext, cancelFlows := context.WithCancel(p.ctx)
	s := &privatePathSelector{pool: p, scope: scope, group: group, checks: owned, checksHash: hex.EncodeToString(digest[:]),
		flowEpoch: 1, flowContext: flowContext, cancelFlows: cancelFlows}
	p.selectors[group] = s
	return s, nil
}

func (s *privatePathSelector) validLocked() bool {
	p := s.pool
	return !s.closed && !p.closed && p.ctx.Err() == nil && privateManagedLease(p.lease) && p.scope == s.scope && p.selectors[s.group] == s
}

// Synchronous admission on an owned caller worker: one probe for the entire
// pool. A blocked adapter cannot create a replacement probe, even after scope
// replacement. Deadline/cancellation also gate the final proof publication.
func (s *privatePathSelector) probe(parent context.Context, candidate *privatePathCandidate) (proof *privateSelectionProof, err error) {
	return s.probeWithRoots(parent, candidate, nil)
}

// An internal fixture seam only. Runtime callers never supply custom roots.
func (s *privatePathSelector) probeWithRoots(parent context.Context, candidate *privatePathCandidate, roots *x509.CertPool) (proof *privateSelectionProof, err error) {
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
	ctx, cancel := context.WithTimeout(parent, 12*time.Second)
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
	for _, check := range s.checks {
		// A normal timer may not advance while suspended. Check the aggregate
		// BOOTTIME budget before every target, not only before publishing proof.
		now := p.lease.clock()
		if ctx.Err() != nil || now < started || now-started >= 12_000 {
			return nil, errPrivatePath
		}
		code, complete := probeRouteWithClock(ctx, func(ctx context.Context, network string, dst M.Socksaddr) (net.Conn, error) {
			return candidate.dialTCP(s.scope, ctx, network, dst)
		}, check, roots, p.lease.clock)
		if !complete || code != "ok" || ctx.Err() != nil {
			if complete && ctx.Err() == nil && (check.Method == "https_exit_country" && code == "exit_country_mismatch" ||
				check.Method == "https_exit_ip" && code == "exit_ip_mismatch") {
				p.mu.Lock()
				if _, fresh := s.freshProbeLocked(ctx, candidate.entry, previous, epoch, started); previous == candidate.entry && fresh {
					s.withdrawLocked()
				}
				p.mu.Unlock()
			}
			return nil, errPrivatePath
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	e := candidate.entry
	now, fresh := s.freshProbeLocked(ctx, e, previous, epoch, started)
	if !fresh {
		return nil, errPrivatePath
	}
	proof = &privateSelectionProof{selector: s, entry: e, previous: previous, scope: s.scope, group: s.group, checksHash: s.checksHash, started: started, completed: now, flowEpoch: epoch}
	s.proof = proof
	return proof, nil
}

// Called with pool.mu held. Neither a late observation nor a probe of a reserve
// can revoke the independently selected current candidate.
func (s *privatePathSelector) freshProbeLocked(ctx context.Context, e, previous *privatePoolEntry, epoch uint64, started int64) (int64, bool) {
	p := s.pool
	now := p.lease.clock()
	return now, s.validLocked() && ctx.Err() == nil && s.active == previous && s.flowEpoch == epoch &&
		now >= started && now-started < 12_000 && e.scope == s.scope && p.entries[e.id] == e &&
		!e.draining && !e.queued && !e.retained && !e.closed && e.path.ctx.Err() == nil
}

func (s *privatePathSelector) withdrawLocked() {
	p := s.pool
	s.proof = nil
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
	if !s.validLocked() || s.proof != proof || proof.selector != s || proof.scope != s.scope || proof.group != s.group || proof.checksHash != s.checksHash || proof.previous != s.active || proof.flowEpoch != s.flowEpoch || now < proof.completed || proof.completed < proof.started || now-proof.started > 15_000 {
		return false
	}
	s.proof = nil
	e := proof.entry
	if e == nil || p.entries[e.id] != e || e.scope != s.scope || e.draining || e.queued || e.retained || e.closed || e.path == nil || e.path.ctx.Err() != nil {
		return false
	}
	old := s.active
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
	epoch, groupContext := s.flowEpoch, s.flowContext
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
