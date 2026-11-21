package bridge

import (
	"context"
	"math"
	"regexp"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/service"
)

var privateScopeID = regexp.MustCompile(`^[0-9a-f]{64}$`)

const privateCandidateLimit = 32 // sixteen active groups plus bounded draining/probing owners
const privateGroupLimit = 16

// Construction/retirement ownership only. This does not grant probe admission,
// selection authority or a public outbound. One instance belongs to one native
// runtime, and its configured adapter count is reserved for that lifetime.
// The resolver is an independently authorized immutable catalogue snapshot.
type privatePathPool struct {
	mu              sync.Mutex
	ctx             context.Context
	cancel          context.CancelFunc
	stopParent      func() bool
	lease           *leaseGuard
	homeUntilBootMS atomic.Int64 // 0 ordinary network; -1 home scope awaiting proof
	scope           string
	configured      int
	capacity        int
	used            int
	holds           int
	operations      int
	probing         bool
	selectors       map[string]*privatePathSelector
	building        bool
	closed          bool
	queueClosed     bool
	next            uint64
	entries         map[uint64]*privatePoolEntry
	retire          chan *privatePoolEntry
	workerExited    chan struct{}
}

type privatePoolEntry struct {
	id             uint64
	scope          string
	cost           int
	path           *privatePath
	cancel         context.CancelFunc
	holds          int
	activeHolds    int
	closeRequested bool
	drainDeadline  int64
	drainTimer     *time.Timer
	draining       bool
	queued         bool
	retained       bool
	closed         bool
	flows          map[*privateFlowOwner]struct{}
}

type privatePathCandidate struct {
	pool  *privatePathPool
	entry *privatePoolEntry
}

type privatePathHold struct {
	pool   *privatePathPool
	entry  *privatePoolEntry
	once   sync.Once
	closed atomic.Bool
}

type privatePoolSnapshot struct {
	Configured, Dynamic, Entries, Holds, Retained, Operations int
	Building, Closed                                          bool
}

func newPrivatePathPool(parent context.Context, scope string, capacity int, lease *leaseGuard) (*privatePathPool, error) {
	if parent == nil || parent.Err() != nil || !privateScopeID.MatchString(scope) || capacity < 1 || capacity > 128 || !privateManagedLease(lease) {
		return nil, errPrivatePath
	}
	manager := service.FromContext[adapter.OutboundManager](parent)
	if manager == nil {
		return nil, errPrivatePath
	}
	configured := len(manager.Outbounds())
	if configured < 1 || configured > capacity {
		return nil, errPrivatePath
	}
	ctx, cancel := context.WithCancel(parent)
	p := &privatePathPool{ctx: ctx, cancel: cancel, lease: lease, scope: scope, configured: configured, capacity: capacity,
		entries: map[uint64]*privatePoolEntry{}, selectors: map[string]*privatePathSelector{}, retire: make(chan *privatePoolEntry, privateCandidateLimit), workerExited: make(chan struct{})}
	go p.retirementWorker()
	stop := context.AfterFunc(parent, p.Close)
	p.mu.Lock()
	if p.closed {
		stop()
	} else {
		p.stopParent = stop
	}
	p.mu.Unlock()
	return p, nil
}

// Called before and after flow I/O as well as while admitting a new route.
// Reading the deadline requires no hub lock while an individual flow owns the pool.
func (p *privatePathPool) homeCurrent() bool {
	deadline := p.homeUntilBootMS.Load()
	if deadline == 0 {
		return true
	}
	now := p.lease.clock()
	return deadline > 0 && now >= 0 && now < deadline && deadline-now <= 180_000
}

func (p *privatePathPool) snapshot() privatePoolSnapshot {
	p.mu.Lock()
	defer p.mu.Unlock()
	s := privatePoolSnapshot{Configured: p.configured, Dynamic: p.used, Entries: len(p.entries), Holds: p.holds, Operations: p.operations, Building: p.building, Closed: p.closed}
	for _, e := range p.entries {
		if e.retained {
			s.Retained++
		}
	}
	return s
}

// No replacement constructor is admitted while one is blocked, even across a
// context change. Adapter reservations include in-flight and failed cleanup.
// The caller runs construction on its owned bounded worker, never a heartbeat.
func (p *privatePathPool) prepare(scope string, hops []string, create func(context.Context, string, string, string) (adapter.Outbound, error)) (*privatePathCandidate, error) {
	return p.prepareWithContext(context.Background(), scope, hops, create)
}

func (p *privatePathPool) prepareWithContext(work context.Context, scope string, hops []string, create func(context.Context, string, string, string) (adapter.Outbound, error)) (*privatePathCandidate, error) {
	if !privateAdaptiveWorkCurrent(work, p.lease.clock) || len(hops) < 1 || len(hops) > 4 || create == nil {
		return nil, errPrivatePath
	}
	ownedHops := append([]string(nil), hops...)
	p.mu.Lock()
	if p.closed || p.ctx.Err() != nil || !privateManagedLease(p.lease) || scope != p.scope || p.building || len(p.entries) >= privateCandidateLimit || p.configured+p.used+len(ownedHops) > p.capacity || p.next == ^uint64(0) {
		p.mu.Unlock()
		return nil, errPrivatePath
	}
	duration := 30 * time.Second
	if deadline, ok := work.Deadline(); ok {
		if remaining := time.Until(deadline); remaining < duration {
			duration = remaining
		}
	}
	started := p.lease.clock()
	if duration < time.Millisecond || started < 0 || started > math.MaxInt64-30_000 {
		p.mu.Unlock()
		return nil, errPrivatePath
	}
	deadlineBoot := started + duration.Milliseconds()
	if aggregate, ok := work.Value(privateAdaptiveWorkDeadlineKey{}).(int64); ok && aggregate < deadlineBoot {
		deadlineBoot = aggregate
	}
	if deadlineBoot <= started {
		p.mu.Unlock()
		return nil, errPrivatePath
	}
	p.next++
	child, cancel := context.WithCancel(p.ctx)
	e := &privatePoolEntry{id: p.next, scope: scope, cost: len(ownedHops), cancel: cancel, flows: map[*privateFlowOwner]struct{}{}}
	p.entries[e.id] = e
	p.used += e.cost
	p.building = true
	p.mu.Unlock()
	remaining := deadlineBoot - p.lease.clock()
	if remaining < 0 {
		remaining = 0
	}
	budget, cancelBudget := context.WithTimeout(work, time.Duration(remaining)*time.Millisecond)
	stopBudget := context.AfterFunc(budget, cancel)
	published := false
	defer func() {
		stopBudget()
		cancelBudget()
		if !published {
			cancel()
		}
	}()
	withinBudget := func() bool {
		now := p.lease.clock()
		return budget.Err() == nil && privateAdaptiveWorkCurrent(work, p.lease.clock) && child.Err() == nil && now >= started && now < deadlineBoot && privateManagedLease(p.lease)
	}
	if !withinBudget() {
		cancel()
	}
	path, retained, err := buildPrivatePathBudgeted(child, ownedHops, func(ctx context.Context, id, tag, previous string) (adapter.Outbound, error) {
		if !withinBudget() {
			cancel()
			return nil, errPrivatePath
		}
		node, err := create(ctx, id, tag, previous)
		if !withinBudget() {
			cancel()
			return node, errPrivatePath
		}
		return node, err
	}, withinBudget)
	unlinked := stopBudget()
	expired := budget.Err() != nil
	cancelBudget()
	p.mu.Lock()
	defer p.mu.Unlock()
	p.building = false
	if retained != nil {
		e.path, e.retained, e.draining = retained, true, true
		e.cancel()
	} else if path == nil {
		e.cancel()
		delete(p.entries, e.id)
		p.used -= e.cost
	} else {
		e.path = path
		finished := p.lease.clock()
		if !unlinked || expired || work.Err() != nil || finished < started || finished >= deadlineBoot || p.closed || p.ctx.Err() != nil || !privateManagedLease(p.lease) || e.scope != p.scope || e.draining {
			p.enqueueLocked(e)
		} else {
			published = true
			return &privatePathCandidate{pool: p, entry: e}, nil
		}
	}
	p.finishQueueLocked()
	if err == nil {
		err = errPrivatePath
	}
	return nil, err
}

func (p *privatePathPool) finishQueueLocked() {
	if p.closed && !p.building && !p.queueClosed {
		p.queueClosed = true
		close(p.retire)
	}
}

func (p *privatePathPool) enqueueLocked(e *privatePoolEntry) {
	e.draining = true
	if e.drainTimer != nil {
		e.drainTimer.Stop()
		e.drainTimer = nil
	}
	if e.path != nil && !e.queued && !e.retained {
		e.queued = true
		e.cancel()
		// At most thirty-two entries, one queue record each. A blocked closer cannot
		// consume a replacement worker or free its adapter reservation.
		p.retire <- e
	}
}

func (p *privatePathPool) retirementWorker() {
	defer close(p.workerExited)
	for e := range p.retire {
		p.mu.Lock()
		flows := make([]*privateFlowOwner, 0, len(e.flows))
		for f := range e.flows {
			flows = append(flows, f)
		}
		p.mu.Unlock()
		for _, f := range flows {
			_ = f.Close()
		}
		err := e.path.Close()
		p.mu.Lock()
		if err != nil {
			e.retained = true
		} else {
			e.closed = true
			// A late/blocked dial still owns a hold, even if adapter.Close
			// returned. Never lend that reservation to a replacement.
			if e.holds == 0 && !e.retained {
				p.releaseEntryLocked(e)
			}
		}
		p.mu.Unlock()
	}
}

// Replace the full locally computed context binding, never an individual epoch.
// Stale construction cannot publish into the replacement context. Retired or
// blocked owners retain their reservation; this creates no replacement worker.
func (p *privatePathPool) changeScope(scope string) bool {
	if !privateScopeID.MatchString(scope) {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.ctx.Err() != nil || scope == p.scope {
		return false
	}
	p.scope = scope
	for _, e := range p.entries {
		e.cancel()
		p.enqueueLocked(e)
	}
	return true
}

func (c *privatePathCandidate) hold(scope string) (*privatePathHold, error) {
	p := c.pool
	p.mu.Lock()
	defer p.mu.Unlock()
	return c.holdLocked(scope)
}

func (c *privatePathCandidate) holdLocked(scope string) (*privatePathHold, error) {
	p, e := c.pool, c.entry
	p.expireDrainsLocked()
	if p.closed || p.ctx.Err() != nil || !privateManagedLease(p.lease) || scope != p.scope || e.scope != scope || p.entries[e.id] != e || e.draining || e.queued || e.retained || e.closed || e.path == nil || e.path.ctx.Err() != nil || p.holds >= 128 {
		return nil, errPrivatePath
	}
	e.holds++
	p.holds++
	return &privatePathHold{pool: p, entry: e}, nil
}

// Internal borrowed handle only: a holder must retain it for the entire probe
// or flow lifetime. Runtime integration must wrap actual traffic handles and
// enforce authorization/lease/proof checks before exposing a data path.
func (h *privatePathHold) outbound(scope string) (adapter.Outbound, error) {
	p := h.pool
	p.mu.Lock()
	defer p.mu.Unlock()
	p.expireDrainsLocked()
	e := h.entry
	if h.closed.Load() || p.closed || p.ctx.Err() != nil || !privateManagedLease(p.lease) || scope != p.scope || e.scope != scope || p.entries[e.id] != e || e.queued || e.path.ctx.Err() != nil {
		return nil, errPrivatePath
	}
	nodes := e.path.registry.Outbounds()
	if len(nodes) == 0 {
		return nil, errPrivatePath
	}
	return nodes[len(nodes)-1], nil
}

func (h *privatePathHold) Close() error {
	h.once.Do(func() {
		h.closed.Store(true)
		p := h.pool
		p.mu.Lock()
		defer p.mu.Unlock()
		e := h.entry
		if e.holds > 0 {
			e.holds--
			p.holds--
		}
		if e.holds == 0 && e.closed && !e.retained {
			p.releaseEntryLocked(e)
		} else if e.holds == 0 && e.draining && p.entries[e.id] == e && !p.queueClosed {
			p.enqueueLocked(e)
		}
	})
	return nil
}

func privateManagedLease(g *leaseGuard) bool {
	if g == nil || g.clock == nil {
		return false
	}
	s := g.state.Load()
	return s != nil && s.deadline > 0 && g.allowed()
}

func (p *privatePathPool) releaseEntryLocked(e *privatePoolEntry) {
	if p.entries[e.id] == e {
		delete(p.entries, e.id)
		p.used -= e.cost
	}
}

func (p *privatePathPool) String() string        { return "PrivatePathPool([redacted])" }
func (p *privatePathPool) GoString() string      { return p.String() }
func (c *privatePathCandidate) String() string   { return "PrivatePathCandidate([redacted])" }
func (c *privatePathCandidate) GoString() string { return c.String() }
func (h *privatePathHold) String() string        { return "PrivatePathHold([redacted])" }
func (h *privatePathHold) GoString() string      { return h.String() }

// Graceful retirement rejects new holds while existing holders finish. Stop or
// a changed security context instead cancels and retires all owned adapters.
func (c *privatePathCandidate) Close() error {
	p := c.pool
	p.mu.Lock()
	defer p.mu.Unlock()
	e := c.entry
	if p.entries[e.id] == e && !p.queueClosed {
		e.closeRequested = true
		if e.activeHolds == 0 {
			p.drainLocked(e, 120_000)
		}
	}
	return nil
}

// One finite timer per resident entry. BOOTTIME is checked at every operation
// too: a suspended scheduler must never extend a drain lease after wake-up.
func (p *privatePathPool) drainLocked(e *privatePoolEntry, graceMS int64) {
	if e.draining || e.queued || e.closed || p.queueClosed {
		return
	}
	e.draining = true
	now := p.lease.clock()
	if !privateManagedLease(p.lease) || now < 0 || now > math.MaxInt64-graceMS {
		p.enqueueLocked(e)
		return
	}
	e.drainDeadline = now + graceMS
	if e.holds == 0 {
		p.enqueueLocked(e)
		return
	}
	e.drainTimer = time.AfterFunc(time.Duration(graceMS)*time.Millisecond, func() {
		p.mu.Lock()
		defer p.mu.Unlock()
		if p.entries[e.id] != e || e.queued || p.queueClosed {
			return
		}
		// The platform clock is authoritative even if a timer wakes early.
		if remaining := e.drainDeadline - p.lease.clock(); remaining > 0 {
			e.drainTimer.Reset(time.Duration(remaining) * time.Millisecond)
			return
		}
		p.enqueueLocked(e)
	})
}

func (p *privatePathPool) expireDrainsLocked() {
	for _, e := range p.entries {
		if e.draining && e.drainDeadline > 0 && !e.queued && !p.queueClosed && p.lease.clock() >= e.drainDeadline {
			p.enqueueLocked(e)
		}
	}
}

func (p *privatePathPool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return
	}
	p.closed = true
	if p.stopParent != nil {
		p.stopParent()
		p.stopParent = nil
	}
	p.cancel()
	for _, e := range p.entries {
		e.cancel()
		p.enqueueLocked(e)
	}
	p.finishQueueLocked()
}
