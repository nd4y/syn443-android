package bridge

import (
	"context"
	"regexp"
	"sync"
	"sync/atomic"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/service"
)

var privateScopeID = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Construction/retirement ownership only. This does not grant probe admission,
// selection authority or a public outbound. One instance belongs to one native
// runtime, and its configured adapter count is reserved for that lifetime.
// The resolver is an independently authorized immutable catalogue snapshot.
type privatePathPool struct {
	mu           sync.Mutex
	ctx          context.Context
	cancel       context.CancelFunc
	stopParent   func() bool
	lease        *leaseGuard
	scope        string
	configured   int
	capacity     int
	used         int
	holds        int
	operations   int
	building     bool
	closed       bool
	queueClosed  bool
	next         uint64
	entries      map[uint64]*privatePoolEntry
	retire       chan *privatePoolEntry
	workerExited chan struct{}
}

type privatePoolEntry struct {
	id       uint64
	scope    string
	cost     int
	path     *privatePath
	cancel   context.CancelFunc
	holds    int
	draining bool
	queued   bool
	retained bool
	closed   bool
	flows    map[*privateFlowOwner]struct{}
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
		entries: map[uint64]*privatePoolEntry{}, retire: make(chan *privatePoolEntry, 8), workerExited: make(chan struct{})}
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
	if len(hops) < 1 || len(hops) > 4 || create == nil {
		return nil, errPrivatePath
	}
	ownedHops := append([]string(nil), hops...)
	p.mu.Lock()
	if p.closed || p.ctx.Err() != nil || !privateManagedLease(p.lease) || scope != p.scope || p.building || len(p.entries) >= 8 || p.configured+p.used+len(ownedHops) > p.capacity || p.next == ^uint64(0) {
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
	path, retained, err := buildPrivatePath(child, ownedHops, create)
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
		if p.closed || p.ctx.Err() != nil || !privateManagedLease(p.lease) || e.scope != p.scope || e.draining {
			p.enqueueLocked(e)
		} else {
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
	if e.path != nil && !e.queued && !e.retained {
		e.queued = true
		e.cancel()
		// At most eight entries, one queue record each. A blocked closer cannot
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
	e := c.entry
	if p.closed || p.ctx.Err() != nil || !privateManagedLease(p.lease) || scope != p.scope || e.scope != scope || p.entries[e.id] != e || e.draining || e.path == nil || p.holds >= 128 {
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
		e.draining = true
		if e.holds == 0 {
			p.enqueueLocked(e)
		}
	}
	return nil
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
