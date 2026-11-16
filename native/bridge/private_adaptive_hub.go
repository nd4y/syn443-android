package bridge

import (
	"context"
	"net"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
	"io.syn443/routegraph"
)

// Runtime-owned TCP primitive, not a public policy/Java entry point. A graph is
// declaration evidence only. The catalogue, lease, context and actual native
// check receipt must all agree before a group gains data-path authority.
type privateAdaptiveHub struct {
	mu           sync.Mutex // hub -> pool is the only nested lock order; no I/O under mu
	graph        *routegraph.Graph
	catalogue    *privatePathCatalogue
	create       func(context.Context, string, string, string) (adapter.Outbound, error) // compiled owner callback, never wire data
	pool         *privatePathPool
	checks       map[string][]routeCheck
	groups       map[string]*privatePathSelector
	cache        map[string]*privatePathCandidate
	scope, mode  string
	busy, closed bool
	cancel       context.CancelFunc
	receipt      *privateAdaptiveReceipt
}

type privateAdaptiveReceipt struct {
	hub                *privateAdaptiveHub
	proof              *privateSelectionProof
	scope, mode, group string
}

func newPrivateAdaptiveHub(c *privatePathCatalogue, metadata []byte, plans map[string][]routeCheck, scope, mode string, capacity int, lease *leaseGuard) (*privateAdaptiveHub, error) {
	if c == nil || !privateScopeID.MatchString(scope) || !privateAdaptiveMode(mode) {
		return nil, errPrivatePath
	}
	ids := make([]string, 0, len(c.profiles))
	for id := range c.profiles {
		ids = append(ids, id)
	}
	g, err := routegraph.Decode(append([]byte(nil), metadata...), ids)
	if err != nil || len(plans) != len(g.GroupIDs()) {
		return nil, errPrivatePath
	}
	owned := make(map[string][]routeCheck, len(plans))
	for _, id := range g.GroupIDs() {
		info, _ := g.GroupInfo(id)
		// Explicit TCP-only integration. Never silently discard requested UDP
		// or ICMP and then claim the graph was implemented.
		if !slices.Contains(info.Features, "TCP") || slices.Contains(info.Features, "UDP") || slices.Contains(info.Features, "ICMP") {
			return nil, errPrivatePath
		}
		checks := append([]routeCheck(nil), plans[id]...)
		if len(checks) < 1 || len(checks) > 4 {
			return nil, errPrivatePath
		}
		country := false
		for _, check := range checks {
			if !validRouteCheck(check) {
				return nil, errPrivatePath
			}
			if check.Method == "https_exit_country" {
				if info.Intent == "INTERNAL" || check.ExpectedExitClass != info.Intent {
					return nil, errPrivatePath
				}
				country = true
			}
		}
		if info.Intent != "INTERNAL" && !country {
			return nil, errPrivatePath
		}
		owned[id] = checks
	}
	p, err := newPrivatePathPool(c.ctx, scope, capacity, lease)
	if err != nil {
		return nil, errPrivatePath
	}
	h := &privateAdaptiveHub{graph: g, catalogue: c, create: c.create, pool: p, checks: owned, scope: scope, mode: mode, cache: map[string]*privatePathCandidate{}}
	if !h.makeGroupsLocked() {
		p.Close()
		return nil, errPrivatePath
	}
	return h, nil
}

func privateAdaptiveMode(mode string) bool {
	return mode == "HOME_WIFI" || mode == "WIFI" || mode == "CELLULAR" || mode == "CELLULAR_RESTRICTED"
}

func (h *privateAdaptiveHub) makeGroupsLocked() bool {
	h.groups = make(map[string]*privatePathSelector, len(h.checks))
	for _, id := range h.graph.GroupIDs() {
		s, err := newPrivatePathSelector(h.pool, h.scope, id, h.checks[id])
		if err != nil {
			return false
		}
		h.groups[id] = s
	}
	return true
}

// Synchronous on one owned caller worker. Cancelling work withdraws publication
// immediately but busy is not released until construction/probes actually exit.
// One global receipt is enough: policy ranking consumes it before exploring the
// next candidate. Successful checks do not switch a healthy current route.
func (h *privateAdaptiveHub) prepareProbe(work context.Context, group string, path []string) (receipt *privateAdaptiveReceipt, err error) {
	if work == nil || work.Err() != nil {
		return nil, errPrivatePath
	}
	path = append([]string(nil), path...)
	h.mu.Lock()
	if h.closed || h.busy || h.receipt != nil || !h.graph.Allows(group, h.mode, path) {
		h.mu.Unlock()
		return nil, errPrivatePath
	}
	scope, mode, selector := h.scope, h.mode, h.groups[group]
	if selector == nil {
		h.mu.Unlock()
		return nil, errPrivatePath
	}
	candidate, admitted := h.candidateLocked(path)
	if !admitted {
		h.mu.Unlock()
		return nil, errPrivatePath
	}
	ctx, cancel := context.WithTimeout(work, 30*time.Second)
	h.cancel, h.busy, h.receipt = cancel, true, nil
	key := strings.Join(path, "/")
	h.mu.Unlock()
	defer func() {
		cancel()
		h.mu.Lock()
		h.busy, h.cancel = false, nil
		h.mu.Unlock()
		if recover() != nil {
			receipt, err = nil, errPrivatePath
		}
	}()
	if candidate == nil {
		candidate, err = h.pool.prepareWithContext(ctx, scope, path, h.create)
		if err != nil {
			return nil, errPrivatePath
		}
		h.mu.Lock()
		if h.closed || h.scope != scope || h.mode != mode || ctx.Err() != nil {
			h.mu.Unlock()
			_ = candidate.Close()
			return nil, errPrivatePath
		}
		// Purge only actually retired entries. An eviction request alone is
		// not proof that adapters/sockets have relinquished their resources.
		h.pool.mu.Lock()
		for k, c := range h.cache {
			if h.pool.entries[c.entry.id] != c.entry {
				delete(h.cache, k)
			}
		}
		h.pool.mu.Unlock()
		if len(h.cache) >= privateCandidateLimit {
			h.mu.Unlock()
			_ = candidate.Close()
			return nil, errPrivatePath
		}
		h.cache[key] = candidate
		h.mu.Unlock()
	}
	proof, err := selector.probe(ctx, candidate)
	if err != nil {
		return nil, errPrivatePath
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed || h.scope != scope || h.mode != mode || ctx.Err() != nil || h.groups[group] != selector {
		return nil, errPrivatePath
	}
	receipt = &privateAdaptiveReceipt{hub: h, proof: proof, scope: scope, mode: mode, group: group}
	h.receipt = receipt
	return receipt, nil
}

// Called under hub.mu. An old cached handle is not reusable after retirement.
// At pressure, retire at most one unselected idle owner and defer this request;
// its capacity remains occupied until the retirement worker actually releases
// it. A pending receipt, selected path or blocked close cannot be evicted into
// apparent spare capacity. The caller's bounded scheduler decides when to retry.
func (h *privateAdaptiveHub) candidateLocked(path []string) (*privatePathCandidate, bool) {
	p := h.pool
	p.mu.Lock()
	defer p.mu.Unlock()
	for key, candidate := range h.cache {
		if p.entries[candidate.entry.id] != candidate.entry {
			delete(h.cache, key)
		}
	}
	if candidate := h.cache[strings.Join(path, "/")]; candidate != nil {
		return candidate, true
	}
	if !p.closed && !p.building && len(p.entries) < privateCandidateLimit && p.configured+p.used+len(path) <= p.capacity {
		return nil, true
	}
	// One existing retirement already owns the single worker. Do not enqueue
	// an unbounded series of evictions while that closer is blocked.
	for _, entry := range p.entries {
		if entry.queued && !entry.closed {
			return nil, false
		}
	}
	keys := make([]string, 0, len(h.cache))
	for key := range h.cache {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	for _, key := range keys {
		entry := h.cache[key].entry
		if entry.activeHolds == 0 && entry.holds == 0 && !entry.draining && !entry.queued && !entry.retained && !entry.closed && (h.receipt == nil || h.receipt.proof.entry != entry) {
			entry.closeRequested = true
			p.enqueueLocked(entry)
			break
		}
	}
	return nil, false
}

// Explicitly abandon an uncommitted proof before exploring another candidate.
// Discarding is not selection and grants no data-path authority.
func (h *privateAdaptiveHub) discard(r *privateAdaptiveReceipt) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed || h.busy || r == nil || h.receipt != r || r.hub != h || r.scope != h.scope || r.mode != h.mode {
		return false
	}
	h.receipt = nil
	h.pool.mu.Lock()
	if selector := h.groups[r.group]; selector != nil && selector.proof == r.proof {
		selector.proof = nil
	}
	h.pool.mu.Unlock()
	return true
}

func (h *privateAdaptiveHub) commit(r *privateAdaptiveReceipt, graceMS int64) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed || h.busy || r == nil || h.receipt != r || r.hub != h || r.scope != h.scope || r.mode != h.mode {
		return false
	}
	h.receipt = nil // One attempt, even if the native proof expired.
	s := h.groups[r.group]
	return s != nil && s.selectVerified(r.proof, graceMS)
}

func (h *privateAdaptiveHub) dialTCP(group string, parent context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	h.mu.Lock()
	s := h.groups[group]
	closed := h.closed
	h.mu.Unlock()
	if closed || s == nil {
		return nil, errPrivatePath
	}
	return s.dialTCP(parent, network, destination)
}

// scope is the full locally computed authority binding. It is never a mode
// label supplied remotely. A mode change without a fresh scope is rejected.
func (h *privateAdaptiveHub) changeScope(scope, mode string) bool {
	if !privateScopeID.MatchString(scope) || !privateAdaptiveMode(mode) {
		return false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed || scope == h.scope {
		return false
	}
	if h.cancel != nil {
		h.cancel()
	}
	if !h.pool.changeScope(scope) {
		return false
	}
	for _, s := range h.groups {
		s.Close()
	}
	h.scope, h.mode, h.receipt = scope, mode, nil
	h.cache = map[string]*privatePathCandidate{}
	if !h.makeGroupsLocked() {
		h.closed = true
		h.pool.Close()
		return false
	}
	return true
}

func (h *privateAdaptiveHub) Close() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return
	}
	h.closed, h.receipt = true, nil
	if h.cancel != nil {
		h.cancel()
	}
	for _, s := range h.groups {
		s.Close()
	}
	h.pool.Close()
}

// Only actual owner retirement is confirmation. A constructor panic, blocked
// close, socket operation or live worker cannot be hidden by a box.Close ack.
// A false result requires process-owner retirement before replacement/reuse.
func (h *privateAdaptiveHub) stopped() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.closed || h.busy {
		return false
	}
	h.pool.mu.Lock()
	defer h.pool.mu.Unlock()
	if h.pool.building || h.pool.probing || h.pool.used != 0 || len(h.pool.entries) != 0 || h.pool.holds != 0 || h.pool.operations != 0 {
		return false
	}
	select {
	case <-h.pool.workerExited:
		return true
	default:
		return false
	}
}

func (*privateAdaptiveHub) String() string         { return "PrivateAdaptiveHub([redacted])" }
func (h *privateAdaptiveHub) GoString() string     { return h.String() }
func (*privateAdaptiveReceipt) String() string     { return "PrivateAdaptiveReceipt([redacted])" }
func (r *privateAdaptiveReceipt) GoString() string { return r.String() }
