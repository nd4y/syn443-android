package bridge

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"net"
	"regexp"
	"time"

	M "github.com/sagernet/sing/common/metadata"
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
	closed                   bool
}

// A pointer minted only by successful real probes, consumed exactly once. A
// copied struct, score, caller supplied result or old context is not authority.
type privateSelectionProof struct {
	selector                 *privatePathSelector
	entry, previous          *privatePoolEntry
	scope, group, checksHash string
	started, completed       int64
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
	if p.closed || p.ctx.Err() != nil || !privateManagedLease(p.lease) || scope != p.scope || len(p.selectors) >= 8 || p.selectors[group] != nil {
		return nil, errPrivatePath
	}
	s := &privatePathSelector{pool: p, scope: scope, group: group, checks: owned, checksHash: hex.EncodeToString(digest[:])}
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
	started, previous := p.lease.clock(), s.active
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
		code, complete := probeRouteWithClock(ctx, func(ctx context.Context, network string, dst M.Socksaddr) (net.Conn, error) {
			return candidate.dialTCP(s.scope, ctx, network, dst)
		}, check, nil, p.lease.clock)
		if !complete || code != "ok" || ctx.Err() != nil {
			return nil, errPrivatePath
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.lease.clock()
	e := candidate.entry
	if !s.validLocked() || ctx.Err() != nil || s.active != previous || now < started || now-started > 12_000 || e.scope != s.scope || p.entries[e.id] != e || e.draining || e.queued || e.retained || e.path.ctx.Err() != nil {
		return nil, errPrivatePath
	}
	proof = &privateSelectionProof{selector: s, entry: e, previous: previous, scope: s.scope, group: s.group, checksHash: s.checksHash, started: started, completed: now}
	s.proof = proof
	return proof, nil
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
	if !s.validLocked() || s.proof != proof || proof.selector != s || proof.scope != s.scope || proof.group != s.group || proof.checksHash != s.checksHash || proof.previous != s.active || now < proof.completed || proof.completed < proof.started || now-proof.started > 15_000 {
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
	p := s.pool
	p.mu.Lock()
	if !s.validLocked() || s.active == nil {
		p.mu.Unlock()
		return nil, errPrivatePath
	}
	c := &privatePathCandidate{pool: p, entry: s.active}
	h, err := c.holdLocked(s.scope)
	p.mu.Unlock()
	if err != nil {
		return nil, errPrivatePath
	}
	return h.dialTCP(s.scope, parent, network, destination)
}

func (s *privatePathSelector) Close() {
	p := s.pool
	p.mu.Lock()
	defer p.mu.Unlock()
	if s.closed {
		return
	}
	s.closed, s.proof = true, nil
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

func (s *privatePathSelector) String() string     { return "PrivatePathSelector([redacted])" }
func (s *privatePathSelector) GoString() string   { return s.String() }
func (p *privateSelectionProof) String() string   { return "PrivateSelectionProof([redacted])" }
func (p *privateSelectionProof) GoString() string { return p.String() }
