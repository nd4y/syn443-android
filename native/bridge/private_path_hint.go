package bridge

import (
	"context"
	"net"
	"os"
	"sort"
	"syscall"
)

const privateHintIntegerLimit uint64 = 9_007_199_254_740_991
const privateHintWindowMS int64 = 30_000

// A request for a new independently admitted check, never a path failure,
// readiness result or selection receipt. Only these five redacted fields cross
// the existing owner heartbeat. No endpoint, source error or traffic is kept.
type privatePathRecheckHint struct {
	Group           string `json:"group"`
	SelectionToken  uint64 `json:"selectionToken"`
	Sequence        uint64 `json:"sequence"`
	CompletedBootMS int64  `json:"completedBootMs"`
	Code            string `json:"code"`
}

func (privatePathRecheckHint) String() string     { return "PrivatePathRecheckHint([redacted])" }
func (h privatePathRecheckHint) GoString() string { return h.String() }

// One embedded slot per selector, therefore at most16. All access uses pool.mu.
// A fresh verified commit starts a new token, even for the same active entry.
// Neither overflow nor a clock rollback may wrap/reuse an old hint identity.
type privatePathHintSlot struct {
	token, sequence uint64
	lastBootMS      int64
	failures        [3]int64
	count           int
	emitted         bool
	disabled        bool
	pending         privatePathRecheckHint
}

func (h *privatePathHintSlot) clearLocked() {
	h.failures, h.count, h.emitted, h.pending = [3]int64{}, 0, false, privatePathRecheckHint{}
}

func (h *privatePathHintSlot) clockLocked(now int64) bool {
	if h.disabled {
		return false
	}
	if now <= 0 || now < h.lastBootMS {
		h.disabled = true
		h.clearLocked()
		return false
	}
	h.lastBootMS = now
	return true
}

func (h *privatePathHintSlot) selectedLocked(now int64) uint64 {
	if !h.clockLocked(now) || h.token >= privateHintIntegerLimit || h.sequence >= privateHintIntegerLimit {
		h.disabled = true
		h.clearLocked()
		return 0
	}
	h.token++
	h.clearLocked()
	return h.token
}

// Captured before exposing the selected stream. This lifetime context is the
// selector's parent-derived stream context, not the inner30s dial context.
// counted suppresses Read/Write/repeated-error duplicates on the same flow.
type privatePathHintFlow struct {
	selector *privatePathSelector
	entry    *privatePoolEntry
	token    uint64
	lifetime context.Context
	counted  bool
}

// Intentionally omit dial failures: a failed construction/dial has no completed
// admitted stream operation to attribute here. Unknown wrappers, timeouts,
// caller deadlines, EOF, local cancellation and local quota errors are ignored.
// Concrete bounded unwrapping never invokes arbitrary Error/Unwrap methods.
func privateHintNetworkError(err error) bool {
	for depth := 0; depth < 4 && err != nil; depth++ {
		switch e := err.(type) {
		case *net.OpError:
			if e == nil || e.Op != "read" && e.Op != "write" {
				return false
			}
			err = e.Err
		case *os.SyscallError:
			if e == nil {
				return false
			}
			err = e.Err
		case syscall.Errno:
			switch e {
			case syscall.ECONNRESET, syscall.ECONNABORTED, syscall.EPIPE, syscall.ENETRESET,
				syscall.ENETDOWN, syscall.ENETUNREACH, syscall.EHOSTUNREACH:
				return true
			}
			return false
		default:
			return false
		}
	}
	return false
}

func (f *privatePathHintFlow) observeLocked(p *privatePathPool, entry *privatePoolEntry, err error, panicked bool) {
	s := f.selector
	if s == nil || f.counted || panicked || !privateHintNetworkError(err) || f.lifetime == nil || f.lifetime.Err() != nil ||
		s.pool != p || f.entry != entry || !s.validLocked() || s.active != entry || s.hint.token == 0 || s.hint.token != f.token {
		return
	}
	now := p.lease.clock()
	if !s.hint.clockLocked(now) {
		return
	}
	f.counted = true
	h := &s.hint
	if h.emitted {
		return
	}
	retained := 0
	for i := 0; i < h.count; i++ {
		if now-h.failures[i] <= privateHintWindowMS {
			h.failures[retained] = h.failures[i]
			retained++
		}
	}
	h.count = retained
	h.failures[h.count] = now
	h.count++
	if h.count == len(h.failures) {
		if h.sequence >= privateHintIntegerLimit {
			h.disabled = true
			h.clearLocked()
			return
		}
		h.sequence++
		h.emitted = true
		h.pending = privatePathRecheckHint{s.group, h.token, h.sequence, now, "traffic_network_failure"}
	}
}

// Caller already owns pool.mu inside the existing heartbeat lock order. Reads
// never consume or refresh a hint; clock/staleness can only retire metadata.
func (p *privatePathPool) recheckHintsLocked(now int64) []privatePathRecheckHint {
	result := make([]privatePathRecheckHint, 0, privateGroupLimit)
	if len(p.selectors) > privateGroupLimit {
		return result
	}
	for _, s := range p.selectors {
		h := &s.hint
		if !s.validLocked() || s.active == nil || !h.clockLocked(now) || h.pending.Sequence == 0 {
			continue
		}
		if h.pending.SelectionToken != h.token || now-h.pending.CompletedBootMS > privateHintWindowMS {
			h.pending = privatePathRecheckHint{}
			continue
		}
		result = append(result, h.pending)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Group < result[j].Group })
	return result
}
