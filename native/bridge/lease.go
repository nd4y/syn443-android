// SPDX-License-Identifier: GPL-3.0-or-later
package bridge

import (
	"errors"
	tun "github.com/sagernet/sing-tun"
	"golang.org/x/sys/unix"
	"math"
	"sync/atomic"
)

var errLeaseExpired = errors.New("managed authorization expired")
var errLeaseRestart = errors.New("expired TUN requires a new owner")

type leaseGuard struct {
	state atomic.Pointer[leaseState]
	clock func() int64
}
type leaseState struct {
	deadline int64
	expired  bool
}

func bootMillis() int64 {
	var ts unix.Timespec
	if unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts) != nil || ts.Sec < 0 || ts.Sec > math.MaxInt64/1000 {
		return math.MaxInt64
	}
	return ts.Sec*1000 + ts.Nsec/1_000_000
}
func (g *leaseGuard) allowed() bool {
	for {
		s := g.state.Load()
		if s == nil || s.expired {
			return false
		}
		if s.deadline == 0 || g.clock() < s.deadline {
			return true
		}
		// Renewal and expiry linearize on the same state; an old read cannot revoke a new lease.
		if g.state.CompareAndSwap(s, &leaseState{deadline: s.deadline, expired: true}) {
			return false
		}
	}
}
func (g *leaseGuard) set(deadline int64) error {
	if deadline < 0 || deadline > 9007199254740991 {
		return errors.New("invalid authorization deadline")
	}
	for {
		s := g.state.Load()
		if s != nil && s.expired {
			return errLeaseRestart
		}
		if g.state.CompareAndSwap(s, &leaseState{deadline: deadline}) {
			return nil
		}
	}
}

type guardedTun struct {
	tun.Tun
	guard *leaseGuard
}

func (t *guardedTun) Read(buffer []byte) (int, error) {
	if !t.guard.allowed() {
		return 0, errLeaseExpired
	}
	n, e := t.Tun.Read(buffer)
	if !t.guard.allowed() {
		return 0, errLeaseExpired
	}
	return n, e
}
func (t *guardedTun) Write(buffer []byte) (int, error) {
	if !t.guard.allowed() {
		return 0, errLeaseExpired
	}
	return t.Tun.Write(buffer)
}

type guardedLinuxTun struct {
	*guardedTun
	linux tun.LinuxTUN
}

func (t *guardedLinuxTun) FrontHeadroom() int      { return t.linux.FrontHeadroom() }
func (t *guardedLinuxTun) BatchSize() int          { return t.linux.BatchSize() }
func (t *guardedLinuxTun) TXChecksumOffload() bool { return t.linux.TXChecksumOffload() }
func (t *guardedLinuxTun) BatchRead(buffers [][]byte, offset int, sizes []int) (int, error) {
	if !t.guard.allowed() {
		clear(sizes)
		return 0, errLeaseExpired
	}
	n, e := t.linux.BatchRead(buffers, offset, sizes)
	if !t.guard.allowed() {
		for i := range sizes {
			sizes[i] = 0
		}
		return 0, errLeaseExpired
	}
	return n, e
}
func (t *guardedLinuxTun) BatchWrite(buffers [][]byte, offset int) (int, error) {
	if !t.guard.allowed() {
		return 0, errLeaseExpired
	}
	return t.linux.BatchWrite(buffers, offset)
}
func protectTun(t tun.Tun, g *leaseGuard) tun.Tun {
	base := &guardedTun{t, g}
	var guarded tun.Tun = base
	if linux, ok := t.(tun.LinuxTUN); ok {
		guarded = &guardedLinuxTun{base, linux}
	}
	return protectStackTun(guarded, t, g)
}

// The controller derives this from authenticated absolute expiry and CLOCK_BOOTTIME.
// No wakeup/periodic timer is needed to deny packets after a suspended device wakes.
func (e *Runtime) SetLeaseDeadline(deadline int64) error { return e.platform.lease.set(deadline) }
