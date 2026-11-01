package bridge

import (
	"errors"
	tun "github.com/sagernet/sing-tun"
	"sync"
	"sync/atomic"
	"testing"
)

type fakeLeaseTun struct {
	tun.Tun
	reads, writes int
	afterRead     func()
}

func (t *fakeLeaseTun) Read(b []byte) (int, error) {
	t.reads++
	b[0] = 42
	if t.afterRead != nil {
		t.afterRead()
	}
	return 1, nil
}
func (t *fakeLeaseTun) Write(b []byte) (int, error) { t.writes++; return len(b), nil }

type fakeLeaseLinux struct{ *fakeLeaseTun }

func (t *fakeLeaseLinux) FrontHeadroom() int      { return 8 }
func (t *fakeLeaseLinux) BatchSize() int          { return 4 }
func (t *fakeLeaseLinux) TXChecksumOffload() bool { return true }
func (t *fakeLeaseLinux) BatchRead(b [][]byte, offset int, sizes []int) (int, error) {
	n, e := t.Read(b[0][offset:])
	sizes[0] = n
	return 1, e
}
func (t *fakeLeaseLinux) BatchWrite(b [][]byte, offset int) (int, error) {
	_, e := t.Write(b[0][offset:])
	return len(b), e
}

func TestLeaseDeniesAfterSuspendWithoutControllerTick(t *testing.T) {
	var now int64 = 10
	g := &leaseGuard{clock: func() int64 { return now }}
	if g.allowed() {
		t.Fatal("uninitialized guard permitted packets")
	}
	if g.set(20) != nil || !g.allowed() {
		t.Fatal("valid lease rejected")
	}
	base := &fakeLeaseTun{}
	wrapped := protectTun(base, g)
	b := make([]byte, 8)
	if n, e := wrapped.Read(b); e != nil || n != 1 {
		t.Fatal("authorized packet failed")
	}
	now = 20
	if n, e := wrapped.Write(b); n != 0 || !errors.Is(e, errLeaseExpired) || base.writes != 0 {
		t.Fatal("expired write reached TUN")
	}
	if n, e := wrapped.Read(b); n != 0 || !errors.Is(e, errLeaseExpired) || base.reads != 1 {
		t.Fatal("expired read reached TUN")
	}
	if !errors.Is(g.set(30), errLeaseRestart) {
		t.Fatal("expired owner was resurrected")
	}
}
func TestLeaseChecksAfterBlockingAndBatchRead(t *testing.T) {
	for _, batch := range []bool{false, true} {
		t.Run(map[bool]string{false: "single", true: "batch"}[batch], func(t *testing.T) {
			var now int64 = 10
			g := &leaseGuard{clock: func() int64 { return now }}
			_ = g.set(20)
			base := &fakeLeaseTun{afterRead: func() { now = 20 }}
			var raw tun.Tun = base
			if batch {
				raw = &fakeLeaseLinux{base}
			}
			wrapped := protectTun(raw, g)
			b := make([]byte, 16)
			if batch {
				linux, ok := wrapped.(tun.LinuxTUN)
				if !ok || linux.FrontHeadroom() != 8 || linux.BatchSize() != 4 || !linux.TXChecksumOffload() {
					t.Fatal("batch capabilities lost")
				}
				sizes := []int{99}
				if n, e := linux.BatchRead([][]byte{b}, 8, sizes); n != 0 || !errors.Is(e, errLeaseExpired) || sizes[0] != 0 {
					t.Fatal("late batch escaped lease")
				}
				if n, e := linux.BatchWrite([][]byte{b}, 8); n != 0 || !errors.Is(e, errLeaseExpired) || base.writes != 0 {
					t.Fatal("expired batch write reached TUN")
				}
			} else if n, e := wrapped.Read(b); n != 0 || !errors.Is(e, errLeaseExpired) {
				t.Fatal("late packet escaped lease")
			}
		})
	}
}
func TestLeaseRenewalLinearizesBeforeOldExpiry(t *testing.T) {
	var first atomic.Bool
	first.Store(true)
	entered := make(chan struct{})
	resume := make(chan struct{})
	g := &leaseGuard{clock: func() int64 {
		if first.CompareAndSwap(true, false) {
			close(entered)
			<-resume
			return 20
		}
		return 20
	}}
	_ = g.set(20)
	done := make(chan bool)
	go func() { done <- g.allowed() }()
	<-entered
	if g.set(30) != nil {
		t.Fatal("renewal rejected")
	}
	close(resume)
	if !<-done || !g.allowed() {
		t.Fatal("old expiry revoked renewed authorization")
	}
}
func TestLeaseUnmanagedAndConcurrentRenewals(t *testing.T) {
	g := &leaseGuard{clock: func() int64 { return 10 }}
	for _, bad := range []int64{-1, 9007199254740992} {
		if g.set(bad) == nil {
			t.Fatal("invalid deadline accepted")
		}
	}
	_ = g.set(0)
	if !g.allowed() {
		t.Fatal("unmanaged lease blocked")
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				if g.set(30) != nil || !g.allowed() {
					t.Error("concurrent renewal lost")
				}
			}
		}()
	}
	wg.Wait()
}
