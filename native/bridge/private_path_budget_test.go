package bridge

import (
	"context"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
)

type privateBudgetLifecycleNode struct {
	pathLifecycleNode
	firstStart func()
}

func (n *privateBudgetLifecycleNode) Start(stage adapter.StartStage) error {
	err := n.pathLifecycleNode.Start(stage)
	if n.firstStart != nil {
		change := n.firstStart
		n.firstStart = nil
		change()
	}
	return err
}

func TestPrivatePoolWorkBudgetCannotPublishLateOrCancelPublishedOwners(t *testing.T) {
	t.Run("published path outlives the construction request", func(t *testing.T) {
		target := listenWire(t, func(c net.Conn) { _, _ = io.Copy(c, c) })
		_, parent := wireNetworkBox(t, nil, []map[string]any{{"type": "direct", "tag": "existing"}}, nil)
		scope := strings.Repeat("a", 64)
		pool, e := newPrivatePathPool(parent, scope, 2, privatePoolLease(t))
		if e != nil {
			t.Fatal(e)
		}
		cleanupPrivatePool(t, pool)
		work, cancel := context.WithCancel(context.Background())
		defer cancel()
		candidate, e := pool.prepareWithContext(work, scope, []string{"one"}, func(_ context.Context, _, tag, _ string) (adapter.Outbound, error) {
			return &privateTrafficTestNode{tag: tag, dial: func(ctx context.Context, network string, dst M.Socksaddr) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, dst.String())
			}}, nil
		})
		if e != nil {
			t.Fatal(e)
		}
		cancel()
		flow, e := candidate.dialTCP(scope, context.Background(), "tcp", M.ParseSocksaddr(target.listener.Addr().String()))
		if e != nil {
			t.Fatal("construction cancellation revoked already-published owner", e)
		}
		defer flow.Close()
		_ = flow.SetDeadline(time.Now().Add(5 * time.Second))
		if _, e = io.WriteString(flow, "owned"); e != nil {
			t.Fatal(e)
		}
		raw := make([]byte, 5)
		if _, e = io.ReadFull(flow, raw); e != nil || string(raw) != "owned" {
			t.Fatal("published owner lost real traffic", e)
		}
	})
	t.Run("cancellation between hops cannot start a late constructor", func(t *testing.T) {
		_, parent := wireNetworkBox(t, nil, []map[string]any{{"type": "direct", "tag": "existing"}}, nil)
		scope := strings.Repeat("a", 64)
		pool, e := newPrivatePathPool(parent, scope, 3, privatePoolLease(t))
		if e != nil {
			t.Fatal(e)
		}
		cleanupPrivatePool(t, pool)
		work, cancel := context.WithCancel(context.Background())
		defer cancel()
		calls := 0
		var starts, closes []string
		candidate, e := pool.prepareWithContext(work, scope, []string{"one", "two"}, func(_ context.Context, _, tag, previous string) (adapter.Outbound, error) {
			calls++
			cancel()
			return &pathLifecycleNode{name: tag, dependency: previous, starts: &starts, closes: &closes}, nil
		})
		if candidate != nil || e != errPrivatePath || calls != 1 || len(starts) != 0 || len(closes) != 1 || pool.snapshot().Dynamic != 0 {
			t.Fatal("cancelled construction started or published late work")
		}
	})
	t.Run("blocked cancelled constructor still owns its only worker", func(t *testing.T) {
		_, parent := wireNetworkBox(t, nil, []map[string]any{{"type": "direct", "tag": "existing"}}, nil)
		scope := strings.Repeat("a", 64)
		pool, e := newPrivatePathPool(parent, scope, 3, privatePoolLease(t))
		if e != nil {
			t.Fatal(e)
		}
		cleanupPrivatePool(t, pool)
		entered, cancelObserved, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
		var once sync.Once
		unblock := func() { once.Do(func() { close(release) }) }
		t.Cleanup(unblock)
		work, cancel := context.WithCancel(context.Background())
		defer cancel()
		var calls atomic.Int32
		go func() {
			defer close(done)
			var starts, closes []string
			c, e := pool.prepareWithContext(work, scope, []string{"one"}, func(ctx context.Context, _, tag, _ string) (adapter.Outbound, error) {
				calls.Add(1)
				close(entered)
				<-ctx.Done()
				close(cancelObserved)
				<-release
				return &pathLifecycleNode{name: tag, starts: &starts, closes: &closes}, nil
			})
			if c != nil || e != errPrivatePath {
				t.Error("cancelled blocked constructor published")
			}
		}()
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			t.Fatal("constructor did not enter")
		}
		cancel()
		select {
		case <-cancelObserved:
		case <-time.After(5 * time.Second):
			t.Fatal("work cancellation did not reach candidate context")
		}
		if s := pool.snapshot(); !s.Building || s.Dynamic != 1 {
			t.Fatal("cancelled running work lost its reservation", s)
		}
		next := strings.Repeat("b", 64)
		if !pool.changeScope(next) {
			t.Fatal("scope did not change")
		}
		if c, e := pool.prepare(next, []string{"other"}, func(context.Context, string, string, string) (adapter.Outbound, error) {
			calls.Add(1)
			return nil, errPrivatePath
		}); c != nil || e != errPrivatePath || calls.Load() != 1 {
			t.Fatal("blocked construction got a replacement")
		}
		unblock()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("released constructor did not finish")
		}
		awaitPrivatePool(t, func() bool { s := pool.snapshot(); return !s.Building && s.Dynamic == 0 })
	})
	for _, duringStart := range []string{"suspend elapsed", "boot clock rollback", "work cancelled"} {
		t.Run("lifecycle stops after "+duringStart, func(t *testing.T) {
			_, parent := wireNetworkBox(t, nil, []map[string]any{{"type": "direct", "tag": "existing"}}, nil)
			var now atomic.Int64
			now.Store(10_000)
			lease := &leaseGuard{clock: now.Load}
			if e := lease.set(1_000_000); e != nil {
				t.Fatal(e)
			}
			scope := strings.Repeat("a", 64)
			pool, e := newPrivatePathPool(parent, scope, 3, lease)
			if e != nil {
				t.Fatal(e)
			}
			cleanupPrivatePool(t, pool)
			work, cancel := context.WithCancel(context.Background())
			defer cancel()
			var starts, closes []string
			calls := 0
			candidate, e := pool.prepareWithContext(work, scope, []string{"one", "two"}, func(_ context.Context, _, tag, previous string) (adapter.Outbound, error) {
				calls++
				return &privateBudgetLifecycleNode{
					pathLifecycleNode: pathLifecycleNode{name: tag, dependency: previous, starts: &starts, closes: &closes},
					firstStart: func() {
						switch duringStart {
						case "suspend elapsed":
							now.Add(30_001)
						case "boot clock rollback":
							now.Add(-1)
						case "work cancelled":
							cancel()
						}
					},
				}, nil
			})
			if candidate != nil || e != errPrivatePath || calls != 1 || len(starts) != 1 || len(closes) != 1 || pool.snapshot().Dynamic != 0 {
				t.Fatal("lifecycle budget admitted a later stage or constructor")
			}
		})
	}
	for _, change := range []int64{30_001, -1} {
		t.Run(map[bool]string{true: "suspend elapsed before timer callback", false: "boot clock rollback"}[change > 0], func(t *testing.T) {
			_, parent := wireNetworkBox(t, nil, []map[string]any{{"type": "direct", "tag": "existing"}}, nil)
			var now atomic.Int64
			now.Store(10_000)
			lease := &leaseGuard{clock: now.Load}
			if e := lease.set(1_000_000); e != nil {
				t.Fatal(e)
			}
			scope := strings.Repeat("a", 64)
			pool, e := newPrivatePathPool(parent, scope, 2, lease)
			if e != nil {
				t.Fatal(e)
			}
			cleanupPrivatePool(t, pool)
			var starts, closes []string
			candidate, e := pool.prepare(scope, []string{"one"}, func(_ context.Context, _, tag, _ string) (adapter.Outbound, error) {
				now.Add(change)
				return &pathLifecycleNode{name: tag, starts: &starts, closes: &closes}, nil
			})
			if candidate != nil || e != errPrivatePath || len(starts) != 0 || len(closes) != 1 || pool.snapshot().Dynamic != 0 {
				t.Fatal("out-of-budget construction gained authority")
			}
		})
	}
}
