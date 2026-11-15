package bridge

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/service"
)

func awaitPrivatePool(t *testing.T, predicate func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !predicate() {
		if time.Now().After(deadline) {
			t.Fatal("owned private pool did not settle")
		}
		time.Sleep(time.Millisecond)
	}
}

func cleanupPrivatePool(t *testing.T, p *privatePathPool) {
	t.Helper()
	t.Cleanup(func() {
		p.Close()
		select {
		case <-p.workerExited:
		case <-time.After(5 * time.Second):
			t.Error("private retirement worker did not exit")
		}
	})
}

func TestPrivatePoolRealTrafficHoldAndConfiguredCapacity(t *testing.T) {
	target := listenWire(t, func(c net.Conn) { _, _ = io.Copy(c, c) })
	address := target.listener.Addr().String()
	exit := httpWire(t, address, "", "")
	entry := socksWire(t, exit.listener.Addr().String())
	instance, parent := wireNetworkBox(t, nil, []map[string]any{{"type": "direct", "tag": "existing"}}, nil)
	scope := strings.Repeat("a", 64)
	p, err := newPrivatePathPool(parent, scope, 3, privatePoolLease(t))
	if err != nil {
		t.Fatal(err)
	}
	cleanupPrivatePool(t, p)
	for _, cap := range []int{0, 129} {
		if other, e := newPrivatePathPool(parent, scope, cap, privatePoolLease(t)); e == nil || other != nil {
			t.Fatal("invalid adapter cap admitted")
		}
	}
	if other, e := newPrivatePathPool(parent, "wrong-scope", 3, privatePoolLease(t)); e == nil || other != nil {
		t.Fatal("invalid context binding admitted")
	}
	catalogue := map[string]map[string]any{"entry": entry.node("socks", "input-entry"), "exit": exit.node("http", "input-exit")}
	create := func(ctx context.Context, id, tag, previous string) (adapter.Outbound, error) {
		raw, _ := json.Marshal(catalogue[id])
		var opts option.Outbound
		if err := opts.UnmarshalJSONContext(ctx, raw); err != nil {
			return nil, err
		}
		wrapper := opts.Options.(option.DialerOptionsWrapper)
		dialer := wrapper.TakeDialerOptions()
		dialer.Detour = previous
		wrapper.ReplaceDialerOptions(dialer)
		return service.FromContext[adapter.OutboundRegistry](ctx).CreateOutbound(ctx, instance.Router(), log.NewNOPFactory().Logger(), tag, opts.Type, opts.Options)
	}
	candidate, err := p.prepare(scope, []string{"entry", "exit"}, create)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = p.prepare(scope, []string{"exit"}, create); err == nil {
		t.Fatal("configured plus dynamic cap exceeded")
	}
	hold, err := candidate.hold(scope)
	if err != nil {
		t.Fatal(err)
	}
	var extras []*privatePathHold
	for i := 0; i < 127; i++ {
		h, e := candidate.hold(scope)
		if e != nil {
			t.Fatal(e)
		}
		extras = append(extras, h)
	}
	if _, e := candidate.hold(scope); e == nil {
		t.Fatal("reference cap exceeded")
	}
	var released sync.WaitGroup
	for _, h := range extras {
		released.Add(1)
		go func() { defer released.Done(); _ = h.Close(); _ = h.Close() }()
	}
	released.Wait()
	if err = candidate.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = candidate.hold(scope); err == nil {
		t.Fatal("draining candidate admitted a new holder")
	}
	last, err := hold.outbound(scope)
	if err != nil {
		t.Fatal("existing hold lost before graceful release")
	}
	if err = payloadWire(t, last, address); err != nil {
		t.Fatal("held real SOCKS/HTTP traffic failed", err)
	}
	if entry.calls.Load() == 0 || exit.calls.Load() == 0 {
		t.Fatal("declared hop bypassed")
	}
	if s := p.snapshot(); s.Configured != 1 || s.Dynamic != 2 || s.Holds != 1 {
		t.Fatal("incorrect capacity reservation", s)
	}
	_ = hold.Close()
	_ = hold.Close()
	if _, err = hold.outbound(scope); err == nil {
		t.Fatal("released hold borrowed an adapter")
	}
	awaitPrivatePool(t, func() bool { return p.snapshot().Dynamic == 0 })
	if err = payloadWire(t, instance.Outbound().Default(), address); err != nil {
		t.Fatal("private retirement changed parent", err)
	}
}

func TestPrivatePoolBlockedConstructionCannotPublishAfterScopeChange(t *testing.T) {
	_, parent := wireNetworkBox(t, nil, []map[string]any{{"type": "direct", "tag": "existing"}}, nil)
	a, b := strings.Repeat("a", 64), strings.Repeat("b", 64)
	p, err := newPrivatePathPool(parent, a, 5, privatePoolLease(t))
	if err != nil {
		t.Fatal(err)
	}
	cleanupPrivatePool(t, p)
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	releaseBuild := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(releaseBuild)
	var calls atomic.Int32
	go func() {
		defer close(done)
		candidate, e := p.prepare(a, []string{"one", "two"}, func(ctx context.Context, id, tag, previous string) (adapter.Outbound, error) {
			calls.Add(1)
			close(entered)
			<-release
			return nil, errPrivatePath
		})
		if candidate != nil || e == nil {
			t.Error("stale construction acquired authority")
		}
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("constructor did not enter")
	}
	if s := p.snapshot(); !s.Building || s.Dynamic != 2 {
		t.Fatal("in-flight adapters not reserved", s)
	}
	if !p.changeScope(b) {
		t.Fatal("context did not change")
	}
	if _, err = p.prepare(b, []string{"other"}, func(context.Context, string, string, string) (adapter.Outbound, error) {
		t.Error("replacement constructor started while old one blocked")
		return nil, errPrivatePath
	}); err == nil {
		t.Fatal("blocked worker replaced")
	}
	releaseBuild()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("constructor did not finish")
	}
	if calls.Load() != 1 || p.snapshot().Dynamic != 0 {
		t.Fatal("late work or reservation leaked")
	}
	if p.changeScope(b) || p.changeScope("invalid") {
		t.Fatal("invalid/no-op scope accepted")
	}
	if _, err = p.prepare(a, []string{"other"}, func(context.Context, string, string, string) (adapter.Outbound, error) {
		t.Error("stale scope ran constructor")
		return nil, nil
	}); err == nil {
		t.Fatal("stale context admitted")
	}
}

type privateBlockingClose struct {
	adapter.Outbound
	tag     string
	entered chan struct{}
	release <-chan struct{}
	fail    bool
}

func (n *privateBlockingClose) Type() string                   { return "http" }
func (n *privateBlockingClose) Tag() string                    { return n.tag }
func (n *privateBlockingClose) Dependencies() []string         { return nil }
func (n *privateBlockingClose) Start(adapter.StartStage) error { return nil }
func (n *privateBlockingClose) Close() error {
	if n.entered != nil {
		close(n.entered)
	}
	if n.release != nil {
		<-n.release
	}
	if n.fail {
		return errPrivatePath
	}
	return nil
}

func TestPrivatePoolRetirementFailureAndBlockedCloseKeepReservations(t *testing.T) {
	_, parent := wireNetworkBox(t, nil, []map[string]any{{"type": "direct", "tag": "existing"}}, nil)
	scope := strings.Repeat("a", 64)
	t.Run("partial constructor cleanup", func(t *testing.T) {
		p, e := newPrivatePathPool(parent, scope, 2, privatePoolLease(t))
		if e != nil {
			t.Fatal(e)
		}
		cleanupPrivatePool(t, p)
		candidate, e := p.prepare(scope, []string{"one"}, func(_ context.Context, _, tag, _ string) (adapter.Outbound, error) {
			return &privateBlockingClose{tag: tag, fail: true}, errPrivatePath
		})
		if candidate != nil || e == nil {
			t.Fatal("failed partial construction became usable")
		}
		if s := p.snapshot(); s.Retained != 1 || s.Dynamic != 1 || s.Building {
			t.Fatal("partial failed cleanup released its reservation", s)
		}
	})
	t.Run("failed cleanup", func(t *testing.T) {
		p, e := newPrivatePathPool(parent, scope, 2, privatePoolLease(t))
		if e != nil {
			t.Fatal(e)
		}
		cleanupPrivatePool(t, p)
		candidate, e := p.prepare(scope, []string{"one"}, func(_ context.Context, _, tag, _ string) (adapter.Outbound, error) {
			return &privateBlockingClose{tag: tag, fail: true}, nil
		})
		if e != nil {
			t.Fatal(e)
		}
		_ = candidate.Close()
		awaitPrivatePool(t, func() bool { return p.snapshot().Retained == 1 })
		if s := p.snapshot(); s.Dynamic != 1 || s.Entries != 1 {
			t.Fatal("failed close freed capacity", s)
		}
		if _, e = p.prepare(scope, []string{"two"}, func(context.Context, string, string, string) (adapter.Outbound, error) {
			t.Error("retained capacity borrowed")
			return nil, nil
		}); e == nil {
			t.Fatal("capacity re-used after failed close")
		}
	})
	t.Run("blocked closer", func(t *testing.T) {
		p, e := newPrivatePathPool(parent, scope, 10, privatePoolLease(t))
		if e != nil {
			t.Fatal(e)
		}
		cleanupPrivatePool(t, p)
		entered, release := make(chan struct{}), make(chan struct{})
		// Release the fixture before pool cleanup, even on an assertion failure.
		t.Cleanup(func() { close(release) })
		for i := 0; i < 8; i++ {
			candidate, e := p.prepare(scope, []string{"one"}, func(_ context.Context, _, tag, _ string) (adapter.Outbound, error) {
				n := &privateBlockingClose{tag: tag}
				if i == 0 {
					n.entered = entered
					n.release = release
				}
				return n, nil
			})
			if e != nil {
				t.Fatal(e)
			}
			_ = candidate.Close()
			if i == 0 {
				select {
				case <-entered:
				case <-time.After(5 * time.Second):
					t.Fatal("closer did not enter")
				}
			}
		}
		if s := p.snapshot(); s.Dynamic != 8 || s.Entries != 8 {
			t.Fatal("blocked retirement lost reservations", s)
		}
		if _, e = p.prepare(scope, []string{"one"}, func(context.Context, string, string, string) (adapter.Outbound, error) {
			t.Error("unbounded replacement candidate")
			return nil, nil
		}); e == nil {
			t.Fatal("entry bound exceeded")
		}
		p.Close() // Must return without waiting for the blocked adapter.
		if !p.snapshot().Closed {
			t.Fatal("Stop did not fence pool")
		}
	})
}

func privatePoolLease(t *testing.T) *leaseGuard {
	t.Helper()
	g := &leaseGuard{clock: bootMillis}
	if e := g.set(bootMillis() + 60_000); e != nil {
		t.Fatal(e)
	}
	return g
}
