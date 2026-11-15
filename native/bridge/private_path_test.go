package bridge

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"reflect"
	"sync"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/service"
)

func TestPrivateCandidateRegistryClonesParentAndNeverBorrowsDefault(t *testing.T) {
	target := listenWire(t, func(conn net.Conn) { _, _ = io.Copy(conn, conn) })
	destination := target.listener.Addr().String()
	exit := httpWire(t, destination, "", "")
	entry := socksWire(t, exit.listener.Addr().String())
	instance, base := wireNetworkBox(t, nil, []map[string]any{{"type": "direct", "tag": "existing"}}, nil)
	parent := instance.Outbound()
	catalogue := map[string]map[string]any{"entry": entry.node("socks", "source-entry"), "exit": exit.node("http", "source-exit")}
	constructor := func(ctx context.Context, id, tag, previous string) (adapter.Outbound, error) {
		if service.FromContext[adapter.OutboundManager](ctx) == parent {
			t.Fatal("candidate reused parent registry")
		}
		raw, err := json.Marshal(catalogue[id])
		if err != nil {
			return nil, err
		}
		var opts option.Outbound
		if err = opts.UnmarshalJSONContext(ctx, raw); err != nil {
			return nil, err
		}
		wrapper := opts.Options.(option.DialerOptionsWrapper)
		dialer := wrapper.TakeDialerOptions()
		dialer.Detour = previous
		wrapper.ReplaceDialerOptions(dialer)
		return service.FromContext[adapter.OutboundRegistry](ctx).CreateOutbound(ctx, instance.Router(), log.NewNOPFactory().Logger(), tag, opts.Type, opts.Options)
	}
	candidate, retained, err := buildPrivatePath(base, []string{"entry", "exit"}, constructor)
	if err != nil || retained != nil {
		t.Fatal("unexpected construction outcome", err)
	}
	t.Cleanup(func() { _ = candidate.Close() })
	if service.FromContext[adapter.OutboundManager](base) != parent || len(parent.Outbounds()) != 1 {
		t.Fatal("parent registry changed")
	}
	if _, ok := candidate.registry.Outbound("existing"); ok || candidate.registry.Default() != nil {
		t.Fatal("candidate borrowed a parent fallback")
	}
	nodes := candidate.registry.Outbounds()
	if len(nodes) != 2 {
		t.Fatal("candidate construction incomplete")
	}
	for _, node := range nodes {
		if _, ok := parent.Outbound(node.Tag()); ok {
			t.Fatal("candidate entered active manager")
		}
	}
	nodes[0] = nil
	if candidate.registry.Outbounds()[0] == nil {
		t.Fatal("external snapshot mutated registry")
	}
	selected := candidate.registry.Outbounds()[1]
	if err = payloadWire(t, selected, destination); err != nil {
		t.Fatal("real private SOCKS/HTTP path failed", err)
	}
	if entry.calls.Load() == 0 || exit.calls.Load() == 0 {
		t.Fatal("private path bypassed a declared hop")
	}
	if candidate.registry.Remove(selected.Tag()) != errPrivatePath ||
		candidate.registry.Create(base, nil, nil, "other", "direct", nil) != errPrivatePath ||
		candidate.registry.Start(adapter.StartStateStart) != errPrivatePath || candidate.registry.Close() != errPrivatePath {
		t.Fatal("private registry admitted an external mutation")
	}
	var readers sync.WaitGroup
	for range 4 {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for range 500 {
				candidate.registry.Outbounds()
				candidate.registry.Outbound("existing")
			}
		}()
	}
	if err = candidate.Close(); err != nil {
		t.Fatal(err)
	}
	readers.Wait()
	if candidate.ctx.Err() == nil || len(candidate.registry.Outbounds()) != 0 {
		t.Fatal("retired candidate remains registered")
	}
	if err = payloadWire(t, parent.Default(), destination); err != nil {
		t.Fatal("candidate retirement broke configured default", err)
	}
}

// Embedding supplies the dialer surface without faking lifecycle outcomes.
type pathLifecycleNode struct {
	adapter.Outbound
	name, dependency             string
	starts                       *[]string
	closes                       *[]string
	failStage                    adapter.StartStage
	fail, panicStart, panicClose bool
}

func (n *pathLifecycleNode) Type() string { return "http" }
func (n *pathLifecycleNode) Tag() string  { return n.name }
func (n *pathLifecycleNode) Dependencies() []string {
	if n.dependency == "" {
		return nil
	}
	return []string{n.dependency}
}
func (n *pathLifecycleNode) Start(stage adapter.StartStage) error {
	*n.starts = append(*n.starts, stage.String())
	if n.panicStart {
		panic("synthetic private details must not escape")
	}
	if n.fail && n.failStage == stage {
		return errors.New("synthetic private details must not escape")
	}
	return nil
}
func (n *pathLifecycleNode) Close() error {
	*n.closes = append(*n.closes, n.name)
	if n.panicClose {
		panic("synthetic close failure")
	}
	return nil
}

func TestPrivateCandidateFailureOwnsPartialObjectsAndClosesInReverse(t *testing.T) {
	_, base := wireNetworkBox(t, nil, []map[string]any{{"type": "direct", "tag": "existing"}}, nil)
	parent := service.FromContext[adapter.OutboundManager](base)
	for _, kind := range []string{"partial", "start", "panic-constructor", "panic-start", "foreign-dependency", "bad-tag"} {
		t.Run(kind, func(t *testing.T) {
			var starts, closes, created []string
			path, retained, err := buildPrivatePath(base, []string{"a", "b"}, func(ctx context.Context, id, tag, previous string) (adapter.Outbound, error) {
				if id == "b" && kind == "panic-constructor" {
					panic("synthetic constructor failure")
				}
				node := &pathLifecycleNode{name: tag, dependency: previous, starts: &starts, closes: &closes}
				created = append(created, tag)
				if id == "b" {
					switch kind {
					case "partial":
						return node, errors.New("synthetic partial failure")
					case "start":
						node.fail = true
						node.failStage = adapter.StartStateStart
					case "panic-start":
						node.panicStart = true
					case "foreign-dependency":
						node.dependency = "existing"
					case "bad-tag":
						node.name = "substituted"
					}
				}
				return node, nil
			})
			if path != nil || retained != nil || err != errPrivatePath {
				t.Fatal("partial path or raw error escaped")
			}
			expected := append([]string(nil), created...)
			if kind == "bad-tag" {
				expected[len(expected)-1] = "substituted"
			}
			for left, right := 0, len(expected)-1; left < right; left, right = left+1, right-1 {
				expected[left], expected[right] = expected[right], expected[left]
			}
			if !reflect.DeepEqual(closes, expected) {
				t.Fatal("partial ownership or dependency cleanup order lost")
			}
			if service.FromContext[adapter.OutboundManager](base) != parent {
				t.Fatal("parent service registry mutated")
			}
		})
	}
}

func TestPrivateCandidateRejectsInvalidPathsAndClosePanicCannotOrphanEarlierNodes(t *testing.T) {
	_, base := wireNetworkBox(t, nil, []map[string]any{{"type": "direct", "tag": "existing"}}, nil)
	calls := 0
	create := func(context.Context, string, string, string) (adapter.Outbound, error) {
		calls++
		return nil, errors.New("synthetic")
	}
	for _, ids := range [][]string{nil, {}, {"a", "a"}, {"UPPER"}, {"a", "b", "c", "d", "e"}} {
		if candidate, retained, err := buildPrivatePath(base, ids, create); candidate != nil || retained != nil || err != errPrivatePath {
			t.Fatal("invalid path admitted")
		}
	}
	canceled, cancel := context.WithCancel(base)
	cancel()
	if candidate, retained, err := buildPrivatePath(canceled, []string{"a"}, create); candidate != nil || retained != nil || err != errPrivatePath || calls != 0 {
		t.Fatal("invalid request reached constructor")
	}
	var starts, closes []string
	candidate, retained, err := buildPrivatePath(base, []string{"a", "b"}, func(ctx context.Context, id, tag, previous string) (adapter.Outbound, error) {
		return &pathLifecycleNode{name: tag, dependency: previous, starts: &starts, closes: &closes, panicClose: id == "b"}, nil
	})
	if err != nil || retained != nil {
		t.Fatal("unexpected construction outcome", err)
	}
	if candidate.Close() != errPrivatePath || candidate.Close() != errPrivatePath || len(closes) != 2 || len(candidate.owned) != 2 {
		t.Fatal("panic prevented earlier cleanup or repeated retirement")
	}
	if len(starts) != 2*len(adapter.ListStartStages) {
		t.Fatal("lifecycle stage omitted")
	}
	partial, unclean, buildErr := buildPrivatePath(base, []string{"a"}, func(ctx context.Context, id, tag, previous string) (adapter.Outbound, error) {
		return &pathLifecycleNode{name: tag, starts: &starts, closes: &closes, panicClose: true}, errors.New("synthetic partial failure")
	})
	if partial != nil || unclean == nil || unclean.ctx.Err() == nil || len(unclean.owned) != 1 || buildErr != errPrivatePath {
		t.Fatal("failed cleanup lost its reservation ownership or gained route authority")
	}
}
