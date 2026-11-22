package bridge

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
)

type privateAdaptiveBlockingClose struct{ privateBlockingClose }

func (*privateAdaptiveBlockingClose) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return nil, errPrivatePath
}

func privateAdaptiveMetadata(t *testing.T, paths [][]string, intent string, features []string) []byte {
	t.Helper()
	ids, exits := map[string]bool{}, map[string]bool{}
	for _, path := range paths {
		for _, id := range path {
			ids[id] = true
		}
		exits[path[len(path)-1]] = true
	}
	names := make([]string, 0, len(ids))
	for id := range ids {
		names = append(names, id)
	}
	slices.Sort(names)
	hops, edges, templates := []any{}, []any{}, []any{}
	for _, id := range names {
		var exit any
		if exits[id] {
			exit = intent
		}
		hops = append(hops, map[string]any{"id": id, "entryModes": []string{"WIFI"}, "exitClass": exit, "features": features})
	}
	seen := map[string]bool{}
	references := []string{}
	for i, path := range paths {
		slots := [][]string{}
		for j, id := range path {
			slots = append(slots, []string{id})
			if j > 0 && !seen[path[j-1]+"/"+id] {
				edges = append(edges, map[string]any{"from": path[j-1], "to": id, "features": features})
				seen[path[j-1]+"/"+id] = true
			}
		}
		name := fmt.Sprintf("t%d", i)
		references = append(references, name)
		templates = append(templates, map[string]any{"id": name, "slots": slots})
	}
	raw, e := json.Marshal(map[string]any{"schemaVersion": 1, "hops": hops, "edges": edges, "templates": templates,
		"groups": []any{map[string]any{"id": "inside", "intent": intent, "features": features, "templates": references}}})
	if e != nil {
		t.Fatal(e)
	}
	return raw
}

func privateAdaptiveCatalogue(t *testing.T, nodes map[string]map[string]any) *privatePathCatalogue {
	t.Helper()
	instance, parent := wireNetworkBox(t, nil, []map[string]any{{"type": "direct", "tag": "existing"}}, nil)
	input := map[string]json.RawMessage{}
	for id, node := range nodes {
		raw, e := json.Marshal(node)
		if e != nil {
			t.Fatal(e)
		}
		input[id] = raw
	}
	c, e := newPrivatePathCatalogue(parent, instance.Router(), input)
	if e != nil {
		t.Fatal(e)
	}
	return c
}

func privateAdaptiveNewHub(t *testing.T, c *privatePathCatalogue, metadata []byte, plans map[string][]routeCheck, capacity int) (*privateAdaptiveHub, *atomic.Int64) {
	t.Helper()
	now := &atomic.Int64{}
	now.Store(bootMillis())
	lease := &leaseGuard{clock: now.Load}
	if e := lease.set(now.Load() + 1_000_000); e != nil {
		t.Fatal(e)
	}
	h, e := newPrivateAdaptiveHub(c, metadata, plans, strings.Repeat("a", 64), "WIFI", capacity, lease)
	if e != nil {
		t.Fatal(e)
	}
	cleanupPrivatePool(t, h.pool)
	t.Cleanup(h.Close)
	return h, now
}

func privateAdaptiveOneHopInputs(t *testing.T, count int) (*privatePathCatalogue, []byte, map[string][]routeCheck, [][]string, string) {
	t.Helper()
	target := listenWire(t, func(c net.Conn) { _, _ = io.Copy(c, c) })
	address := target.listener.Addr().String()
	nodes, paths := map[string]map[string]any{}, [][]string{}
	for i := 0; i < count; i++ {
		id := fmt.Sprintf("p%02d", i)
		proxy := httpWire(t, address, "", "")
		nodes[id] = proxy.node("http", id)
		paths = append(paths, []string{id})
	}
	return privateAdaptiveCatalogue(t, nodes), privateAdaptiveMetadata(t, paths, "INTERNAL", []string{"TCP", "IPV4"}),
		map[string][]routeCheck{"inside": {{Method: "tcp", Target: address}}}, paths, address
}

func privateAdaptiveEcho(t *testing.T, c net.Conn, value string) {
	t.Helper()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, e := io.WriteString(c, value); e != nil {
		t.Fatal(e)
	}
	raw := make([]byte, len(value))
	if _, e := io.ReadFull(c, raw); e != nil || string(raw) != value {
		t.Fatal("adaptive selected path lost real payload", e)
	}
}

func TestPrivateAdaptiveHubRealTwoHopCommitDrainAndRebuild(t *testing.T) {
	target := listenWire(t, func(c net.Conn) { _, _ = io.Copy(c, c) })
	address := target.listener.Addr().String()
	exitA, exitB := httpWire(t, address, "", ""), httpWire(t, address, "", "")
	entryA, entryB := socksWire(t, exitA.listener.Addr().String()), socksWire(t, exitB.listener.Addr().String())
	catalogue := privateAdaptiveCatalogue(t, map[string]map[string]any{
		"a1": entryA.node("socks", "a1"), "a2": exitA.node("http", "a2"),
		"b1": entryB.node("socks", "b1"), "b2": exitB.node("http", "b2"),
	})
	a, b := []string{"a1", "a2"}, []string{"b1", "b2"}
	metadata := privateAdaptiveMetadata(t, [][]string{a, b}, "INTERNAL", []string{"TCP", "IPV4"})
	plans := map[string][]routeCheck{"inside": {{Method: "tcp", Target: address}}}
	h, now := privateAdaptiveNewHub(t, catalogue, metadata, plans, 5)
	// The graph/check handoff must own its bytes and slices.
	for i := range metadata {
		metadata[i] = '!'
	}
	plans["inside"][0].Target = "invalid-input"
	if conn, e := h.dialTCP("inside", context.Background(), "tcp", M.ParseSocksaddr(address)); conn != nil || e != errPrivatePath {
		t.Fatal("unverified group acquired a direct fallback")
	}
	r, e := h.prepareProbe(context.Background(), "inside", a)
	if e != nil || r == nil || entryA.calls.Load() == 0 || exitA.calls.Load() == 0 {
		t.Fatal("actual first chain did not produce a receipt", e)
	}
	if conn, e := h.dialTCP("inside", context.Background(), "tcp", M.ParseSocksaddr(address)); conn != nil || e != errPrivatePath {
		t.Fatal("successful probing selected a route before commit")
	}
	copyReceipt := *r
	if h.commit(&copyReceipt, 1000) || !h.commit(r, 1000) || h.commit(r, 1000) {
		t.Fatal("receipt identity, explicit commit or single-use boundary failed")
	}
	old, e := h.dialTCP("inside", context.Background(), "tcp", M.ParseSocksaddr(address))
	if e != nil {
		t.Fatal(e)
	}
	defer old.Close()
	privateAdaptiveEcho(t, old, "first-real-chain")
	firstID := h.cache["a1/a2"].entry.id
	r, e = h.prepareProbe(context.Background(), "inside", b)
	if e != nil || r == nil || entryB.calls.Load() == 0 || exitB.calls.Load() == 0 {
		t.Fatal("actual replacement chain did not produce a receipt", e)
	}
	beforeA := entryA.calls.Load()
	uncommitted, e := h.dialTCP("inside", context.Background(), "tcp", M.ParseSocksaddr(address))
	if e != nil {
		t.Fatal(e)
	}
	privateAdaptiveEcho(t, uncommitted, "still-first-until-commit")
	_ = uncommitted.Close()
	if entryA.calls.Load() <= beforeA || !h.commit(r, 1000) {
		t.Fatal("probe silently switched a healthy selected chain")
	}
	privateAdaptiveEcho(t, old, "old-flow-drains")
	current, e := h.dialTCP("inside", context.Background(), "tcp", M.ParseSocksaddr(address))
	if e != nil {
		t.Fatal(e)
	}
	defer current.Close()
	privateAdaptiveEcho(t, current, "second-real-chain")
	now.Add(1001)
	if n, e := old.Write([]byte("late-drain")); n != 0 || e != errPrivatePath {
		t.Fatal("suspend extended the old flow's drain authority")
	}
	_ = old.Close()
	awaitPrivatePool(t, func() bool { return h.pool.snapshot().Dynamic == 2 })
	// A released cached owner must be rebuilt: a stale pointer cannot make the
	// first alternative permanently unusable after a successful failover.
	r, e = h.prepareProbe(context.Background(), "inside", a)
	if e != nil || r == nil || h.cache["a1/a2"].entry.id == firstID || !h.commit(r, 1000) {
		t.Fatal("retired alternative could not be rediscovered and selected", e)
	}
	for _, v := range []any{h, r} {
		if raw := fmt.Sprintf("%v %#v", v, v); strings.Contains(raw, address) || strings.Contains(raw, h.scope) {
			t.Fatal("adaptive diagnostics exposed private binding data")
		}
	}
	if !h.changeScope(strings.Repeat("b", 64), "WIFI") {
		t.Fatal("full local context did not change")
	}
	if conn, e := h.dialTCP("inside", context.Background(), "tcp", M.ParseSocksaddr(address)); conn != nil || e != errPrivatePath {
		t.Fatal("new context borrowed a previously selected route")
	}
}

func TestUnknownUnderlayRequiresUniversalEntryAndFreshRealPayloadProof(t *testing.T) {
	c, metadata, plans, paths, address := privateAdaptiveOneHopInputs(t, 2)
	var graph map[string]json.RawMessage
	if err := json.Unmarshal(metadata, &graph); err != nil {
		t.Fatal(err)
	}
	var hops []map[string]any
	if err := json.Unmarshal(graph["hops"], &hops); err != nil {
		t.Fatal(err)
	}
	hops[1]["entryModes"] = []string{"UNKNOWN"}
	graph["hops"] = privateAdaptiveMarshal(t, hops)
	if bad, err := newPrivateAdaptiveHub(c, privateAdaptiveMarshal(t, graph), plans, strings.Repeat("c", 64), "UNKNOWN", 4, privatePoolLease(t)); bad != nil || err == nil {
		t.Fatal("signed metadata invented an entry permission for an unrecognized network")
	}
	hops[1]["entryModes"] = []string{"HOME_WIFI", "WIFI", "CELLULAR", "CELLULAR_RESTRICTED"}
	graph["hops"] = privateAdaptiveMarshal(t, hops)
	h, _ := privateAdaptiveNewHub(t, c, privateAdaptiveMarshal(t, graph), plans, 4)
	old, err := h.prepareProbe(context.Background(), "inside", paths[0])
	if err != nil || old == nil || !h.changeScope(strings.Repeat("b", 64), "UNKNOWN") || h.commit(old, 1000) {
		t.Fatal("a new underlay must retire the earlier Wi-Fi receipt", err)
	}
	if conn, err := h.dialTCP("inside", context.Background(), "tcp", M.ParseSocksaddr(address)); conn != nil || err != errPrivatePath {
		t.Fatal("unverified entry carried user traffic")
	}
	if probe, err := h.prepareProbe(context.Background(), "inside", paths[0]); probe != nil || err != errPrivatePath {
		t.Fatal("Wi-Fi-only path admitted on unknown underlay")
	}
	proof, err := h.prepareProbe(context.Background(), "inside", paths[1])
	if err != nil || proof == nil || !h.commit(proof, 1000) {
		t.Fatal("fresh probe on universal entry failed", err)
	}
	conn, err := h.dialTCP("inside", context.Background(), "tcp", M.ParseSocksaddr(address))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	privateAdaptiveEcho(t, conn, "unknown-underlay-verified-route")
}

func TestPrivateAdaptiveHubStrictPlansModesReceiptsAndFreshness(t *testing.T) {
	c, metadata, plans, paths, address := privateAdaptiveOneHopInputs(t, 1)
	for _, scenario := range []string{"nil catalogue", "empty metadata", "invalid scope", "zero capacity", "oversized capacity"} {
		t.Run(scenario, func(t *testing.T) {
			catalogue, raw, scope, capacity := c, metadata, strings.Repeat("a", 64), 2
			switch scenario {
			case "nil catalogue":
				catalogue = nil
			case "empty metadata":
				raw = nil
			case "invalid scope":
				scope = "remote-label"
			case "zero capacity":
				capacity = 0
			case "oversized capacity":
				capacity = 129
			}
			if h, e := newPrivateAdaptiveHub(catalogue, raw, plans, scope, "WIFI", capacity, privatePoolLease(t)); h != nil || e != errPrivatePath {
				if h != nil {
					h.Close()
				}
				t.Fatal("invalid owner input admitted")
			}
		})
	}
	for _, mode := range []string{"", "LTE", "LTE_WHITELIST", "wifi", "REMOTE_MODE"} {
		if h, e := newPrivateAdaptiveHub(c, metadata, plans, strings.Repeat("a", 64), mode, 2, privatePoolLease(t)); h != nil || e != errPrivatePath {
			t.Fatal("unknown or legacy mode admitted")
		}
	}
	t.Run("undeclared paths cannot start a constructor", func(t *testing.T) {
		h, _ := privateAdaptiveNewHub(t, c, metadata, plans, 2)
		create := h.create
		var calls atomic.Int32
		h.create = func(ctx context.Context, id, tag, previous string) (adapter.Outbound, error) {
			calls.Add(1)
			return create(ctx, id, tag, previous)
		}
		for _, path := range [][]string{nil, {"missing"}, {"p00", "p00"}} {
			if r, e := h.prepareProbe(context.Background(), "inside", path); r != nil || e != errPrivatePath {
				t.Fatal("undeclared path obtained a proof")
			}
		}
		if r, e := h.prepareProbe(context.Background(), "missing", paths[0]); r != nil || e != errPrivatePath {
			t.Fatal("unknown group obtained a proof")
		}
		cancelled, cancel := context.WithCancel(context.Background())
		cancel()
		for _, work := range []context.Context{nil, cancelled} {
			if r, e := h.prepareProbe(work, "inside", paths[0]); r != nil || e != errPrivatePath {
				t.Fatal("invalid work context obtained a proof")
			}
		}
		if calls.Load() != 0 || h.pool.snapshot().Dynamic != 0 {
			t.Fatal("rejected declaration started a private constructor")
		}
	})
	for _, scenario := range []string{"missing plan", "extra plan", "wrong group", "empty checks", "too many checks", "invalid check", "unknown catalogue", "duplicate metadata", "UDP requested", "ICMP requested", "TCP absent", "internal country", "public without country", "wrong country class", "country query", "country path", "country fragment"} {
		t.Run(scenario, func(t *testing.T) {
			raw := append([]byte(nil), metadata...)
			checks := map[string][]routeCheck{"inside": append([]routeCheck(nil), plans["inside"]...)}
			switch scenario {
			case "missing plan":
				delete(checks, "inside")
			case "extra plan":
				checks["other"] = checks["inside"]
			case "wrong group":
				checks["other"] = checks["inside"]
				delete(checks, "inside")
			case "empty checks":
				checks["inside"] = nil
			case "too many checks":
				checks["inside"] = []routeCheck{plans["inside"][0], plans["inside"][0], plans["inside"][0], plans["inside"][0], plans["inside"][0]}
			case "invalid check":
				checks["inside"][0].Method = "remote_code"
			case "unknown catalogue":
				raw = []byte(strings.ReplaceAll(string(raw), "p00", "missing"))
			case "duplicate metadata":
				raw = []byte(strings.Replace(string(raw), `"schemaVersion":1`, `"schemaVersion":1,"schemaVersion":1`, 1))
			case "UDP requested":
				raw = privateAdaptiveMetadata(t, paths, "INTERNAL", []string{"TCP", "UDP", "IPV4"})
			case "ICMP requested":
				raw = privateAdaptiveMetadata(t, paths, "INTERNAL", []string{"TCP", "ICMP", "IPV4"})
			case "TCP absent":
				raw = privateAdaptiveMetadata(t, paths, "INTERNAL", []string{"IPV4"})
			case "internal country":
				checks["inside"] = []routeCheck{{Method: "https_exit_country", Target: "https://geo.example.invalid/", ExpectedExitClass: "RU"}}
			default:
				raw = privateAdaptiveMetadata(t, paths, "RU", []string{"TCP", "IPV4"})
				if scenario != "public without country" {
					check := routeCheck{Method: "https_exit_country", Target: "https://geo.example.invalid/", ExpectedExitClass: "RU"}
					switch scenario {
					case "wrong country class":
						check.ExpectedExitClass = "NON_RU"
					case "country query":
						check.Target += "?ip=192.0.2.1"
					case "country path":
						check.Target += "192.0.2.1"
					case "country fragment":
						check.Target += "#ip"
					}
					checks["inside"] = []routeCheck{check}
				}
			}
			if h, e := newPrivateAdaptiveHub(c, raw, checks, strings.Repeat("a", 64), "WIFI", 2, privatePoolLease(t)); h != nil || e != errPrivatePath {
				if h != nil {
					h.Close()
				}
				t.Fatal("invalid or falsely advertised adaptive plan admitted")
			}
		})
	}
	// Validate the public declaration without contacting any external service.
	for _, intent := range []string{"RU", "NON_RU"} {
		raw := privateAdaptiveMetadata(t, paths, intent, []string{"TCP", "IPV4"})
		checks := map[string][]routeCheck{"inside": {{Method: "https_exit_country", Target: "https://geo.example.invalid/", ExpectedExitClass: intent}}}
		h, _ := privateAdaptiveNewHub(t, c, raw, checks, 2)
		h.Close()
		awaitPrivatePool(t, h.stopped)
	}
	for _, scenario := range []string{"pending", "stale", "group", "checks", "context", "mode", "invalid grace", "foreign hub"} {
		t.Run("receipt "+scenario, func(t *testing.T) {
			h, now := privateAdaptiveNewHub(t, c, metadata, plans, 2)
			r, e := h.prepareProbe(context.Background(), "inside", paths[0])
			if e != nil || r == nil {
				t.Fatal(e)
			}
			switch scenario {
			case "pending":
				if other, e := h.prepareProbe(context.Background(), "inside", paths[0]); other != nil || e != errPrivatePath || !h.discard(r) || h.discard(r) || h.commit(r, 1000) {
					t.Fatal("pending/discarded receipt lost its ownership boundary")
				}
				fresh, e := h.prepareProbe(context.Background(), "inside", paths[0])
				if e != nil || !h.commit(fresh, 1000) {
					t.Fatal("explicit discard prevented subsequent actual probing", e)
				}
				return
			case "stale":
				now.Add(15_001)
			case "group":
				r.group = "other"
			case "checks":
				r.proof.checksHash = strings.Repeat("0", 64)
			case "context":
				if !h.changeScope(strings.Repeat("b", 64), "WIFI") {
					t.Fatal("scope did not change")
				}
			case "mode":
				if h.changeScope(h.scope, "HOME_WIFI") || !h.changeScope(strings.Repeat("b", 64), "HOME_WIFI") {
					t.Fatal("mode change did not require a fresh full context")
				}
				if fresh, e := h.prepareProbe(context.Background(), "inside", paths[0]); fresh != nil || e != errPrivatePath {
					t.Fatal("path used an undeclared entry mode")
				}
			case "invalid grace":
				if h.commit(r, 999) || h.commit(r, 1000) {
					t.Fatal("failed commit attempt could be replayed")
				}
				return
			case "foreign hub":
				if (&privateAdaptiveHub{}).commit(r, 1000) || !h.commit(r, 1000) {
					t.Fatal("receipt borrowed or was consumed by a foreign hub")
				}
				return
			}
			if h.commit(r, 1000) {
				t.Fatal("wrong binding or stale receipt selected a route")
			}
			if conn, e := h.dialTCP("inside", context.Background(), "tcp", M.ParseSocksaddr(address)); conn != nil || e != errPrivatePath {
				t.Fatal("rejected receipt left data-path authority")
			}
		})
	}
}

func TestPrivateAdaptiveHubBoundedCacheRetainsActualOwnership(t *testing.T) {
	t.Run("thirty-two residents can evict and rediscover without dropping the active path", func(t *testing.T) {
		c, metadata, plans, paths, address := privateAdaptiveOneHopInputs(t, privateCandidateLimit+1)
		h, _ := privateAdaptiveNewHub(t, c, metadata, plans, privateCandidateLimit+2)
		for i := 0; i < privateCandidateLimit; i++ {
			r, e := h.prepareProbe(context.Background(), "inside", paths[i])
			if e != nil || r == nil {
				t.Fatal("bounded resident setup failed", e)
			}
			if i == 0 {
				if !h.commit(r, 1000) {
					t.Fatal("active resident not selected")
				}
			} else if !h.discard(r) {
				t.Fatal("idle resident not explicitly discarded")
			}
		}
		if s := h.pool.snapshot(); s.Entries != privateCandidateLimit || s.Dynamic != privateCandidateLimit {
			t.Fatal("resident bound or reservation count changed", s)
		}
		if r, e := h.prepareProbe(context.Background(), "inside", paths[privateCandidateLimit]); r != nil || e != errPrivatePath {
			t.Fatal("eviction request borrowed capacity before actual retirement")
		}
		awaitPrivatePool(t, func() bool { return h.pool.snapshot().Dynamic == privateCandidateLimit-1 })
		r, e := h.prepareProbe(context.Background(), "inside", paths[privateCandidateLimit])
		if e != nil || r == nil || !h.discard(r) {
			t.Fatal("idle cache pressure permanently prevented exploration", e)
		}
		active, e := h.dialTCP("inside", context.Background(), "tcp", M.ParseSocksaddr(address))
		if e != nil {
			t.Fatal("cache eviction retired an actively selected path", e)
		}
		privateAdaptiveEcho(t, active, "active-during-exploration")
		_ = active.Close()
	})
	t.Run("active and pending owners are not eviction candidates", func(t *testing.T) {
		c, metadata, plans, paths, address := privateAdaptiveOneHopInputs(t, 2)
		h, _ := privateAdaptiveNewHub(t, c, metadata, plans, 2)
		r, e := h.prepareProbe(context.Background(), "inside", paths[0])
		if e != nil {
			t.Fatal(e)
		}
		if other, e := h.prepareProbe(context.Background(), "inside", paths[1]); other != nil || e != errPrivatePath || !h.commit(r, 1000) {
			t.Fatal("pending owner was evicted under capacity pressure")
		}
		for i := 0; i < 5; i++ {
			if other, e := h.prepareProbe(context.Background(), "inside", paths[1]); other != nil || e != errPrivatePath {
				t.Fatal("full active capacity admitted another owner")
			}
		}
		active, e := h.dialTCP("inside", context.Background(), "tcp", M.ParseSocksaddr(address))
		if e != nil || h.pool.snapshot().Dynamic != 1 {
			t.Fatal("deferred exploration damaged its active route", e)
		}
		privateAdaptiveEcho(t, active, "active-under-full-capacity")
		_ = active.Close()
	})
	t.Run("blocked retirement keeps its capacity until actual close", func(t *testing.T) {
		c, metadata, plans, paths, _ := privateAdaptiveOneHopInputs(t, 2)
		h, _ := privateAdaptiveNewHub(t, c, metadata, plans, 2)
		entered, release := make(chan struct{}), make(chan struct{})
		var once sync.Once
		unblock := func() { once.Do(func() { close(release) }) }
		t.Cleanup(unblock)
		var calls atomic.Int32
		h.create = func(_ context.Context, _, tag, _ string) (adapter.Outbound, error) {
			calls.Add(1)
			return &privateAdaptiveBlockingClose{privateBlockingClose{tag: tag, entered: entered, release: release}}, nil
		}
		// The synthetic owner returns a normal negative dial result, leaving
		// one unselected resident whose later Close really blocks.
		r, e := h.prepareProbe(context.Background(), "inside", paths[0])
		if r != nil {
			t.Fatal("non-dialing synthetic owner gained a receipt")
		}
		requirePrivateCheckedFailure(t, e, "dial_failed")
		if r, e := h.prepareProbe(context.Background(), "inside", paths[1]); r != nil || e != errPrivatePath {
			t.Fatal("blocked retirement lent capacity")
		}
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			t.Fatal("cache eviction did not start owned retirement")
		}
		for i := 0; i < 5; i++ {
			if r, e := h.prepareProbe(context.Background(), "inside", paths[1]); r != nil || e != errPrivatePath {
				t.Fatal("blocked closer admitted a replacement constructor")
			}
		}
		if calls.Load() != 1 || h.pool.snapshot().Dynamic != 1 {
			t.Fatal("unconfirmed close lost its reservation")
		}
		h.Close()
		if h.stopped() {
			t.Fatal("close request was mistaken for actual owner exit")
		}
		unblock()
		awaitPrivatePool(t, h.stopped)
	})
}

func TestPrivateAdaptiveHubBusyAndStopRequireActualOwnerExit(t *testing.T) {
	for _, phase := range []string{"constructor", "probe"} {
		t.Run("cancelled blocked "+phase, func(t *testing.T) {
			c, metadata, plans, paths, _ := privateAdaptiveOneHopInputs(t, 1)
			h, _ := privateAdaptiveNewHub(t, c, metadata, plans, 2)
			entered, cancelled, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			t.Cleanup(unblock)
			var calls atomic.Int32
			h.create = func(ctx context.Context, _, tag, _ string) (adapter.Outbound, error) {
				calls.Add(1)
				if phase == "constructor" {
					close(entered)
					<-ctx.Done()
					close(cancelled)
					<-release
					return nil, errPrivatePath
				}
				return &privateTrafficTestNode{tag: tag, dial: func(ctx context.Context, _ string, _ M.Socksaddr) (net.Conn, error) {
					close(entered)
					<-ctx.Done()
					close(cancelled)
					<-release
					return nil, errPrivatePath
				}}, nil
			}
			go func() {
				defer close(done)
				if r, e := h.prepareProbe(context.Background(), "inside", paths[0]); r != nil || e != errPrivatePath {
					t.Error("cancelled blocked owner published a receipt")
				}
			}()
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("owned worker did not enter blocking phase")
			}
			if !h.changeScope(strings.Repeat("b", 64), "WIFI") {
				t.Fatal("scope did not withdraw blocked work")
			}
			select {
			case <-cancelled:
			case <-time.After(5 * time.Second):
				t.Fatal("scope cancellation did not reach the worker")
			}
			for i := 0; i < 10; i++ {
				if r, e := h.prepareProbe(context.Background(), "inside", paths[0]); r != nil || e != errPrivatePath {
					t.Fatal("cancelled blocked worker was replaced")
				}
			}
			h.Close()
			if calls.Load() != 1 || h.stopped() {
				t.Fatal("pending work was acknowledged as a stopped owner")
			}
			unblock()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("released worker did not actually exit")
			}
			awaitPrivatePool(t, h.stopped)
		})
	}
	t.Run("constructor panic requires process owner retirement", func(t *testing.T) {
		c, metadata, plans, paths, _ := privateAdaptiveOneHopInputs(t, 1)
		h, _ := privateAdaptiveNewHub(t, c, metadata, plans, 2)
		h.create = func(context.Context, string, string, string) (adapter.Outbound, error) {
			panic("synthetic unknown allocation")
		}
		if r, e := h.prepareProbe(context.Background(), "inside", paths[0]); r != nil || e != errPrivatePath {
			t.Fatal("unknown constructor allocation acquired authority")
		}
		h.Close()
		select {
		case <-h.pool.workerExited:
		case <-time.After(5 * time.Second):
			t.Fatal("retirement worker did not exit")
		}
		if s := h.pool.snapshot(); s.Retained != 1 || s.Dynamic != 1 || h.stopped() {
			t.Fatal("normal close acknowledged an unknown allocation", s)
		}
	})
}

func TestExpiredHomeProofBlocksNewAdaptiveTrafficAtTheActualNativeDial(t *testing.T) {
	requireAdaptiveModeExpiryAtActualDial(t, "HOME_WIFI")
}

func TestTemporaryWiFiModeExpiryClosesExistingAndNewNativeFlows(t *testing.T) {
	requireAdaptiveModeExpiryAtActualDial(t, "WIFI")
}

func requireAdaptiveModeExpiryAtActualDial(t *testing.T, mode string) {
	t.Helper()
	c, metadata, plans, paths, address := privateAdaptiveOneHopInputs(t, 1)
	var graph map[string]json.RawMessage
	if err := json.Unmarshal(metadata, &graph); err != nil {
		t.Fatal(err)
	}
	var hops []map[string]any
	if err := json.Unmarshal(graph["hops"], &hops); err != nil {
		t.Fatal(err)
	}
	for _, hop := range hops {
		hop["entryModes"] = []string{mode}
	}
	graph["hops"] = privateAdaptiveMarshal(t, hops)
	h, clock := privateAdaptiveNewHub(t, c, privateAdaptiveMarshal(t, graph), plans, 4)
	scope := strings.Repeat("b", 64)
	if !h.changeScope(scope, mode) {
		t.Fatal("scope not replaced")
	}
	until := clock.Load() + 15_000
	if h.setModeDeadline(scope, mode, clock.Load()+180_001) || h.setModeDeadline(scope, mode, clock.Load()) ||
		h.setModeDeadline(strings.Repeat("c", 64), mode, until) {
		t.Fatal("invalid home proof accepted")
	}
	if mode == "HOME_WIFI" {
		if result, e := h.prepareProbe(context.Background(), "inside", paths[0]); result != nil || e != errPrivatePath {
			t.Fatal("unauthorized home probe")
		}
	}
	if !h.setModeDeadline(scope, mode, until) {
		t.Fatal("fresh home proof not applied")
	}
	if h.setModeDeadline(scope, mode, 0) {
		t.Fatal("active time limit removed in the same scope")
	}
	receipt, err := h.prepareProbe(context.Background(), "inside", paths[0])
	if err != nil || !h.commit(receipt, 1000) {
		t.Fatal("route did not pass", err)
	}
	conn, err := h.dialTCP("inside", context.Background(), "tcp", M.ParseSocksaddr(address))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	privateAdaptiveEcho(t, conn, "verified-home")
	// Renewing on the same physical scope keeps a live TCP connection usable.
	oldUntil := until
	until += 1000
	if !h.setModeDeadline(scope, mode, until) {
		t.Fatal("valid renewal refused")
	}
	clock.Store(oldUntil)
	h.expireMode(scope, oldUntil)
	privateAdaptiveEcho(t, conn, "still-authorized")
	blocked, err := h.dialTCP("inside", context.Background(), "tcp", M.ParseSocksaddr(address))
	if err != nil {
		t.Fatal(err)
	}
	defer blocked.Close()
	result := make(chan error, 1)
	go func() { var buf [1]byte; _, err := blocked.Read(buf[:]); result <- err }()
	clock.Store(until)
	if n, err := conn.Write([]byte("expired")); n != 0 || err != errPrivatePath {
		t.Fatal("established home flow still writable", n, err)
	}
	h.expireMode(scope, until)
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("expired read delivered data")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("blocked home read survived shared expiry")
	}
	if h.setModeDeadline(scope, mode, until+1000) {
		t.Fatal("expired proof revived the previous selection")
	}
	if conn, e := h.dialTCP("inside", context.Background(), "tcp", M.ParseSocksaddr(address)); conn != nil || e != errPrivatePath {
		t.Fatal("expired home route served a new connection")
	}
	if got, e := h.prepareProbe(context.Background(), "inside", paths[0]); got != nil || e != errPrivatePath {
		t.Fatal("expired home proof earned route evidence")
	}
}
