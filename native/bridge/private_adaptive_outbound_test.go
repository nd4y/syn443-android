package bridge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	boxservice "github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/direct"
	proxyhttp "github.com/sagernet/sing-box/protocol/http"
	"github.com/sagernet/sing-box/protocol/socks"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
)

func privateAdaptiveOutboundContext(t *testing.T) context.Context {
	t.Helper()
	or := outbound.NewRegistry()
	direct.RegisterOutbound(or)
	proxyhttp.RegisterOutbound(or)
	socks.RegisterOutbound(or)
	registerPrivateAdaptiveOutbound(or)
	dr := dns.NewTransportRegistry()
	registerPhysicalDNS(dr, dnsProtector{exchange: func([]byte) ([]byte, error) {
		t.Error("IP-only adaptive outbound fixture attempted DNS")
		return nil, errors.New("unexpected fixture DNS")
	}})
	registerRemoteDNS(dr)
	return service.ContextWithDefaultRegistry(box.Context(context.Background(), inbound.NewRegistry(), or,
		endpoint.NewRegistry(), dr, boxservice.NewRegistry()))
}

func privateAdaptiveOutboundBox(t *testing.T, r *privateAdaptiveReference, nodes []map[string]any) *box.Box {
	t.Helper()
	raw, e := json.Marshal(map[string]any{"log": map[string]any{"disabled": true}, "outbounds": nodes,
		"route": map[string]any{"final": "managed"}})
	if e != nil {
		t.Fatal(e)
	}
	var options option.Options
	if e = options.UnmarshalJSONContext(r.ctx, raw); e != nil {
		t.Fatal(e)
	}
	instance, e := box.New(box.Options{Context: r.ctx, Options: options})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { r.Close(); _ = instance.Close() })
	return instance
}

func privateAdaptiveOutboundFixture(t *testing.T, bindings map[string]string, nodes []map[string]any) (*privateAdaptiveReference, *box.Box) {
	t.Helper()
	r, e := newPrivateAdaptiveReference(privateAdaptiveOutboundContext(t), bindings)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(r.Close)
	if nodes == nil {
		nodes = []map[string]any{{"type": privateAdaptiveOutboundType, "tag": "managed", "group": "inside"}, {"type": "direct", "tag": "existing"}}
	}
	return r, privateAdaptiveOutboundBox(t, r, nodes)
}

func privateAdaptiveOutboundCatalogue(t *testing.T, ctx context.Context, router adapter.Router, nodes map[string]map[string]any) *privatePathCatalogue {
	t.Helper()
	raw := make(map[string]json.RawMessage, len(nodes))
	for id, node := range nodes {
		value, e := json.Marshal(node)
		if e != nil {
			t.Fatal(e)
		}
		raw[id] = value
	}
	c, e := newPrivatePathCatalogue(ctx, router, raw)
	if e != nil {
		t.Fatal(e)
	}
	return c
}

func privateAdaptiveOutboundNode(t *testing.T, instance *box.Box, tag string) *privateAdaptiveOutbound {
	t.Helper()
	node, ok := instance.Outbound().Outbound(tag)
	if !ok {
		t.Fatal("adaptive box did not register the configured tag")
	}
	managed, ok := node.(*privateAdaptiveOutbound)
	if !ok {
		t.Fatal("configured tag is not an actual adaptive adapter")
	}
	return managed
}

func TestPrivateAdaptiveOutboundRealBoxTwoHopSwitchAndNoFallback(t *testing.T) {
	target := listenWire(t, func(c net.Conn) { _, _ = io.Copy(c, c) })
	address := target.listener.Addr().String()
	exitA, exitB := httpWire(t, address, "", ""), httpWire(t, address, "", "")
	entryA, entryB := socksWire(t, exitA.listener.Addr().String()), socksWire(t, exitB.listener.Addr().String())
	bindings := map[string]string{"managed": "inside"}
	r, e := newPrivateAdaptiveReference(privateAdaptiveOutboundContext(t), bindings)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(r.Close)
	bindings["managed"] = "changed-input"
	instance := privateAdaptiveOutboundBox(t, r, []map[string]any{{"type": privateAdaptiveOutboundType, "tag": "managed", "group": "inside"}, {"type": "direct", "tag": "existing"}})
	node := privateAdaptiveOutboundNode(t, instance, "managed")
	if node.Start(adapter.StartStateInitialize) != errPrivatePath {
		t.Fatal("uninitialized reference passed lifecycle readiness")
	}
	if conn, e := node.DialContext(context.Background(), "tcp", M.ParseSocksaddr(address)); conn != nil || e != errPrivatePath {
		t.Fatal("uninitialized reference borrowed the configured direct outbound")
	}
	catalogue := privateAdaptiveOutboundCatalogue(t, r.ctx, instance.Router(), map[string]map[string]any{
		"a1": entryA.node("socks", "a1"), "a2": exitA.node("http", "a2"),
		"b1": entryB.node("socks", "b1"), "b2": exitB.node("http", "b2"),
	})
	a, b := []string{"a1", "a2"}, []string{"b1", "b2"}
	metadata := privateAdaptiveMetadata(t, [][]string{a, b}, "INTERNAL", []string{"TCP", "IPV4"})
	h, _ := privateAdaptiveNewHub(t, catalogue, metadata, map[string][]routeCheck{"inside": {{Method: "tcp", Target: address}}}, 6)
	if !r.initialize(h) || r.initialize(h) {
		t.Fatal("exact owner could not initialize once")
	}
	if e := instance.Start(); e != nil {
		t.Fatal("actual box could not start an initialized managed outbound", e)
	}
	if instance.Outbound().Default() != node || !slices.Equal(node.Network(), []string{"tcp"}) || len(node.Dependencies()) != 0 {
		t.Fatal("registered adapter used an unintended default, network or parent dependency")
	}
	networks := node.Network()
	networks[0] = "udp"
	if !slices.Equal(node.Network(), []string{"tcp"}) {
		t.Fatal("borrowed network metadata changed the TCP-only adapter")
	}
	if conn, e := instance.Outbound().Default().DialContext(context.Background(), "tcp", M.ParseSocksaddr(address)); conn != nil || e != errPrivatePath {
		t.Fatal("unverified managed default silently fell back to direct")
	}
	proof, e := h.prepareProbe(context.Background(), "inside", a)
	if e != nil || !h.commit(proof, 1000) {
		t.Fatal("first real chain could not be committed", e)
	}
	old, e := instance.Outbound().Default().DialContext(context.Background(), "tcp", M.ParseSocksaddr(address))
	if e != nil {
		t.Fatal(e)
	}
	defer old.Close()
	privateAdaptiveEcho(t, old, "registered-first-chain")
	beforeA := entryA.calls.Load()
	proof, e = h.prepareProbe(context.Background(), "inside", b)
	if e != nil || proof == nil {
		t.Fatal("second actual chain did not produce fresh evidence", e)
	}
	beforeCommit, e := node.DialContext(context.Background(), "tcp4", M.ParseSocksaddr(address))
	if e != nil {
		t.Fatal(e)
	}
	privateAdaptiveEcho(t, beforeCommit, "registered-still-first")
	_ = beforeCommit.Close()
	if entryA.calls.Load() <= beforeA || !h.commit(proof, 1000) {
		t.Fatal("probing switched an actual manager outbound without explicit commit")
	}
	privateAdaptiveEcho(t, old, "registered-old-flow-drains")
	current, e := instance.Outbound().Default().DialContext(context.Background(), "tcp", M.ParseSocksaddr(address))
	if e != nil {
		t.Fatal(e)
	}
	defer current.Close()
	privateAdaptiveEcho(t, current, "registered-second-chain")
	if entryA.calls.Load() == 0 || exitA.calls.Load() == 0 || entryB.calls.Load() == 0 || exitB.calls.Load() == 0 {
		t.Fatal("registered data path bypassed a declared real SOCKS or HTTP hop")
	}
	if packet, e := node.ListenPacket(context.Background(), M.ParseSocksaddr(address)); packet != nil || e != errPrivatePath {
		t.Fatal("TCP-only managed adapter exposed UDP")
	}
	if conn, e := node.DialContext(context.Background(), "udp", M.ParseSocksaddr(address)); conn != nil || e != errPrivatePath {
		t.Fatal("wrong-network Dial acquired data-path authority")
	}
	for _, value := range []any{r, node} {
		if raw := fmt.Sprintf("%v %#v", value, value); strings.Contains(raw, address) || strings.Contains(raw, h.scope) {
			t.Fatal("reference diagnostics exposed private context or endpoint")
		}
	}
	if !h.changeScope(strings.Repeat("b", 64), "WIFI") {
		t.Fatal("actual runtime scope did not change")
	}
	if conn, e := node.DialContext(context.Background(), "tcp", M.ParseSocksaddr(address)); conn != nil || e != errPrivatePath {
		t.Fatal("configured managed outbound borrowed the previous context's selection")
	}
	r.Close()
	if node.Start(adapter.StartStateStarted) != errPrivatePath {
		t.Fatal("closed reference passed readiness")
	}
	if conn, e := node.DialContext(context.Background(), "tcp", M.ParseSocksaddr(address)); conn != nil || e != errPrivatePath {
		t.Fatal("stale managed adapter survived reference revocation")
	}
	_ = old.Close()
	_ = current.Close()
	awaitPrivatePool(t, r.stopped)
}

func TestPrivateAdaptiveOutboundReferenceBindingAndInitialization(t *testing.T) {
	parent := privateAdaptiveOutboundContext(t)
	for _, bindings := range []map[string]string{nil, {}, {"": "inside"}, {"managed": ""}, {"bad/tag": "inside"}, {"one": "inside", "two": "inside"}} {
		if r, e := newPrivateAdaptiveReference(parent, bindings); r != nil || e != errPrivatePath {
			t.Fatal("invalid or aliased reference binding admitted")
		}
	}
	bindings := map[string]string{}
	for i := 0; i < privateGroupLimit; i++ {
		bindings[fmt.Sprintf("tag%02d", i)] = fmt.Sprintf("group%02d", i)
	}
	r, e := newPrivateAdaptiveReference(parent, bindings)
	if e != nil || r == nil || r.registry == service.RegistryFromContext(parent) {
		t.Fatal("bounded reference did not own an isolated registry", e)
	}
	r.Close()
	if !r.stopped() {
		t.Fatal("empty closed reference retained an imaginary owner")
	}
	bindings["overflow"] = "overflow"
	if r, e := newPrivateAdaptiveReference(parent, bindings); r != nil || e != errPrivatePath {
		t.Fatal("seventeenth reference binding admitted")
	}
	for _, invalid := range []context.Context{nil, context.Background(), r.ctx} {
		if next, e := newPrivateAdaptiveReference(invalid, map[string]string{"managed": "inside"}); next != nil || e != errPrivatePath {
			t.Fatal("missing, closed or borrowed context created a reference")
		}
	}
	target := listenWire(t, func(c net.Conn) { _, _ = io.Copy(c, c) })
	address := target.listener.Addr().String()
	proxy := httpWire(t, address, "", "")
	nodes := map[string]map[string]any{"only": proxy.node("http", "only")}
	paths := [][]string{{"only"}}
	metadata := privateAdaptiveMetadata(t, paths, "INTERNAL", []string{"TCP", "IPV4"})
	plans := map[string][]routeCheck{"inside": {{Method: "tcp", Target: address}}}
	for _, scenario := range []string{"foreign catalogue", "cloned context", "foreign marker", "foreign router", "wrong groups", "missing managed tag", "substituted catalogue", "closed pool"} {
		t.Run(scenario, func(t *testing.T) {
			bindings := map[string]string{"managed": "inside"}
			if scenario == "missing managed tag" {
				bindings["missing"] = "other"
			}
			r, instance := privateAdaptiveOutboundFixture(t, bindings, nil)
			ctx, router, raw := r.ctx, instance.Router(), metadata
			checks := plans
			switch scenario {
			case "foreign catalogue":
				_, ctx = wireNetworkBox(t, nil, []map[string]any{{"type": "direct", "tag": "foreign"}}, nil)
				router = service.FromContext[adapter.Router](ctx)
			case "cloned context":
				ctx = service.ExtendContext(ctx)
			case "foreign marker":
				foreign, e := newPrivateAdaptiveReference(parent, map[string]string{"managed": "inside"})
				if e != nil {
					t.Fatal(e)
				}
				t.Cleanup(foreign.Close)
				ctx = context.WithValue(ctx, privateAdaptiveReferenceKey{}, foreign)
			case "foreign router":
				foreign, _ := wireNetworkBox(t, nil, []map[string]any{{"type": "direct", "tag": "foreign"}}, nil)
				router = foreign.Router()
			case "wrong groups":
				raw = []byte(strings.ReplaceAll(string(metadata), "inside", "other"))
				checks = map[string][]routeCheck{"other": plans["inside"]}
			}
			catalogue := privateAdaptiveOutboundCatalogue(t, ctx, router, nodes)
			h, _ := privateAdaptiveNewHub(t, catalogue, raw, checks, 3)
			if scenario == "substituted catalogue" {
				h.catalogue = privateAdaptiveOutboundCatalogue(t, r.ctx, instance.Router(), nodes)
			} else if scenario == "closed pool" {
				h.pool.Close()
			}
			if r.initialize(h) || h.closed {
				t.Fatal("initialization borrowed or retired an unrelated hub")
			}
			if scenario != "missing managed tag" {
				// A rejected handoff cannot poison the one later valid handoff.
				validCatalogue := privateAdaptiveOutboundCatalogue(t, r.ctx, instance.Router(), nodes)
				valid, _ := privateAdaptiveNewHub(t, validCatalogue, metadata, plans, 3)
				if !r.initialize(valid) {
					t.Fatal("rejected foreign handoff prevented valid initialization")
				}
			}
		})
	}
}

func TestPrivateAdaptiveOutboundRejectsForeignFactoriesAndClosedOptions(t *testing.T) {
	for _, raw := range [][]byte{
		[]byte(`{}`), []byte(`null`), []byte(`[]`),
		[]byte(`{"Group":"inside"}`), []byte(`{"group":null}`), []byte(`{"group":123}`), []byte(`{"group":true}`),
		[]byte(`{"group":""}`), []byte(`{"group":"inside","group":"other"}`),
		[]byte(`{"group":"inside","\u0067roup":"inside"}`),
		[]byte(`{"group":"inside","detour":"existing"}`), []byte(`{"group":"inside"} {}`),
		[]byte("{\"group\":\"in\xffside\"}"), []byte(strings.Repeat(" ", 2049)),
	} {
		options := privateAdaptiveOutboundOptions{Group: "previous"}
		if e := json.Unmarshal(raw, &options); e == nil {
			t.Fatal("closed typed group parser accepted malformed or substituted input")
		}
		// The encoding/json entry point rejects malformed bytes before calling
		// UnmarshalJSON, so separately require the native method to clear stale state.
		if e := options.UnmarshalJSON(raw); e == nil || options.Group != "" {
			t.Fatal("native typed option parser retained stale group authority")
		}
	}
	var valid privateAdaptiveOutboundOptions
	if e := json.Unmarshal([]byte(`{"group":"inside"}`), &valid); e != nil || valid.Group != "inside" {
		t.Fatal("valid exact typed group did not parse", e)
	}
	r, instance := privateAdaptiveOutboundFixture(t, map[string]string{"managed": "inside"}, nil)
	actual := privateAdaptiveOutboundNode(t, instance, "managed")
	logger := log.NewNOPFactory().Logger()
	for _, scenario := range []string{"missing marker", "cloned registry", "foreign router", "unknown tag", "wrong group", "duplicate adapter"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, router, tag, group := r.ctx, instance.Router(), "managed", "inside"
			switch scenario {
			case "missing marker":
				ctx = context.WithValue(ctx, privateAdaptiveReferenceKey{}, nil)
			case "cloned registry":
				ctx = service.ExtendContext(ctx)
			case "foreign router":
				foreign, _ := wireNetworkBox(t, nil, []map[string]any{{"type": "direct", "tag": "foreign"}}, nil)
				router = foreign.Router()
			case "unknown tag":
				tag = "undeclared"
			case "wrong group":
				group = "other"
			}
			if node, e := newPrivateAdaptiveOutbound(ctx, router, logger, tag, privateAdaptiveOutboundOptions{Group: group}); node != nil || e != errPrivatePath {
				t.Fatal("foreign, substituted or duplicate constructor admitted")
			}
		})
	}
	for _, raw := range []string{
		`{"type":"syn443-adaptive","tag":"managed","group":"inside","detour":"existing"}`,
		`{"type":"syn443-adaptive","tag":"managed","group":"inside","server":"127.0.0.1"}`,
		`{"type":"syn443-adaptive","tag":"managed","group":"inside","network":"udp"}`,
		`{"type":"syn443-adaptive","tag":"managed","group":123}`,
	} {
		var options option.Outbound
		if e := options.UnmarshalJSONContext(r.ctx, []byte(raw)); e == nil {
			t.Fatal("adaptive typed options accepted an extra field or coerced group")
		}
	}
	if next, e := newPrivateAdaptiveReference(r.ctx, map[string]string{"managed": "inside"}); next != nil || e != errPrivatePath {
		t.Fatal("constructed runtime was borrowed by a replacement reference")
	}
	if e := instance.Outbound().Remove("managed"); e != nil {
		t.Fatal(e)
	}
	target := listenWire(t, func(c net.Conn) { _, _ = io.Copy(c, c) })
	address := target.listener.Addr().String()
	proxy := httpWire(t, address, "", "")
	c := privateAdaptiveOutboundCatalogue(t, r.ctx, instance.Router(), map[string]map[string]any{"only": proxy.node("http", "only")})
	h, _ := privateAdaptiveNewHub(t, c, privateAdaptiveMetadata(t, [][]string{{"only"}}, "INTERNAL", []string{"TCP", "IPV4"}), map[string][]routeCheck{"inside": {{Method: "tcp", Target: address}}}, 3)
	if r.initialize(h) {
		t.Fatal("initialization ignored actual manager membership")
	}
	if conn, e := actual.DialContext(context.Background(), "tcp", M.ParseSocksaddr(address)); conn != nil || e != errPrivatePath {
		t.Fatal("removed adapter borrowed its manager's replacement default")
	}
	forged := &privateAdaptiveOutbound{Adapter: outbound.NewAdapter(privateAdaptiveOutboundType, "managed", []string{"tcp"}, nil), ctx: r.ctx, ref: r, group: "inside"}
	if forged.Start(adapter.StartStateInitialize) != errPrivatePath {
		t.Fatal("unowned forged adapter passed lifecycle readiness")
	}
	r.Close()
	if node, e := newPrivateAdaptiveOutbound(r.ctx, instance.Router(), logger, "managed", privateAdaptiveOutboundOptions{Group: "inside"}); node != nil || e != errPrivatePath {
		t.Fatal("closed reference admitted a replacement adapter")
	}
}

func TestPrivateAdaptiveOutboundStopRequiresActualHubRetirement(t *testing.T) {
	for _, scenario := range []string{"blocked constructor", "unknown constructor allocation", "manager replacement", "closed hub", "closed pool", "expired lease"} {
		t.Run(scenario, func(t *testing.T) {
			r, instance := privateAdaptiveOutboundFixture(t, map[string]string{"managed": "inside"}, nil)
			node := privateAdaptiveOutboundNode(t, instance, "managed")
			target := listenWire(t, func(c net.Conn) { _, _ = io.Copy(c, c) })
			address := target.listener.Addr().String()
			proxy := httpWire(t, address, "", "")
			c := privateAdaptiveOutboundCatalogue(t, r.ctx, instance.Router(), map[string]map[string]any{"only": proxy.node("http", "only")})
			h, _ := privateAdaptiveNewHub(t, c, privateAdaptiveMetadata(t, [][]string{{"only"}}, "INTERNAL", []string{"TCP", "IPV4"}), map[string][]routeCheck{"inside": {{Method: "tcp", Target: address}}}, 3)
			if !r.initialize(h) {
				t.Fatal("actual hub did not initialize")
			}
			if e := instance.Start(); e != nil {
				t.Fatal(e)
			}
			if r.stopped() {
				t.Fatal("live reference reported stopped")
			}
			switch scenario {
			case "closed hub", "closed pool", "expired lease":
				switch scenario {
				case "closed hub":
					h.Close()
				case "closed pool":
					h.pool.Close()
				case "expired lease":
					if e := h.pool.lease.set(h.pool.lease.clock() - 1); e != nil {
						t.Fatal(e)
					}
				}
				if node.Start(adapter.StartStateStarted) != errPrivatePath {
					t.Fatal("closed or expired actual hub passed lifecycle readiness")
				}
				if conn, e := node.DialContext(context.Background(), "tcp", M.ParseSocksaddr(address)); conn != nil || e != errPrivatePath {
					t.Fatal("closed or expired hub exposed a data path")
				}
				r.Close()
				awaitPrivatePool(t, r.stopped)
			case "blocked constructor":
				entered, cancelled, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
				var once sync.Once
				unblock := func() { once.Do(func() { close(release) }) }
				t.Cleanup(unblock)
				h.create = func(ctx context.Context, _, _, _ string) (adapter.Outbound, error) {
					close(entered)
					<-ctx.Done()
					close(cancelled)
					<-release
					return nil, errPrivatePath
				}
				go func() {
					defer close(done)
					if receipt, e := h.prepareProbe(context.Background(), "inside", []string{"only"}); receipt != nil || e != errPrivatePath {
						t.Error("revoked blocked owner published a receipt")
					}
				}()
				select {
				case <-entered:
				case <-time.After(5 * time.Second):
					t.Fatal("owned constructor did not enter")
				}
				r.Close()
				select {
				case <-cancelled:
				case <-time.After(5 * time.Second):
					t.Fatal("reference close did not revoke its worker context")
				}
				if e := instance.Close(); e != nil {
					t.Fatal(e)
				}
				if r.stopped() || h.pool.snapshot().Dynamic != 1 {
					t.Fatal("box.Close acknowledgment released a still-running owner")
				}
				unblock()
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					t.Fatal("released owner did not actually exit")
				}
				awaitPrivatePool(t, r.stopped)
			case "unknown constructor allocation":
				h.create = func(context.Context, string, string, string) (adapter.Outbound, error) {
					panic("synthetic unknown allocation")
				}
				if receipt, e := h.prepareProbe(context.Background(), "inside", []string{"only"}); receipt != nil || e != errPrivatePath {
					t.Fatal("unknown allocation acquired authority")
				}
				r.Close()
				if e := instance.Close(); e != nil {
					t.Fatal(e)
				}
				select {
				case <-h.pool.workerExited:
				case <-time.After(5 * time.Second):
					t.Fatal("retirement worker did not exit")
				}
				if r.stopped() || h.pool.snapshot().Retained != 1 {
					t.Fatal("normal box close confirmed an unknown allocation")
				}
			case "manager replacement":
				receipt, e := h.prepareProbe(context.Background(), "inside", []string{"only"})
				if e != nil || !h.commit(receipt, 1000) {
					t.Fatal(e)
				}
				flow, e := node.DialContext(context.Background(), "tcp", M.ParseSocksaddr(address))
				if e != nil {
					t.Fatal(e)
				}
				defer flow.Close()
				privateAdaptiveEcho(t, flow, "before-manager-replacement")
				if e := instance.Outbound().Create(r.ctx, instance.Router(), log.NewNOPFactory().Logger(), "managed", "direct", &option.DirectOutboundOptions{}); e != nil {
					t.Fatal(e)
				}
				if n, e := flow.Write([]byte("revoked-flow")); n != 0 || e != errPrivatePath {
					t.Fatal("manager replacement left the old flow authorized")
				}
				if conn, e := node.DialContext(context.Background(), "tcp", M.ParseSocksaddr(address)); conn != nil || e != errPrivatePath {
					t.Fatal("stale adapter borrowed the direct replacement")
				}
				_ = flow.Close()
				awaitPrivatePool(t, r.stopped)
			}
		})
	}
	t.Run("closing one adapter revokes every bound group", func(t *testing.T) {
		r, instance := privateAdaptiveOutboundFixture(t, map[string]string{"managed": "inside", "second": "other"}, []map[string]any{
			{"type": privateAdaptiveOutboundType, "tag": "managed", "group": "inside"},
			{"type": privateAdaptiveOutboundType, "tag": "second", "group": "other"},
			{"type": "direct", "tag": "existing"},
		})
		first, second := privateAdaptiveOutboundNode(t, instance, "managed"), privateAdaptiveOutboundNode(t, instance, "second")
		target := listenWire(t, func(c net.Conn) { _, _ = io.Copy(c, c) })
		address := target.listener.Addr().String()
		proxy := httpWire(t, address, "", "")
		c := privateAdaptiveOutboundCatalogue(t, r.ctx, instance.Router(), map[string]map[string]any{"only": proxy.node("http", "only")})
		raw := privateAdaptiveMetadata(t, [][]string{{"only"}}, "INTERNAL", []string{"TCP", "IPV4"})
		var graph map[string]any
		if e := json.Unmarshal(raw, &graph); e != nil {
			t.Fatal(e)
		}
		graph["groups"] = append(graph["groups"].([]any), map[string]any{"id": "other", "intent": "INTERNAL", "features": []string{"TCP", "IPV4"}, "templates": []string{"t0"}})
		raw, e := json.Marshal(graph)
		if e != nil {
			t.Fatal(e)
		}
		h, _ := privateAdaptiveNewHub(t, c, raw, map[string][]routeCheck{
			"inside": {{Method: "tcp", Target: address}}, "other": {{Method: "tcp", Target: address}},
		}, 4)
		if !r.initialize(h) {
			t.Fatal("exact two-group ownership did not initialize")
		}
		if e := instance.Start(); e != nil {
			t.Fatal(e)
		}
		for _, group := range []string{"inside", "other"} {
			receipt, e := h.prepareProbe(context.Background(), group, []string{"only"})
			if e != nil || !h.commit(receipt, 1000) {
				t.Fatal("group could not select its independently checked path", e)
			}
		}
		flow, e := second.DialContext(context.Background(), "tcp", M.ParseSocksaddr(address))
		if e != nil {
			t.Fatal(e)
		}
		defer flow.Close()
		privateAdaptiveEcho(t, flow, "second-group-real-payload")
		if e := first.Close(); e != nil {
			t.Fatal(e)
		}
		if n, e := flow.Write([]byte("revoked-other-group")); n != 0 || e != errPrivatePath {
			t.Fatal("closing one adapter left a different group's flow authorized")
		}
		if conn, e := second.DialContext(context.Background(), "tcp", M.ParseSocksaddr(address)); conn != nil || e != errPrivatePath {
			t.Fatal("another group survived whole-reference revocation")
		}
		_ = flow.Close()
		awaitPrivatePool(t, r.stopped)
	})
}
