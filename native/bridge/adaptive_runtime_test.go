package bridge

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
)

func adaptiveRuntimeTestConfig(t *testing.T, count int) ([]byte, []byte, string) {
	t.Helper()
	graph, catalogue, groups := privateAdaptiveWireFixture(t, count)
	wire := privateAdaptiveEncode(t, graph, catalogue, groups)
	config := privateAdaptiveMarshal(t, map[string]any{
		"adaptive_routes": json.RawMessage(wire),
		"outbounds":       []any{map[string]any{"type": "direct", "tag": "existing"}, map[string]any{"type": privateAdaptiveOutboundType, "tag": "managed-inside", "group": "inside"}},
		"route":           map[string]any{"final": "managed-inside"},
		"route_checks":    []any{map[string]any{"outbound": "managed-inside", "required": true, "checks": []any{map[string]any{"method": "tcp", "target": "192.0.2.9:443"}}}},
	})
	control := string(privateAdaptiveMarshal(t, map[string]any{"schemaVersion": 1, "scope": strings.Repeat("b", 64), "mode": "WIFI"}))
	return config, wire, control
}
func rejectAdaptiveRuntimeConfig(t *testing.T, raw []byte, control string) {
	t.Helper()
	if clean, input, e := adaptiveRuntimeConfig(string(raw), control); clean != nil || input != nil || e != errPrivatePath {
		t.Fatal("invalid adaptive rendered config acquired partial runtime data")
	}
}
func adaptiveRuntimeCommand(t *testing.T, r *Runtime, value map[string]any) bool {
	t.Helper()
	return r.AdaptiveCommand(string(privateAdaptiveMarshal(t, value)))
}

func TestAdaptiveRuntimePreflightRetainsClosedWireAndWholeRenderedBounds(t *testing.T) {
	for _, count := range []int{1, 500} {
		raw, _, control := adaptiveRuntimeTestConfig(t, count)
		clean, input, e := adaptiveRuntimeConfig(string(raw), control)
		if e != nil || input == nil || len(input.wire.catalogue) != count || input.scope != strings.Repeat("b", 64) || input.mode != "WIFI" || len(input.plans["inside"]) != 1 {
			t.Fatal("valid exact catalogue/check handoff rejected", e)
		}
		root := privateAdaptiveObject(t, clean)
		if _, present := root["adaptive_routes"]; present {
			t.Fatal("private extension escaped into upstream SDK options")
		}
		if _, present := root["route_checks"]; present {
			t.Fatal("application probes escaped into upstream SDK options")
		}
		if count == 500 && input.wire.catalogue["hop-499"] == nil {
			t.Fatal("preflight truncated the last candidate")
		}
	}
	raw, wire, control := adaptiveRuntimeTestConfig(t, 1)
	for _, mutated := range [][]byte{
		bytes.Replace(raw, []byte(`"outbounds":`), []byte(`"outbounds":null,"\u006futbounds":`), 1),
		bytes.Replace(raw, []byte(`"schemaVersion":1`), []byte(`"schemaVersion":1.0`), 1),
		bytes.Replace(raw, []byte(`"schemaVersion":1`), []byte(`"schemaVersion":"1"`), 1),
		bytes.Replace(raw, []byte(`"schemaVersion":1`), []byte(`"schemaVersion":1,"\u0073chemaVersion":1`), 1),
		bytes.Replace(raw, []byte(`"inside"`), []byte("\"in\xffside\""), 1),
		append(append([]byte(nil), raw...), []byte("null")...),
	} {
		rejectAdaptiveRuntimeConfig(t, mutated, control)
	}
	for _, badControl := range []string{"", `null`, strings.Replace(control, `"schemaVersion":1`, `"schemaVersion":1.0`, 1), strings.Replace(control, `"scope"`, `"Scope"`, 1), strings.Replace(control, `"mode":"WIFI"`, `"mode":null`, 1), strings.Replace(control, `"schemaVersion":1`, `"schemaVersion":1,"schemaVersion":1`, 1)} {
		rejectAdaptiveRuntimeConfig(t, raw, badControl)
	}
	for _, name := range []string{"wire-null", "wire-case", "wire-base64", "duplicate-tag", "missing-managed", "managed-extra", "missing-checks", "foreign-check-field", "foreign-method-predicate", "null-required", "failover", "urltest", "hidden-netbird"} {
		t.Run(name, func(t *testing.T) {
			root := privateAdaptiveObject(t, raw)
			nodes := root["outbounds"].([]any)
			managed := nodes[1].(map[string]any)
			checks := root["route_checks"].([]any)
			plan := checks[0].(map[string]any)
			predicate := plan["checks"].([]any)[0].(map[string]any)
			switch name {
			case "wire-null":
				root["adaptive_routes"] = nil
			case "wire-case":
				w := root["adaptive_routes"].(map[string]any)
				w["GraphB64"] = w["graphB64"]
				delete(w, "graphB64")
			case "wire-base64":
				w := root["adaptive_routes"].(map[string]any)
				w["graphB64"] = w["graphB64"].(string) + "\n"
			case "duplicate-tag":
				root["outbounds"] = append(nodes, map[string]any{"type": "direct", "tag": "managed-inside"})
			case "missing-managed":
				root["outbounds"] = nodes[:1]
			case "managed-extra":
				managed["detour"] = "existing"
			case "missing-checks":
				root["route_checks"] = []any{}
			case "foreign-check-field":
				plan["ignored"] = false
			case "foreign-method-predicate":
				predicate["expected_exit_class"] = ""
			case "null-required":
				plan["required"] = nil
			case "failover":
				root["route_failover"] = map[string]any{}
			case "urltest":
				root["outbounds"] = append(nodes, map[string]any{"type": "urltest", "tag": "automatic", "outbounds": []string{"existing"}})
			case "hidden-netbird":
				root["outbounds"] = append(nodes, map[string]any{"type": "vless", "tag": "underlay", "detour": "managed-inside"}, map[string]any{"type": "netbird", "tag": "overlay", "detour": "underlay"})
			}
			rejectAdaptiveRuntimeConfig(t, privateAdaptiveMarshal(t, root), control)
		})
	}
	// This larger limit applies only after the local renderer adds TUN options;
	// the assigned engine's262144-byte guard remains a separate policy boundary.
	maxRendered := append(append([]byte(nil), raw...), bytes.Repeat([]byte{' '}, 524288-len(raw))...)
	if _, _, e := adaptiveRuntimeConfig(string(maxRendered), control); e != nil {
		t.Fatal("exact rendered byte boundary rejected", e)
	}
	rejectAdaptiveRuntimeConfig(t, append(maxRendered, ' '), control)
	// Count the literal extension bytes before canonicalization can discard
	// padding. A small semantic object cannot hide an oversized wire field.
	paddedWire := append(append(append([]byte(nil), wire[:len(wire)-1]...), bytes.Repeat([]byte{' '}, privateAdaptiveWireLimit+1-len(wire))...), '}')
	oversizedWire := bytes.Replace(raw, wire, paddedWire, 1)
	rejectAdaptiveRuntimeConfig(t, oversizedWire, control)
	legacy := `{"outbounds":[{"type":"direct","tag":"existing"}]}`
	if clean, input, e := adaptiveRuntimeConfig(legacy, ""); e != nil || input != nil || string(clean) != legacy {
		t.Fatal("legacy configuration path changed")
	}
	rejectAdaptiveRuntimeConfig(t, []byte(`{"outbounds":[{"type":"syn443-adaptive","tag":"managed","group":"inside"}]}`), "")
}

func TestAdaptiveRuntimeExportedCommandsRequireActualTwoHopReceiptAndNativeEpoch(t *testing.T) {
	f := newPrivateAdaptiveOwnerFixture(t, nil)
	runtime := &Runtime{adaptive: f.owner, platform: &platform{lease: f.owner.hub.pool.lease}}
	create := f.owner.hub.create
	f.owner.hub.create = func(ctx context.Context, id, tag, previous string) (adapter.Outbound, error) {
		f.now.Add(11)
		return create(ctx, id, tag, previous)
	}
	var initial privateAdaptiveOwnerReport
	if json.Unmarshal([]byte(runtime.AdaptiveStatus()), &initial) != nil {
		t.Fatal("actual exported status is not a bounded native report")
	}
	if initial.PolicyScope != strings.Repeat("b", 64) || initial.NativeEpoch != 1 || !initial.Ready {
		t.Fatal("native report did not retain the local policy context")
	}
	start := map[string]any{"command": "start", "nativeEpoch": initial.NativeEpoch, "scope": initial.Scope, "request": "rpc-first", "group": "inside", "hops": f.path}
	for _, bad := range []string{`null`, `{"command":"unknown","nativeEpoch":1}`, strings.Repeat(" ", 4097)} {
		if runtime.AdaptiveCommand(bad) {
			t.Fatal("invalid exported frame accepted")
		}
	}
	for _, key := range []string{"nativeEpoch", "scope", "request", "group", "hops"} {
		copy := privateAdaptiveObject(t, privateAdaptiveMarshal(t, start))
		copy[key] = nil
		if adaptiveRuntimeCommand(t, runtime, copy) {
			t.Fatal("null field acquired worker authority")
		}
	}
	fractional := privateAdaptiveObject(t, privateAdaptiveMarshal(t, start))
	fractional["nativeEpoch"] = json.Number("1.0")
	if adaptiveRuntimeCommand(t, runtime, fractional) {
		t.Fatal("fractional generation coerced into authority")
	}
	if !adaptiveRuntimeCommand(t, runtime, start) {
		t.Fatal("actual exported start rejected")
	}
	proof := awaitPrivateAdaptiveOwner(t, f.owner)
	if proof.Code != "verified" || proof.Receipt == "" || proof.GroupSelected || proof.ElapsedMS != 22 || proof.ProbeMS != 0 {
		t.Fatal("checks selected the data path implicitly")
	}
	var published privateAdaptiveOwnerReport
	if json.Unmarshal([]byte(runtime.AdaptiveStatus()), &published) != nil || published.Receipt != proof.Receipt || published.ProbeMS != 0 || published.ElapsedMS != 22 {
		t.Fatal("exported report confused construction cost with fresh probe latency")
	}
	if conn, e := f.managed.DialContext(context.Background(), "tcp", M.ParseSocksaddr(f.address)); conn != nil || e != errPrivatePath {
		t.Fatal("uncommitted RPC proof borrowed a default route")
	}
	commit := map[string]any{"command": "commit", "nativeEpoch": proof.NativeEpoch, "scope": proof.Scope, "request": proof.Request, "receipt": proof.Receipt}
	wrong := privateAdaptiveObject(t, privateAdaptiveMarshal(t, commit))
	wrong["request"] = "another-operation"
	if adaptiveRuntimeCommand(t, runtime, wrong) {
		t.Fatal("foreign request borrowed a native receipt")
	}
	if !adaptiveRuntimeCommand(t, runtime, commit) || adaptiveRuntimeCommand(t, runtime, commit) {
		t.Fatal("actual exported receipt was denied or replayed")
	}
	flow, e := f.managed.DialContext(context.Background(), "tcp", M.ParseSocksaddr(f.address))
	if e != nil {
		t.Fatal(e)
	}
	defer flow.Close()
	privateAdaptiveEcho(t, flow, "exported-rpc-real-socks-http")
	if f.entry.calls.Load() == 0 || f.exit.calls.Load() == 0 {
		t.Fatal("exported path bypassed an actual hop")
	}
	runtime.InvalidateAdaptiveContext()
	invalid := readPrivateAdaptiveOwner(t, f.owner)
	if invalid.Ready || invalid.NativeEpoch != proof.NativeEpoch+1 || invalid.Scope == proof.Scope || adaptiveRuntimeCommand(t, runtime, commit) {
		t.Fatal("native network invalidation retained old authority")
	}
	if n, e := flow.Write([]byte("old-context")); n != 0 || e != errPrivatePath {
		t.Fatal("native invalidation left selected flow usable")
	}
	configure := map[string]any{"command": "configure", "schemaVersion": 1, "nativeEpoch": proof.NativeEpoch, "scope": initial.PolicyScope, "mode": "WIFI"}
	if adaptiveRuntimeCommand(t, runtime, configure) {
		t.Fatal("late local configure revived a stale native epoch")
	}
	configure["nativeEpoch"] = invalid.NativeEpoch
	if !adaptiveRuntimeCommand(t, runtime, configure) {
		t.Fatal("current local configure could not acknowledge the new epoch")
	}
	configured := readPrivateAdaptiveOwner(t, f.owner)
	if !configured.Ready || configured.Scope == proof.Scope {
		t.Fatal("configured context reused old native authority")
	}
	if e := runtime.SetLeaseDeadline(1); e != nil {
		t.Fatal(e)
	}
	if readPrivateAdaptiveOwner(t, f.owner).Ready || adaptiveRuntimeCommand(t, runtime, start) {
		t.Fatal("explicit lease withdrawal retained exported route control")
	}
	_ = runtime.SetLeaseDeadline(f.now.Load() + 1_000_000)
	if readPrivateAdaptiveOwner(t, f.owner).Ready {
		t.Fatal("lease renewal resurrected a closed native route owner")
	}
	if runtime.AdaptiveStatus() == "{}" || strings.Contains(runtime.AdaptiveStatus(), f.address) {
		t.Fatal("owned report disappeared or exposed an endpoint")
	}
	empty := &Runtime{}
	empty.InvalidateAdaptiveContext()
	if empty.AdaptiveStatus() != "{}" || empty.AdaptiveCommand("{}") {
		t.Fatal("unconfigured runtime exposed adaptive authority")
	}
}

func TestAdaptiveRuntimeSharedBootDeadlinePreventsAnotherProbe(t *testing.T) {
	t.Run("expired before cold construction", func(t *testing.T) {
		var fixture privateAdaptiveOwnerFixture
		fixture = newPrivateAdaptiveOwnerFixture(t, func(bool) (func(), bool) { fixture.now.Add(30_000); return func() {}, true })
		var calls atomic.Int32
		original := fixture.owner.hub.create
		fixture.owner.hub.create = func(ctx context.Context, id, tag, previous string) (adapter.Outbound, error) {
			calls.Add(1)
			return original(ctx, id, tag, previous)
		}
		epoch, scope, _ := fixture.owner.context()
		if !fixture.owner.start("cold-expired", epoch, scope, "inside", fixture.path) {
			t.Fatal("compiled admission rejected before its budget observation")
		}
		report := awaitPrivateAdaptiveOwner(t, fixture.owner)
		if report.Code != "probe_unavailable" || report.Receipt != "" || calls.Load() != 0 || fixture.entry.calls.Load() != 0 || fixture.exit.calls.Load() != 0 {
			t.Fatal("aggregate-expired cold request constructed or dialed another hop")
		}
	})
	t.Run("aggregate remainder bounds constructor stages", func(t *testing.T) {
		var fixture privateAdaptiveOwnerFixture
		fixture = newPrivateAdaptiveOwnerFixture(t, func(bool) (func(), bool) { fixture.now.Add(10_000); return func() {}, true })
		var calls atomic.Int32
		var starts, closes []string
		fixture.owner.hub.create = func(_ context.Context, _, tag, previous string) (adapter.Outbound, error) {
			calls.Add(1)
			return &privateBudgetLifecycleNode{pathLifecycleNode: pathLifecycleNode{name: tag, dependency: previous, starts: &starts, closes: &closes}, firstStart: func() { fixture.now.Add(20_000) }}, nil
		}
		epoch, scope, _ := fixture.owner.context()
		if !fixture.owner.start("cold-stage-budget", epoch, scope, "inside", fixture.path) {
			t.Fatal("compiled aggregate budget request denied before construction")
		}
		report := awaitPrivateAdaptiveOwner(t, fixture.owner)
		if report.Code != "probe_unavailable" || report.Receipt != "" || calls.Load() != 1 || fixture.entry.calls.Load() != 0 || fixture.exit.calls.Load() != 0 {
			t.Fatal("constructor borrowed a fresh thirty seconds beyond the owner remainder")
		}
	})
	var fixture privateAdaptiveOwnerFixture
	var admissions atomic.Int32
	fixture = newPrivateAdaptiveOwnerFixture(t, func(bool) (func(), bool) {
		if admissions.Add(1) == 2 {
			fixture.now.Add(30_000)
		}
		return func() {}, true
	})
	runtime := &Runtime{adaptive: fixture.owner}
	epoch, scope, _ := fixture.owner.context()
	start := func(request string) bool {
		return adaptiveRuntimeCommand(t, runtime, map[string]any{"command": "start", "nativeEpoch": epoch, "scope": scope, "request": request, "group": "inside", "hops": fixture.path})
	}
	if !start("warm-cache") {
		t.Fatal("first actual probe denied")
	}
	proof := awaitPrivateAdaptiveOwner(t, fixture.owner)
	if proof.Code != "verified" || !adaptiveRuntimeCommand(t, runtime, map[string]any{"command": "discard", "nativeEpoch": epoch, "scope": scope, "request": proof.Request, "receipt": proof.Receipt}) {
		t.Fatal("first actual probe could not be explicitly discarded")
	}
	entry, exit := fixture.entry.calls.Load(), fixture.exit.calls.Load()
	if entry == 0 || exit == 0 {
		t.Fatal("cache fixture did not traverse both real hops")
	}
	// The compiled admission hook advances BOOTTIME after start's initial
	// sample, before its worker can use the cached candidate. Go's timer has not
	// elapsed: the common native BOOT deadline must deny another TCP probe.
	if !start("suspended-before-probe") {
		t.Fatal("bounded second request denied before worker admission")
	}
	report := awaitPrivateAdaptiveOwner(t, fixture.owner)
	if report.Code != "probe_unavailable" || report.Receipt != "" || fixture.entry.calls.Load() != entry || fixture.exit.calls.Load() != exit {
		t.Fatal("suspend-expired aggregate budget performed extra network I/O or published proof")
	}
}
