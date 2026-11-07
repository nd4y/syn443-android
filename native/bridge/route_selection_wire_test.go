package bridge

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/interrupt"
	M "github.com/sagernet/sing/common/metadata"
)

func TestNativeSelectionPlanRejectsWrongMemberIdentityAndMutablePath(t *testing.T) {
	runner := newRouteRunner(context.Background(), nil)
	runner.nodes = map[string]routeNode{
		"primary": {ID: "route-1", Kind: "http"},
		"reserve": {ID: "route-2", Kind: "socks"},
	}
	runner.selectors = map[string]map[string]bool{"group": {"primary": true, "reserve": true}}
	for _, fixture := range []struct {
		selector, memberID, memberTag, memberKind string
	}{
		{"unknown", "route-2", "reserve", "socks"},
		{"group", "route-3", "reserve", "socks"},
		{"group", "route-2", "primary", "socks"},
		{"group", "route-2", "reserve", "urltest"},
	} {
		runner.nodes["reserve"] = routeNode{ID: "route-2", Kind: fixture.memberKind}
		checks := []routeCheck{{Method: "tcp", Target: "127.0.0.1:12345"}}
		raw, err := json.Marshal(routeSelectionPlan{Selector: fixture.selector, Paths: []routePlan{
			{ID: "route-1", Outbound: "primary", Checks: checks},
			{ID: fixture.memberID, Outbound: fixture.memberTag, Checks: checks},
		}})
		if err != nil || runner.configureSelection(string(raw)) || runner.selectionGroup != "" {
			t.Fatal("invalid plan changed native selection authority", err)
		}
	}
}

func TestVerifiedSelectorSwitchKeepsExistingTrafficAndRejectsStaleProof(t *testing.T) {
	target := listenWire(t, func(conn net.Conn) { _, _ = io.Copy(conn, conn) })
	address := target.listener.Addr().String()
	primary := httpWire(t, address, "", "")
	reserve := httpWire(t, address, "", "")
	box := wireBox(t, primary.node("http", "primary"), reserve.node("http", "reserve"),
		map[string]any{"type": "selector", "tag": "group", "default": "primary",
			"outbounds": []string{"primary", "reserve"}, "interrupt_exist_connections": false})
	lookup := func(tag string) (adapter.Outbound, bool) { return box.Outbound().Outbound(tag) }
	runner := newRouteRunner(context.Background(), lookup)
	t.Cleanup(runner.stop)
	runner.nodes = map[string]routeNode{
		"primary": {ID: "route-1", Kind: "http"},
		"reserve": {ID: "route-2", Kind: "http"},
		"group":   {ID: "route-3", Kind: "selector"},
	}
	runner.selectors = map[string]map[string]bool{
		"group": {"primary": true, "reserve": true}, "other-group": {"primary": true, "reserve": true},
	}
	checks := []routeCheck{{Method: "tcp", Target: address}}
	approved := routeSelectionPlan{Selector: "group", Paths: []routePlan{
		{ID: "route-1", Outbound: "primary", Checks: checks},
		{ID: "route-2", Outbound: "reserve", Checks: checks},
	}}
	raw, err := json.Marshal(approved)
	if err != nil || !runner.configureSelection(string(raw)) {
		t.Fatal("authorized route checks were not installed", err)
	}
	group, ok := lookup("group")
	if !ok {
		t.Fatal("configured selector missing")
	}
	selectable := group.(interface{ Now() string })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	flow, err := group.DialContext(interrupt.ContextWithIsExternalConnection(ctx), "tcp", M.ParseSocksaddr(address))
	if err != nil {
		t.Fatal(err)
	}
	defer flow.Close()
	if err := flow.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	echo := func(value string) {
		t.Helper()
		if _, err := io.WriteString(flow, value); err != nil {
			t.Fatal(err)
		}
		read := make([]byte, len(value))
		if _, err := io.ReadFull(flow, read); err != nil || string(read) != value {
			t.Fatal("established proxy traffic did not survive", err)
		}
	}
	echo("first")
	if runner.selectVerified("before-probe", "route-2", "group", "primary", "reserve") {
		t.Fatal("member selected without evidence")
	}
	probe := func(receipt string, checks []routeCheck) {
		t.Helper()
		request, _ := json.Marshal(routeRequest{Request: receipt, Routes: []routePlan{
			{ID: "route-2", Outbound: "reserve", Checks: checks},
		}})
		if !runner.start(string(request)) {
			t.Fatal("probe not admitted")
		}
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			var report routeReport
			if json.Unmarshal([]byte(runner.snapshot()), &report) == nil && !report.Running {
				if report.Request != receipt || len(report.Results) != 1 || !report.Results[0].OK || !report.Results[0].Complete {
					t.Fatal("reserve did not prove its path")
				}
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
		t.Fatal("probe completion not observed")
	}
	diagnosticChecks := []routeCheck{checks[0], checks[0]}
	probe("diagnostic-only", diagnosticChecks)
	if runner.selectVerified("diagnostic-only", "route-2", "group", "primary", "reserve") {
		t.Fatal("a successful diagnostic outside the approved plan authorized a switch")
	}
	probe("discarded-network", checks)
	runner.stop()
	if runner.selectVerified("discarded-network", "route-2", "group", "primary", "reserve") {
		t.Fatal("network invalidation left the old proof usable")
	}
	probe("expired-proof", checks)
	runner.mu.Lock()
	runner.report.Results[0].SampledElapsedMS = bootMillis() - 15_001
	runner.mu.Unlock()
	if runner.selectVerified("expired-proof", "route-2", "group", "primary", "reserve") {
		t.Fatal("old reserve result was treated as current")
	}
	probe("current-network", checks)
	if runner.selectVerified("current-network", "wrong-check", "group", "primary", "reserve") ||
		runner.selectVerified("current-network", "route-2", "other-group", "primary", "reserve") ||
		runner.selectVerified("current-network", "route-2", "group", "another", "reserve") ||
		runner.selectVerified("current-network", "route-2", "group", "reserve", "primary") ||
		runner.selectVerified("current-network", "route-2", "group", "primary", "unassigned") {
		t.Fatal("selection accepted a mismatched probe, previous member or candidate")
	}
	if !runner.selectVerified("current-network", "route-2", "group", "primary", "reserve") || selectable.Now() != "reserve" {
		t.Fatal("verified reserve did not become the new path")
	}
	echo("after-switch")
	if runner.selectVerified("current-network", "route-2", "group", "primary", "reserve") {
		t.Fatal("selector reused a consumed check")
	}
	calls := reserve.calls.Load()
	if err := payloadWire(t, group, address); err != nil || reserve.calls.Load() <= calls {
		t.Fatal("new connection did not use the verified reserve", err)
	}
	runner.networkChanged()
	if selectable.Now() != "primary" {
		t.Fatal("new physical context inherited an adaptive selection")
	}
	echo("after-context-reset")
}
