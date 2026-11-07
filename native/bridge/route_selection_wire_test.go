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
	runner.selectors = map[string]map[string]bool{"group": {"primary": true, "reserve": true}}
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
	if runner.selectVerified("before-probe", "reserve-check", "group", "primary", "reserve") {
		t.Fatal("member selected without evidence")
	}
	probe := func(receipt string) {
		t.Helper()
		request, _ := json.Marshal(routeRequest{Request: receipt, Routes: []routePlan{
			{ID: "reserve-check", Outbound: "reserve", Checks: []routeCheck{{Method: "tcp", Target: address}}},
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
	probe("discarded-network")
	runner.stop()
	if runner.selectVerified("discarded-network", "reserve-check", "group", "primary", "reserve") {
		t.Fatal("network invalidation left the old proof usable")
	}
	probe("expired-proof")
	runner.mu.Lock()
	runner.report.Results[0].SampledElapsedMS = bootMillis() - 15_001
	runner.mu.Unlock()
	if runner.selectVerified("expired-proof", "reserve-check", "group", "primary", "reserve") {
		t.Fatal("old reserve result was treated as current")
	}
	probe("current-network")
	if runner.selectVerified("current-network", "wrong-check", "group", "primary", "reserve") ||
		runner.selectVerified("current-network", "reserve-check", "group", "another", "reserve") ||
		runner.selectVerified("current-network", "reserve-check", "group", "reserve", "primary") ||
		runner.selectVerified("current-network", "reserve-check", "group", "primary", "unassigned") {
		t.Fatal("selection accepted a mismatched probe, previous member or candidate")
	}
	if !runner.selectVerified("current-network", "reserve-check", "group", "primary", "reserve") || selectable.Now() != "reserve" {
		t.Fatal("verified reserve did not become the new path")
	}
	echo("after-switch")
	if runner.selectVerified("current-network", "reserve-check", "group", "primary", "reserve") {
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
