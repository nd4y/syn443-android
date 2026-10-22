package netbird

import (
	"context"
	"net"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
)

type graphManager struct {
	adapter.OutboundManager
	nodes map[string]adapter.Outbound
}

func (m graphManager) Outbound(tag string) (adapter.Outbound, bool) {
	v, ok := m.nodes[tag]
	return v, ok
}

type graphOutbound struct {
	adapter.Outbound
	kind string
	dial func(context.Context, string, M.Socksaddr) (net.Conn, error)
}

func (o graphOutbound) Type() string { return o.kind }
func (o graphOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return o.dial(ctx, network, destination)
}

type graphGroup struct {
	graphOutbound
	members []string
}

func (o graphGroup) All() []string { return o.members }
func TestVLESSGroupRejectsEveryUnsafeBranch(t *testing.T) {
	leaf := graphOutbound{kind: "vless"}
	group := func(kind string, tags ...string) adapter.Outbound {
		return graphGroup{graphOutbound: graphOutbound{kind: kind}, members: tags}
	}
	cases := []struct {
		name  string
		nodes map[string]adapter.Outbound
		valid bool
	}{
		{"vless", map[string]adapter.Outbound{"root": leaf}, true},
		{"urltest", map[string]adapter.Outbound{"root": group("urltest", "a", "b"), "a": leaf, "b": leaf}, true},
		{"nested", map[string]adapter.Outbound{"root": group("selector", "nested", "b"), "nested": group("urltest", "a"), "a": leaf, "b": leaf}, true},
		{"shared", map[string]adapter.Outbound{"root": group("selector", "nested", "nested"), "nested": group("urltest", "a"), "a": leaf}, true},
		{"missing-root", map[string]adapter.Outbound{}, false},
		{"direct", map[string]adapter.Outbound{"root": graphOutbound{kind: "direct"}}, false},
		{"mixed-unused-direct", map[string]adapter.Outbound{"root": group("urltest", "a", "bad"), "a": leaf, "bad": graphOutbound{kind: "direct"}}, false},
		{"empty", map[string]adapter.Outbound{"root": group("urltest")}, false},
		{"missing-member", map[string]adapter.Outbound{"root": group("selector", "missing")}, false},
		{"cycle", map[string]adapter.Outbound{"root": group("selector", "next"), "next": group("urltest", "root")}, false},
		{"netbird", map[string]adapter.Outbound{"root": group("selector", "bad"), "bad": graphOutbound{kind: "netbird"}}, false},
		{"fake-group", map[string]adapter.Outbound{"root": graphOutbound{kind: "selector"}}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := validatedVLESSDetour(graphManager{nodes: tc.nodes}, "root")
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v err=%v", tc.valid, err)
			}
		})
	}
}
func TestGroupDialPreservesHostnameAndRevalidatesAllMembers(t *testing.T) {
	var got string
	calls := 0
	leaf := graphOutbound{kind: "vless"}
	group := graphGroup{graphOutbound: graphOutbound{kind: "urltest", dial: func(_ context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
		calls++
		got = network + "/" + destination.String()
		a, b := net.Pipe()
		b.Close()
		return a, nil
	}}, members: []string{"leaf"}}
	nodes := map[string]adapter.Outbound{"root": group, "leaf": leaf}
	d := vlessGroupDialer{manager: graphManager{nodes: nodes}, tag: "root"}
	c, err := d.DialContext(context.Background(), "tcp", "relay.invalid:443")
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if got != "tcp/relay.invalid:443" || calls != 1 {
		t.Fatal(got, calls)
	}
	nodes["leaf"] = graphOutbound{kind: "direct"}
	if c, err = d.DialContext(context.Background(), "tcp", "relay.invalid:443"); err == nil || c != nil {
		t.Fatal("unsafe group accepted")
	}
	if calls != 1 {
		t.Fatal("unsafe group reached dialer")
	}
}
