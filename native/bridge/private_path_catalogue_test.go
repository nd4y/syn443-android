package bridge

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

func TestPrivateCatalogueOwnsNormalizedProfilesAndRuntimeFactory(t *testing.T) {
	target := listenWire(t, func(c net.Conn) { _, _ = io.Copy(c, c) })
	address := target.listener.Addr().String()
	exit := httpWire(t, address, "", "")
	entry := socksWire(t, exit.listener.Addr().String())
	instance, parent := wireNetworkBox(t, nil, []map[string]any{{"type": "direct", "tag": "existing"}}, nil)
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	input := map[string]json.RawMessage{}
	input["entry"], _ = json.Marshal(entry.node("socks", "entry"))
	input["exit"], _ = json.Marshal(exit.node("http", "exit"))
	c, e := newPrivatePathCatalogue(ctx, instance.Router(), input)
	if e != nil {
		t.Fatal(e)
	}
	hash := c.hash
	// Neither mutation of an imported backing buffer nor replacement of the
	// caller's map may change later candidates or the dependency binding.
	for _, raw := range input {
		for i := range raw {
			raw[i] = '!'
		}
	}
	input["exit"] = nil
	if c.hash != hash || len(hash) != 64 || strings.Contains(fmt.Sprintf("%v %#v", c, c), address) {
		t.Fatal("catalogue binding or redaction failed")
	}
	scope := strings.Repeat("a", 64)
	p, e := newPrivatePathPool(c.ctx, scope, 3, privatePoolLease(t))
	if e != nil {
		t.Fatal(e)
	}
	cleanupPrivatePool(t, p)
	path, e := p.prepare(scope, []string{"entry", "exit"}, c.create)
	if e != nil {
		t.Fatal(e)
	}
	flow, e := path.dialTCP(scope, context.Background(), "tcp", M.ParseSocksaddr(address))
	if e != nil {
		t.Fatal(e)
	}
	_ = flow.SetDeadline(time.Now().Add(5 * time.Second))
	if _, e = io.WriteString(flow, "catalogue-owned"); e != nil {
		t.Fatal(e)
	}
	buf := make([]byte, len("catalogue-owned"))
	if _, e = io.ReadFull(flow, buf); e != nil || string(buf) != "catalogue-owned" {
		t.Fatal("catalogue-bound owned SOCKS/HTTP payload failed", e)
	}
	_ = flow.Close()
	_ = path.Close()
	awaitPrivatePool(t, func() bool { return p.snapshot().Dynamic == 0 })
	if entry.calls.Load() == 0 || exit.calls.Load() == 0 {
		t.Fatal("catalogue bypassed a declared hop")
	}
	if e = payloadWire(t, instance.Outbound().Default(), address); e != nil {
		t.Fatal("private factory changed configured parent", e)
	}
	if node, e := c.create(c.ctx, "entry", "candidate", ""); node != nil || e != errPrivatePath {
		t.Fatal("factory borrowed configured parent registry")
	}
	other, otherParent := wireNetworkBox(t, nil, []map[string]any{{"type": "direct", "tag": "another"}}, nil)
	otherRaw, _ := json.Marshal(map[string]any{"type": "http", "tag": "only", "server": "proxy.example.invalid", "server_port": 443})
	otherCatalogue, e := newPrivatePathCatalogue(otherParent, other.Router(), map[string]json.RawMessage{"only": otherRaw})
	if e != nil {
		t.Fatal(e)
	}
	if path, retained, e := buildPrivatePath(otherCatalogue.ctx, []string{"entry"}, c.create); path != nil || retained != nil || e != errPrivatePath {
		t.Fatal("old factory borrowed a replacement runtime")
	}
	if path, retained, e := buildPrivatePath(c.ctx, []string{"missing"}, c.create); path != nil || retained != nil || e != errPrivatePath {
		t.Fatal("unbound profile obtained a default")
	}
	cancel()
	if path, retained, e := buildPrivatePath(c.ctx, []string{"entry"}, c.create); path != nil || retained != nil || e != errPrivatePath {
		t.Fatal("cancelled catalogue constructed a path")
	}
}

func TestPrivateCatalogueRejectsNoncanonicalUnsafeAndSubstitutedOptions(t *testing.T) {
	instance, parent := wireNetworkBox(t, nil, []map[string]any{{"type": "direct", "tag": "existing"}}, nil)
	valid := func() map[string]any {
		return map[string]any{"type": "http", "tag": "one", "server": "proxy.example.invalid", "server_port": 443}
	}
	for _, kind := range []string{"wrong-tag", "unknown-type", "file-key", "foreign-detour", "insecure-tls", "file-tls", "file-utls", "file-reality", "tls-type", "tls-disabled", "tls-insecure-type", "utls-type", "utls-disabled", "reality-disabled", "ssh-no-host-key", "bad-port", "zero-port", "huge-port", "empty-server", "unknown-field"} {
		t.Run(kind, func(t *testing.T) {
			node := valid()
			switch kind {
			case "wrong-tag":
				node["tag"] = "other"
			case "unknown-type":
				node["type"] = "netbird"
			case "file-key":
				node["type"] = "ssh"
				node["private_key_path"] = "/nonexistent/synthetic"
			case "foreign-detour":
				node["detour"] = "existing"
			case "insecure-tls":
				node["tls"] = map[string]any{"enabled": true, "insecure": true}
			case "file-tls":
				node["tls"] = map[string]any{"enabled": true, "certificate_path": "/nonexistent/synthetic"}
			case "file-utls":
				node["tls"] = map[string]any{"enabled": true, "utls": map[string]any{"enabled": true, "fingerprint": "chrome", "file_path": "/nonexistent/synthetic"}}
			case "file-reality":
				node["tls"] = map[string]any{"enabled": true, "reality": map[string]any{"enabled": true, "private_key_path": "/nonexistent/synthetic"}}
			case "tls-type":
				node["tls"] = "bad"
			case "tls-disabled":
				node["tls"] = map[string]any{"enabled": false}
			case "tls-insecure-type":
				node["tls"] = map[string]any{"enabled": true, "insecure": "false"}
			case "utls-type":
				node["tls"] = map[string]any{"enabled": true, "utls": "bad"}
			case "utls-disabled":
				node["tls"] = map[string]any{"enabled": true, "utls": map[string]any{"enabled": false}}
			case "reality-disabled":
				node["tls"] = map[string]any{"enabled": true, "reality": map[string]any{"enabled": false}}
			case "ssh-no-host-key":
				node["type"] = "ssh"
			case "bad-port":
				node["server_port"] = "443"
			case "zero-port":
				node["server_port"] = 0
			case "huge-port":
				node["server_port"] = 65536
			case "empty-server":
				node["server"] = ""
			case "unknown-field":
				node["settings"] = map[string]any{}
			}
			raw, _ := json.Marshal(node)
			if c, e := newPrivatePathCatalogue(parent, instance.Router(), map[string]json.RawMessage{"one": raw}); c != nil || e != errPrivatePath {
				t.Fatal("unsafe/substituted profile accepted", kind, e)
			}
		})
	}
	for _, raw := range []string{`null`, `[]`, `{`, `{"type":"http","type":"http","tag":"one","server":"proxy.example.invalid","server_port":443}`, `{"Type":"http","tag":"one","server":"proxy.example.invalid","server_port":443}`} {
		if c, e := newPrivatePathCatalogue(parent, instance.Router(), map[string]json.RawMessage{"one": json.RawMessage(raw)}); c != nil || e != errPrivatePath {
			t.Fatal("noncanonical input accepted")
		}
	}
	duplicate := valid()
	duplicate["tag"] = "two"
	one, _ := json.Marshal(valid())
	two, _ := json.Marshal(duplicate)
	if c, e := newPrivatePathCatalogue(parent, instance.Router(), map[string]json.RawMessage{"one": one, "two": two}); c != nil || e != errPrivatePath {
		t.Fatal("duplicate proxy aliases accepted")
	}
}

func TestPrivateCatalogueBoundsContextAndFreshTypedConstruction(t *testing.T) {
	instance, parent := wireNetworkBox(t, nil, []map[string]any{{"type": "direct", "tag": "existing"}}, nil)
	profiles := map[string]json.RawMessage{}
	for i := 0; i < 500; i++ {
		id := fmt.Sprintf("hop-%03d", i)
		profiles[id], _ = json.Marshal(map[string]any{"type": "http", "tag": id, "server": fmt.Sprintf("proxy-%03d.example.invalid", i), "server_port": 443})
	}
	c, e := newPrivatePathCatalogue(parent, instance.Router(), profiles)
	if e != nil || len(c.profiles) != 500 {
		t.Fatal("500-profile normalized snapshot rejected", e)
	}
	for _, args := range []struct {
		ctx      context.Context
		router   bool
		profiles map[string]json.RawMessage
	}{{nil, true, profiles}, {context.Background(), true, profiles}, {parent, false, profiles}, {parent, true, nil}, {parent, true, map[string]json.RawMessage{"invalid/id": profiles["hop-000"]}}, {parent, true, map[string]json.RawMessage{"one": make([]byte, 65537)}}} {
		router := instance.Router()
		if !args.router {
			router = nil
		}
		if c, e := newPrivatePathCatalogue(args.ctx, router, args.profiles); c != nil || e != errPrivatePath {
			t.Fatal("invalid catalogue precondition accepted")
		}
	}
	profiles["extra"] = profiles["hop-000"]
	if c, e := newPrivatePathCatalogue(parent, instance.Router(), profiles); c != nil || e != errPrivatePath {
		t.Fatal("catalogue count exceeded")
	}
	delete(profiles, "extra")
	for id, raw := range profiles {
		var node map[string]any
		_ = json.Unmarshal(raw, &node)
		node["password"] = strings.Repeat("x", 600)
		profiles[id], _ = json.Marshal(node)
	}
	if c, e := newPrivatePathCatalogue(parent, instance.Router(), profiles); c != nil || e != errPrivatePath {
		t.Fatal("aggregate catalogue byte limit exceeded")
	}
	ctx, cancel := context.WithCancel(parent)
	cancel()
	if c, e := newPrivatePathCatalogue(ctx, instance.Router(), map[string]json.RawMessage{"one": json.RawMessage(`{}`)}); c != nil || e != errPrivatePath {
		t.Fatal("cancelled parent admitted catalogue")
	}
	// A fresh private registry per construction prevents typed detour options
	// from one candidate mutating another. No adapter is added to the parent.
	for i := 0; i < 3; i++ {
		p, retained, e := buildPrivatePath(c.ctx, []string{"hop-000", "hop-001"}, c.create)
		if e != nil || retained != nil {
			t.Fatal("fresh private options failed", e)
		}
		if e = p.Close(); e != nil {
			t.Fatal(e)
		}
	}
	if len(instance.Outbound().Outbounds()) != 1 {
		t.Fatal("private construction mutated configured manager")
	}
}
