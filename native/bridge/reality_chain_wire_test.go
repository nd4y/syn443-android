package bridge

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"io"
	"net"
	"strconv"
	"testing"
)

func realityWire(t *testing.T) (map[string]any, *wireFixture) {
	t.Helper()
	_, _, certificate := wireTLS(t)
	origin := listenWire(t, func(conn net.Conn) {
		secure := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13, NextProtos: []string{"h2", "http/1.1"}})
		defer secure.Close()
		if secure.Handshake() != nil {
			return
		}
		_, _ = io.Copy(io.Discard, secure)
	})
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var short [8]byte
	if _, err = rand.Read(short[:]); err != nil {
		t.Fatal(err)
	}
	shortID := ""
	const hex = "0123456789abcdef"
	for _, v := range short {
		shortID += string([]byte{hex[v>>4], hex[v&15]})
	}
	uuid := wireUUID(t)
	port := wirePort(t)
	host, originPort, _ := net.SplitHostPort(origin.listener.Addr().String())
	number, _ := strconv.Atoi(originPort)
	in := map[string]any{"type": "vless", "tag": "reality-in", "listen": "127.0.0.1", "listen_port": port, "users": []any{map[string]any{"uuid": uuid}}, "tls": map[string]any{"enabled": true, "server_name": "wire.example.invalid", "reality": map[string]any{"enabled": true, "private_key": base64.RawURLEncoding.EncodeToString(private.Bytes()), "short_id": []string{shortID}, "handshake": map[string]any{"server": host, "server_port": number}}}}
	wireConfiguredBox(t, []map[string]any{in}, []map[string]any{{"type": "direct", "tag": "direct"}})
	return map[string]any{"type": "vless", "tag": "exit", "server": "127.0.0.1", "server_port": port, "uuid": uuid, "tls": map[string]any{"enabled": true, "server_name": "wire.example.invalid", "utls": map[string]any{"enabled": true, "fingerprint": "chrome"}, "reality": map[string]any{"enabled": true, "public_key": base64.RawURLEncoding.EncodeToString(private.PublicKey().Bytes()), "short_id": shortID}}}, origin
}

func TestRegisteredVLESSRealityActualPayloadAndAuthenticationBoundary(t *testing.T) {
	for _, failure := range []string{"none", "public-key", "short-id", "uuid"} {
		t.Run(failure, func(t *testing.T) {
			target := listenWire(t, func(conn net.Conn) { _, _ = io.Copy(conn, conn) })
			node, origin := realityWire(t)
			options := node["tls"].(map[string]any)["reality"].(map[string]any)
			switch failure {
			case "public-key":
				other, err := ecdh.X25519().GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				options["public_key"] = base64.RawURLEncoding.EncodeToString(other.PublicKey().Bytes())
			case "short-id":
				options["short_id"] = "" // The fixture accepts only its generated nonempty ID.
			case "uuid":
				node["uuid"] = wireUUID(t)
			}
			client := wireBox(t, node)
			out, _ := client.Outbound().Outbound("exit")
			err := payloadWire(t, out, target.listener.Addr().String())
			if failure == "none" {
				if err != nil || target.calls.Load() != 1 || origin.calls.Load() < 1 {
					t.Fatal("actual Reality path failed", err)
				}
			} else if err == nil || target.calls.Load() != 0 {
				t.Fatal("invalid Reality authority reached payload target")
			}
		})
	}
}

func TestRegisteredFourHopHTTPToSOCKSToSSHToVLESSUsesEveryHop(t *testing.T) {
	target := listenWire(t, func(conn net.Conn) { _, _ = io.Copy(conn, conn) })
	last, _ := vlessWire(t, "tls")
	sshServer, hostKey := sshWire(t, net.JoinHostPort("127.0.0.1", strconv.Itoa(last["server_port"].(int))))
	sshNode := sshServer.node("ssh", "third")
	sshNode["user"] = "fixture"
	sshNode["password"] = "fixture-pass"
	sshNode["host_key"] = []string{hostKey}
	sshNode["detour"] = "second"
	socks := socksWire(t, sshServer.listener.Addr().String())
	second := socks.node("socks", "second")
	second["detour"] = "first"
	http := httpWire(t, socks.listener.Addr().String(), "", "")
	last["detour"] = "third"
	client := wireBox(t, last, sshNode, second, http.node("http", "first"))
	out, _ := client.Outbound().Outbound("exit")
	if err := payloadWire(t, out, target.listener.Addr().String()); err != nil {
		t.Fatal(err)
	}
	for _, hop := range []*wireFixture{http, socks, sshServer, target} {
		if hop.calls.Load() != 1 {
			t.Fatal("four-hop chain bypassed or duplicated a hop")
		}
	}
}

func TestRegisteredSelectorEntrySwitchesWholePathWithoutImplicitEscape(t *testing.T) {
	target := listenWire(t, func(conn net.Conn) { _, _ = io.Copy(conn, conn) })
	last, _ := vlessWire(t, "tls")
	destination := net.JoinHostPort("127.0.0.1", strconv.Itoa(last["server_port"].(int)))
	good := httpWire(t, destination, "", "")
	bad := httpWire(t, destination, "required-user", "required-pass")
	last["detour"] = "entry"
	client := wireBox(t, last, good.node("http", "good"), bad.node("http", "bad"), map[string]any{"type": "selector", "tag": "entry", "outbounds": []string{"bad", "good"}, "default": "bad", "interrupt_exist_connections": true})
	out, _ := client.Outbound().Outbound("exit")
	selected, _ := client.Outbound().Outbound("entry")
	selector, ok := selected.(interface {
		SelectOutbound(string) bool
		Now() string
	})
	if !ok {
		t.Fatal("actual selector unavailable")
	}
	if payloadWire(t, out, target.listener.Addr().String()) == nil || target.calls.Load() != 0 || good.calls.Load() != 0 {
		t.Fatal("failed selected entry escaped to another path")
	}
	if selector.SelectOutbound("unassigned") || selector.Now() != "bad" {
		t.Fatal("unknown selection changed path")
	}
	if !selector.SelectOutbound("good") || selector.Now() != "good" {
		t.Fatal("authorized selection rejected")
	}
	if err := payloadWire(t, out, target.listener.Addr().String()); err != nil || target.calls.Load() != 1 || good.calls.Load() != 1 {
		t.Fatal("whole selected chain did not work", err)
	}
	if !selector.SelectOutbound("bad") {
		t.Fatal("second selection rejected")
	}
	if payloadWire(t, out, target.listener.Addr().String()) == nil || target.calls.Load() != 1 || good.calls.Load() != 1 {
		t.Fatal("selection failure silently reused prior path")
	}
}

func TestRegisteredVLESSCarriesActualUDPThroughTCPHTTPEntry(t *testing.T) {
	for _, failure := range []bool{false, true} {
		t.Run(strconv.FormatBool(failure), func(t *testing.T) {
			target, calls := udpEchoWire(t)
			node, _ := vlessWire(t, "tls")
			entry := httpWire(t, net.JoinHostPort("127.0.0.1", strconv.Itoa(node["server_port"].(int))), "", "")
			node["detour"] = "entry"
			if failure {
				node["uuid"] = wireUUID(t)
			}
			client := wireBox(t, node, entry.node("http", "entry"))
			out, _ := client.Outbound().Outbound("exit")
			err := udpPayloadWire(out, target.LocalAddr().(*net.UDPAddr))
			if !failure {
				if err != nil || calls.Load() != 1 || entry.calls.Load() != 1 {
					t.Fatal("VLESS UDP over TCP proxy failed", err)
				}
			} else if err == nil || calls.Load() != 0 {
				t.Fatal("failed VLESS UDP escaped directly")
			}
		})
	}
}
