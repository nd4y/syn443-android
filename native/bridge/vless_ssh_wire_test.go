package bridge

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	"golang.org/x/crypto/ssh"
)

// All credentials/certificates are generated per test and never identify a real
// provider. The actual embedded outbound modules cross real loopback servers.
func wireUUID(t *testing.T) string {
	t.Helper()
	var bytes [16]byte
	if _, e := rand.Read(bytes[:]); e != nil {
		t.Fatal(e)
	}
	raw := hex.EncodeToString(bytes[:])
	return raw[:8] + "-" + raw[8:12] + "-" + raw[12:16] + "-" + raw[16:20] + "-" + raw[20:]
}
func wireTLS(t *testing.T) (string, string, tls.Certificate) {
	t.Helper()
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	serial, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if e != nil {
		t.Fatal(e)
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "wire.example.invalid"}, DNSNames: []string{"wire.example.invalid"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, e := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	private, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		t.Fatal(e)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})
	certificate, e := tls.X509KeyPair(certPEM, keyPEM)
	if e != nil {
		t.Fatal(e)
	}
	return string(certPEM), string(keyPEM), certificate
}
func wirePort(t *testing.T) int {
	t.Helper()
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if e = listener.Close(); e != nil {
		t.Fatal(e)
	}
	return port
}
func vlessWire(t *testing.T, transport string) (map[string]any, *box.Box) {
	t.Helper()
	cert, key, _ := wireTLS(t)
	uuid := wireUUID(t)
	port := wirePort(t)
	alpn := []string{"h2", "http/1.1"}
	if transport == "xhttp-h3" {
		alpn = []string{"h3"}
	}
	in := map[string]any{"type": "vless", "tag": "wire-in", "listen": "127.0.0.1", "listen_port": port, "users": []any{map[string]any{"name": "fixture", "uuid": uuid}}, "tls": map[string]any{"enabled": true, "certificate": []string{cert}, "key": []string{key}, "alpn": alpn}}
	out := map[string]any{"type": "vless", "tag": "exit", "server": "127.0.0.1", "server_port": port, "uuid": uuid, "tls": map[string]any{"enabled": true, "server_name": "wire.example.invalid", "certificate": []string{cert}, "alpn": alpn}}
	var options map[string]any
	switch transport {
	case "tls":
	case "ws":
		options = map[string]any{"type": "ws", "path": "/fixture"}
	case "grpc":
		options = map[string]any{"type": "grpc", "service_name": "fixture"}
	case "xhttp-h2":
		options = map[string]any{"type": "xhttp", "mode": "stream-one", "path": "/fixture"}
		in["tls"].(map[string]any)["alpn"] = []string{"h2"}
		out["tls"].(map[string]any)["alpn"] = []string{"h2"}
	case "xhttp-h3":
		options = map[string]any{"type": "xhttp", "mode": "stream-one", "path": "/fixture"}
	case "xhttp-packet-up":
		options = map[string]any{"type": "xhttp", "mode": "packet-up", "path": "/fixture", "sc_min_posts_interval_ms": 0}
		in["tls"].(map[string]any)["alpn"] = []string{"h2"}
		out["tls"].(map[string]any)["alpn"] = []string{"h2"}
	default:
		t.Fatal("unknown fixture transport")
	}
	if options != nil {
		in["transport"] = options
		out["transport"] = options
	}
	server := wireConfiguredBox(t, []map[string]any{in}, []map[string]any{{"type": "direct", "tag": "direct"}})
	return out, server
}
func TestRegisteredVLESSTLSTransportsActualPayloadAndDetour(t *testing.T) {
	for _, transport := range []string{"tls", "ws", "grpc", "xhttp-h2", "xhttp-h3", "xhttp-packet-up"} {
		t.Run(transport, func(t *testing.T) {
			target := listenWire(t, func(c net.Conn) { _, _ = io.Copy(c, c) })
			node, _ := vlessWire(t, transport)
			nodes := []map[string]any{node}
			var entry *wireFixture
			if transport == "xhttp-h2" {
				entry = socksWire(t, net.JoinHostPort("127.0.0.1", strconv.Itoa(node["server_port"].(int))))
				node["detour"] = "entry"
				nodes = append(nodes, entry.node("socks", "entry"))
			}
			client := wireBox(t, nodes...)
			proxy, ok := client.Outbound().Outbound("exit")
			if !ok {
				t.Fatal("registered VLESS missing")
			}
			if e := payloadWire(t, proxy, target.listener.Addr().String()); e != nil {
				t.Fatal(e)
			}
			if target.calls.Load() != 1 {
				t.Fatal("VLESS payload bypassed or duplicated target")
			}
			if entry != nil && entry.calls.Load() < 1 {
				t.Fatal("XHTTP bypassed actual SOCKS entry")
			}
		})
	}
}
func TestRegisteredVLESSBadUUIDAndTLSIdentityCannotDialTargetDirectly(t *testing.T) {
	for _, failure := range []string{"uuid", "certificate", "server-name", "refused"} {
		t.Run(failure, func(t *testing.T) {
			target := listenWire(t, func(c net.Conn) { _, _ = io.Copy(c, c) })
			node, server := vlessWire(t, "tls")
			switch failure {
			case "uuid":
				node["uuid"] = wireUUID(t)
			case "certificate":
				other, _, _ := wireTLS(t)
				node["tls"].(map[string]any)["certificate"] = []string{other}
			case "server-name":
				node["tls"].(map[string]any)["server_name"] = "wrong.example.invalid"
			case "refused":
				if e := server.Close(); e != nil {
					t.Fatal(e)
				}
			}
			client := wireBox(t, node)
			proxy, _ := client.Outbound().Outbound("exit")
			if e := payloadWire(t, proxy, target.listener.Addr().String()); e == nil {
				t.Fatal("invalid VLESS authority succeeded")
			}
			if target.calls.Load() != 0 {
				t.Fatal("failed VLESS escaped through direct fallback")
			}
		})
	}
}

func sshWire(t *testing.T, destination string) (*wireFixture, string) {
	t.Helper()
	_, private, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	signer, e := ssh.NewSignerFromKey(private)
	if e != nil {
		t.Fatal(e)
	}
	config := &ssh.ServerConfig{PasswordCallback: func(metadata ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
		if metadata.User() != "fixture" || string(password) != "fixture-pass" {
			return nil, errors.New("denied")
		}
		return nil, nil
	}}
	config.AddHostKey(signer)
	fixture := listenWire(t, func(c net.Conn) {
		connection, channels, requests, e := ssh.NewServerConn(c, config)
		if e != nil {
			return
		}
		defer connection.Close()
		go ssh.DiscardRequests(requests)
		var workers sync.WaitGroup
		defer workers.Wait()
		for request := range channels {
			if request.ChannelType() != "direct-tcpip" {
				_ = request.Reject(ssh.UnknownChannelType, "unsupported")
				continue
			}
			var payload struct {
				Host       string
				Port       uint32
				Origin     string
				OriginPort uint32
			}
			if ssh.Unmarshal(request.ExtraData(), &payload) != nil || net.JoinHostPort(payload.Host, strconv.Itoa(int(payload.Port))) != destination {
				_ = request.Reject(ssh.Prohibited, "destination denied")
				continue
			}
			upstream, e := net.DialTimeout("tcp", destination, time.Second)
			if e != nil {
				_ = request.Reject(ssh.ConnectionFailed, "unavailable")
				continue
			}
			_ = upstream.SetDeadline(time.Now().Add(3 * time.Second))
			channel, reqs, e := request.Accept()
			if e != nil {
				upstream.Close()
				continue
			}
			go ssh.DiscardRequests(reqs)
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer channel.Close()
				defer upstream.Close()
				done := make(chan struct{})
				go func() { _, _ = io.Copy(upstream, channel); _ = upstream.Close(); close(done) }()
				_, _ = io.Copy(channel, upstream)
				_ = channel.Close()
				<-done
			}()
		}
	})
	return fixture, string(ssh.MarshalAuthorizedKey(signer.PublicKey()))
}
func TestRegisteredSSHPasswordHostKeyAndActualChannelPayload(t *testing.T) {
	for _, failure := range []string{"none", "password", "host-key", "refused"} {
		t.Run(failure, func(t *testing.T) {
			target := listenWire(t, func(c net.Conn) { _, _ = io.Copy(c, c) })
			server, hostKey := sshWire(t, target.listener.Addr().String())
			node := server.node("ssh", "exit")
			node["user"] = "fixture"
			node["password"] = "fixture-pass"
			node["host_key"] = []string{hostKey}
			if failure == "password" {
				node["password"] = "wrong-pass"
			}
			if failure == "host-key" {
				_, other, e := ed25519.GenerateKey(rand.Reader)
				if e != nil {
					t.Fatal(e)
				}
				signer, e := ssh.NewSignerFromKey(other)
				if e != nil {
					t.Fatal(e)
				}
				node["host_key"] = []string{string(ssh.MarshalAuthorizedKey(signer.PublicKey()))}
			}
			if failure == "refused" {
				_ = server.listener.Close()
			}
			client := wireBox(t, node)
			proxy, _ := client.Outbound().Outbound("exit")
			e := payloadWire(t, proxy, target.listener.Addr().String())
			if failure == "none" {
				if e != nil {
					t.Fatal(e)
				}
				if target.calls.Load() != 1 {
					t.Fatal("SSH channel did not reach target exactly once")
				}
			} else {
				if e == nil {
					t.Fatal("invalid SSH authority succeeded")
				}
				if target.calls.Load() != 0 {
					t.Fatal("failed SSH bypassed host-key/authentication")
				}
			}
		})
	}
}
