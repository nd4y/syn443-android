package netbird

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-vmess/vless"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type vlessEchoHandler struct{ destinations chan string }

func (h *vlessEchoHandler) NewConnectionEx(_ context.Context, conn net.Conn, _ M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	h.destinations <- destination.String()
	go func() {
		_, err := io.Copy(conn, conn)
		conn.Close()
		if onClose != nil {
			onClose(err)
		}
	}()
}
func (*vlessEchoHandler) NewPacketConnectionEx(_ context.Context, conn N.PacketConn, _, _ M.Socksaddr, onClose N.CloseHandlerFunc) {
	conn.Close()
	if onClose != nil {
		onClose(nil)
	}
}

// This test uses the real VLESS wire codec and a loopback proxy listener. The
// target hostname deliberately cannot resolve locally; the proxy sees it intact.
func TestUnderlayThroughRealVLESS(t *testing.T) {
	const uuid = "8c64ab05-baf0-45c2-af5f-d7c776e71f97"
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	handler := &vlessEchoHandler{destinations: make(chan string, 1)}
	service := vless.NewService[string](logger.NOP(), handler)
	service.UpdateUsers([]string{"test"}, []string{uuid}, []string{""})
	serverErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			conn.SetDeadline(time.Now().Add(3 * time.Second))
			err = service.NewConnection(context.Background(), conn, M.ParseSocksaddr(conn.RemoteAddr().String()), nil)
		}
		serverErr <- err
	}()
	client, err := vless.NewClient(uuid, "", logger.NOP())
	if err != nil {
		t.Fatal(err)
	}
	u := newUnderlay(context.Background(), dialFunc(func(ctx context.Context, _, address string) (net.Conn, error) {
		conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", listener.Addr().String())
		if err != nil {
			return nil, err
		}
		proxied, err := client.DialConn(conn, M.ParseSocksaddr(address))
		if err != nil {
			conn.Close()
		}
		return proxied, err
	}))
	defer u.Close()
	conn, err := u.DialContext(context.Background(), "tcp", "relay.invalid:443")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write([]byte("netbird transport")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len("netbird transport"))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "netbird transport" {
		t.Fatalf("bad echo %q", got)
	}
	select {
	case destination := <-handler.destinations:
		if destination != "relay.invalid:443" {
			t.Fatal(destination)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("VLESS did not receive the target")
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
}
