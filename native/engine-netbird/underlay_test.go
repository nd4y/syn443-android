package netbird

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

type dialFunc func(context.Context, string, string) (net.Conn, error)

func (f dialFunc) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return f(ctx, network, address)
}

func TestUnderlayPreservesUnresolvableHostname(t *testing.T) {
	var calls int
	left, right := net.Pipe()
	defer right.Close()
	u := newUnderlay(context.Background(), dialFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
		calls++
		if network != "tcp" || address != "management.invalid:443" {
			t.Fatalf("unexpected destination %s %s", network, address)
		}
		return left, nil
	}))
	defer u.Close()
	conn, err := u.DialContext(context.Background(), "tcp", "management.invalid:443")
	if err != nil || calls != 1 {
		t.Fatalf("calls=%d err=%v", calls, err)
	}
	go func() { _, _ = right.Write([]byte("ok")) }()
	buf := make([]byte, 2)
	if n, err := conn.Read(buf); n != 2 || err != nil || string(buf) != "ok" {
		t.Fatalf("read %q: %v", buf, err)
	}
}

func TestUnderlayFailureNeverDialsDirect(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := listener.(*net.TCPListener).SetDeadline(time.Now().Add(150 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	want := errors.New("VLESS unavailable")
	var calls int
	u := newUnderlay(context.Background(), dialFunc(func(context.Context, string, string) (net.Conn, error) {
		calls++
		return nil, want
	}))
	defer u.Close()
	if _, err := u.DialContext(context.Background(), "tcp", listener.Addr().String()); !errors.Is(err, want) {
		t.Fatal(err)
	}
	if conn, err := listener.Accept(); err == nil {
		conn.Close()
		t.Fatal("direct fallback reached listener")
	}
	if calls != 1 {
		t.Fatalf("detour calls %d", calls)
	}
}

func TestUnderlayRejectsUDP(t *testing.T) {
	u := newUnderlay(context.Background(), dialFunc(func(context.Context, string, string) (net.Conn, error) {
		t.Fatal("UDP reached detour")
		return nil, nil
	}))
	defer u.Close()
	if _, err := u.DialContext(context.Background(), "udp", "stun.invalid:3478"); err == nil {
		t.Fatal("UDP accepted")
	}
}

func TestUnderlayCloseCancelsPendingDial(t *testing.T) {
	entered := make(chan struct{})
	done := make(chan error, 1)
	u := newUnderlay(context.Background(), dialFunc(func(ctx context.Context, _, _ string) (net.Conn, error) {
		close(entered)
		<-ctx.Done()
		return nil, ctx.Err()
	}))
	go func() { _, err := u.DialContext(context.Background(), "tcp", "relay.invalid:443"); done <- err }()
	<-entered
	u.Close()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("dial was not canceled")
	}
}

func TestUnderlayNetworkChangeCancelsPendingDial(t *testing.T) {
	entered := make(chan struct{})
	done := make(chan error, 1)
	u := newUnderlay(context.Background(), dialFunc(func(ctx context.Context, _, _ string) (net.Conn, error) {
		close(entered)
		<-ctx.Done()
		return nil, ctx.Err()
	}))
	defer u.Close()
	go func() { _, err := u.DialContext(context.Background(), "tcp", "relay.invalid:443"); done <- err }()
	<-entered
	u.Reset()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("old-network dial was not canceled")
	}
}

func TestUnderlayResetClosesConnectionsAndAllowsReconnect(t *testing.T) {
	var calls atomic.Int32
	peers := make(chan net.Conn, 2)
	u := newUnderlay(context.Background(), dialFunc(func(context.Context, string, string) (net.Conn, error) {
		calls.Add(1)
		left, right := net.Pipe()
		peers <- right
		return left, nil
	}))
	defer u.Close()
	first, err := u.DialContext(context.Background(), "tcp", "relay.invalid:443")
	if err != nil {
		t.Fatal(err)
	}
	peer := <-peers
	defer peer.Close()
	u.Reset()
	if _, err := first.Write([]byte("closed")); err == nil {
		t.Fatal("old connection remained open")
	}
	second, err := u.DialContext(context.Background(), "tcp", "relay.invalid:443")
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	peer = <-peers
	defer peer.Close()
	if calls.Load() != 2 {
		t.Fatal("did not reconnect")
	}
	u.Close()
	if _, err := u.DialContext(context.Background(), "tcp", "relay.invalid:443"); !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
}
