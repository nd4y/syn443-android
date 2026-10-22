package netbird

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"sync/atomic"
	"testing"
	"time"

	"github.com/netbirdio/netbird/client/embed"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
)

type fakeManager struct{ adapter.OutboundManager }

func (fakeManager) Outbound(string) (adapter.Outbound, bool) { return fakeVLESS{}, true }

type fakeVLESS struct{ adapter.Outbound }

func (fakeVLESS) Type() string { return "vless" }

type pendingPeer struct {
	peerClient
	entered chan struct{}
	stops   atomic.Int32
}

func (p *pendingPeer) Start(ctx context.Context) error {
	close(p.entered)
	<-ctx.Done()
	return ctx.Err()
}
func (p *pendingPeer) Stop(context.Context) error { p.stops.Add(1); return embed.ErrClientNotStarted }

func TestCloseCancelsEnrollmentWithoutWaitingForStartupTimeout(t *testing.T) {
	peer := &pendingPeer{entered: make(chan struct{})}
	dir := t.TempDir()
	o := &Outbound{
		ctx: context.Background(), logger: logger.NOP(), manager: fakeManager{},
		options: OutboundOptions{DialerOptions: option.DialerOptions{Detour: "vless"}, StateDirectory: dir, SetupKey: "test-key"},
		newClient: func(options embed.Options) (peerClient, error) {
			if options.UnderlayDialer == nil || !options.BlockInbound || !options.DisableIPv6 {
				t.Fatal("unsafe native options")
			}
			return peer, nil
		},
	}
	started := make(chan error, 1)
	go func() { started <- o.Start(adapter.StartStateStarted) }()
	select {
	case <-peer.entered:
	case <-time.After(time.Second):
		t.Fatal("enrollment did not begin")
	}
	closed := make(chan error, 1)
	go func() { closed <- o.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close blocked on enrollment")
	}
	if err := <-started; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if peer.stops.Load() != 1 {
		t.Fatal("client cleanup did not run")
	}
	if _, err := o.getClient(); !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
	release, err := acquireIdentity(dir)
	if err != nil {
		t.Fatal("identity lock not released:", err)
	}
	release()
}

func TestIdentityLockAcrossProcesses(t *testing.T) {
	if directory := os.Getenv("NEKO_NETBIRD_LOCK_TEST"); directory != "" {
		release, err := acquireIdentity(directory)
		if err == nil {
			release()
			t.Fatal("child acquired parent's identity")
		}
		return
	}
	directory := t.TempDir()
	release, err := acquireIdentity(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	cmd := exec.Command(os.Args[0], "-test.run=^TestIdentityLockAcrossProcesses$")
	cmd.Env = append(os.Environ(), "NEKO_NETBIRD_LOCK_TEST="+directory)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("child: %v\n%s", err, output)
	}
	release()
	reacquired, err := acquireIdentity(directory)
	if err != nil {
		t.Fatal(err)
	}
	reacquired()
}

func TestProcessLeasePreventsConcurrentConstruction(t *testing.T) {
	release, err := acquirePeerProcess()
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if second, err := acquirePeerProcess(); err == nil {
		second()
		t.Fatal("concurrent construction permitted")
	}
	release()
	next, err := acquirePeerProcess()
	if err != nil {
		t.Fatal(err)
	}
	next()
}
