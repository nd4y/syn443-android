package netbird

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/embed"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
)

func deferredFixture(t *testing.T) *Deferred {
	t.Helper()
	ctx := service.ContextWithDefaultRegistry(context.Background())
	service.MustRegister[adapter.OutboundManager](ctx, fakeManager{})
	value, err := NewDeferredOutbound(ctx, nil, logger.NOP(), "overlay", OutboundOptions{
		ConnectionMode: "vless", ManagementURL: "https://example.invalid", SetupKey: "synthetic-key", StateDirectory: t.TempDir(), DialerOptions: option.DialerOptions{Detour: "vless"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return value.(*Deferred)
}
func TestOptionalEnrollmentDoesNotHoldGlobalStartAndPrivateDialFailsClosed(t *testing.T) {
	d := deferredFixture(t)
	peer := &pendingPeer{entered: make(chan struct{})}
	d.current.newClient = func(embed.Options) (peerClient, error) { return peer, nil }
	started := time.Now()
	if err := d.Start(adapter.StartStateStarted); err != nil {
		t.Fatal(err)
	}
	if time.Since(started) > 100*time.Millisecond {
		t.Fatal("optional startup blocked global barrier")
	}
	select {
	case <-peer.entered:
	case <-time.After(time.Second):
		t.Fatal("optional client did not start")
	}
	if conn, err := d.DialContext(context.Background(), "tcp", M.ParseSocksaddr("198.51.100.7:443")); err == nil || conn != nil {
		t.Fatal("unready private route fell through")
	}
	stopped := time.Now()
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	if time.Since(stopped) > time.Second || peer.stops.Load() != 1 {
		t.Fatal("startup cancellation did not clean up")
	}
}

type stuckPeer struct {
	peerClient
	entered, release chan struct{}
}

func (p *stuckPeer) Start(context.Context) error {
	close(p.entered)
	<-p.release
	return context.Canceled
}
func (p *stuckPeer) Stop(context.Context) error { return embed.ErrClientNotStarted }
func TestUnconfirmedCleanupCannotCreateASecondIdentityOwner(t *testing.T) {
	d := deferredFixture(t)
	d.startupTimeout = 40 * time.Millisecond
	d.cleanupTimeout = 40 * time.Millisecond
	peer := &stuckPeer{entered: make(chan struct{}), release: make(chan struct{})}
	d.current.newClient = func(embed.Options) (peerClient, error) { return peer, nil }
	d.makePeer = func() (*Outbound, error) {
		t.Error("replacement constructed before cleanup proof")
		return nil, net.ErrClosed
	}
	d.Start(adapter.StartStateStarted)
	select {
	case <-peer.entered:
	case <-time.After(time.Second):
		t.Fatal("startup did not begin")
	}
	select {
	case <-d.done:
	case <-time.After(time.Second):
		t.Fatal("uncooperative dependency blocked optional coordinator")
	}
	if state := d.state.Load().(moduleState); state.Phase != "NeedsAction" || state.Reason != "cleanup_unconfirmed" {
		t.Fatal("missing uncertain cleanup state")
	}
	close(peer.release)
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		release, err := acquireIdentity(d.options.StateDirectory)
		if err == nil {
			release()
			releaseProcess, err := acquirePeerProcess()
			if err == nil {
				releaseProcess()
				d.Close()
				return
			}
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("eventual cleanup did not release identity")
}
func TestCorruptedRetryCheckpointRequiresActionWithoutEnrollment(t *testing.T) {
	d := deferredFixture(t)
	if err := os.WriteFile(filepath.Join(d.options.StateDirectory, "syn443-retry.json"), []byte(`{"attempt":31}`), 0600); err != nil {
		t.Fatal(err)
	}
	d.current.newClient = func(embed.Options) (peerClient, error) {
		t.Error("enrollment crossed an invalid checkpoint")
		return nil, net.ErrClosed
	}
	d.Start(adapter.StartStateStarted)
	select {
	case <-d.done:
	case <-time.After(time.Second):
		t.Fatal("invalid checkpoint was retried")
	}
	if d.state.Load().(moduleState).Reason != "retry_checkpoint_invalid" {
		t.Fatal("invalid checkpoint was silently reset")
	}
	d.Close()
}

type rejectedPeer struct{ peerClient }

func (*rejectedPeer) Start(context.Context) error {
	return status.Error(codes.PermissionDenied, "enrollment rejected")
}
func (*rejectedPeer) Stop(context.Context) error { return embed.ErrClientNotStarted }
func TestRejectedEnrollmentRequiresActionInsteadOfRetryingForever(t *testing.T) {
	d := deferredFixture(t)
	d.current.newClient = func(embed.Options) (peerClient, error) { return &rejectedPeer{}, nil }
	d.makePeer = func() (*Outbound, error) { t.Error("authorization rejection retried"); return nil, net.ErrClosed }
	d.Start(adapter.StartStateStarted)
	select {
	case <-d.done:
	case <-time.After(time.Second):
		t.Fatal("authorization rejection did not finish")
	}
	state := d.state.Load().(moduleState)
	if state.Phase != "NeedsAction" || state.Reason != "enrollment_rejected" || !strings.Contains(state.Failure, "PermissionDenied") {
		t.Fatal("missing actionable diagnostic")
	}
	d.Close()
}
func TestStartupFailureRedactsCredentialsBeforeBoundingText(t *testing.T) {
	key := "synthetic-enrollment-value"
	secret := strings.Repeat("A", 43) + "="
	message := "setup_key=" + strings.ToUpper(key) + " " + secret + " https://" + "user:placeholder@" + "example.invalid/path\n" + strings.Repeat("x", 600)
	result := redactStartupFailure(errors.New(message), key)
	if strings.Contains(result, strings.ToUpper(key)) || strings.Contains(result, secret) || strings.Contains(result, "placeholder") || strings.Contains(result, "\n") || len([]rune(result)) > 512 {
		t.Fatal("unsafe startup diagnostic")
	}
}
