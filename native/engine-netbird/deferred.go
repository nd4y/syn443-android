// SPDX-License-Identifier: GPL-3.0-or-later
package netbird

import (
	"context"
	"encoding/json"
	"errors"
	"math/rand/v2"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	M "github.com/sagernet/sing/common/metadata"
)

// Optional overlay startup must never hold the global sing-box start barrier.
// A failed/starting overlay remains selected by its private route and fails closed.
type Deferred struct {
	adapter.Outbound
	mu             sync.RWMutex
	current        *Outbound
	makePeer       func() (*Outbound, error)
	ctx            context.Context
	cancel         context.CancelFunc
	done           chan struct{}
	once           sync.Once
	state          atomic.Value
	report         atomic.Value
	diagnostics    atomic.Value
	options        OutboundOptions
	startupTimeout time.Duration
	cleanupTimeout time.Duration
}
type retryState struct {
	Attempt int   `json:"attempt"`
	Next    int64 `json:"next_at_ms"`
}
type moduleState struct {
	Active  bool       `json:"active"`
	Phase   string     `json:"phase"`
	Reason  string     `json:"reason"`
	Mode    string     `json:"mode"`
	Retry   retryState `json:"retry"`
	Sampled int64      `json:"sampled_at_ms"`
}

var deferredPeer struct {
	sync.RWMutex
	current *Deferred
}

func NewDeferredOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options OutboundOptions) (adapter.Outbound, error) {
	ctx, cancel := context.WithCancel(ctx)
	makePeer := func() (*Outbound, error) {
		peer, err := NewOutbound(ctx, router, logger, tag, options)
		if err != nil {
			return nil, err
		}
		return peer.(*Outbound), nil
	}
	peer, err := makePeer()
	if err != nil {
		cancel()
		return nil, err
	}
	d := &Deferred{Outbound: peer, current: peer, makePeer: makePeer, ctx: ctx, cancel: cancel, done: make(chan struct{}), options: peer.options, startupTimeout: 46 * time.Second, cleanupTimeout: 16 * time.Second}
	d.state.Store(moduleState{Active: true, Phase: "Configured", Mode: peer.options.ConnectionMode})
	d.report.Store(`{"active":false,"peers":[]}`)
	d.diagnostics.Store(`{"state":"unavailable","results":[]}`)
	deferredPeer.Lock()
	deferredPeer.current = d
	deferredPeer.Unlock()
	return d, nil
}
func (d *Deferred) set(phase, reason string, retry retryState) {
	d.state.Store(moduleState{true, phase, reason, d.options.ConnectionMode, retry, time.Now().UnixMilli()})
}
func (d *Deferred) Start(stage adapter.StartStage) error {
	if stage == adapter.StartStateStarted {
		d.once.Do(func() { go d.run() })
	}
	return nil
}
func (d *Deferred) getClient() (peerClient, error) {
	d.mu.RLock()
	peer := d.current
	d.mu.RUnlock()
	if peer == nil {
		return nil, net.ErrClosed
	}
	return peer.getClient()
}
func (d *Deferred) DialContext(ctx context.Context, network string, address M.Socksaddr) (net.Conn, error) {
	d.mu.RLock()
	peer := d.current
	d.mu.RUnlock()
	if peer == nil {
		return nil, net.ErrClosed
	}
	return peer.DialContext(ctx, network, address)
}
func (d *Deferred) ListenPacket(ctx context.Context, address M.Socksaddr) (net.PacketConn, error) {
	d.mu.RLock()
	peer := d.current
	d.mu.RUnlock()
	if peer == nil {
		return nil, net.ErrClosed
	}
	return peer.ListenPacket(ctx, address)
}
func (d *Deferred) InterfaceUpdated() {
	d.mu.RLock()
	peer := d.current
	d.mu.RUnlock()
	if peer != nil {
		peer.InterfaceUpdated()
	}
}
func stopBounded(peer *Outbound, timeout time.Duration) error {
	result := make(chan error, 1)
	go func() { result <- peer.Close() }()
	select {
	case err := <-result:
		return err
	case <-time.After(timeout):
		return errors.New("overlay cleanup deadline")
	}
}
func (d *Deferred) run() {
	defer close(d.done)
	retry := retryState{}
	if err := os.MkdirAll(d.options.StateDirectory, 0700); err != nil {
		d.set("NeedsAction", "state_unavailable", retry)
		return
	}
	path := filepath.Join(d.options.StateDirectory, "syn443-retry.json")
	if data, err := os.ReadFile(path); err == nil {
		if len(data) > 4096 || json.Unmarshal(data, &retry) != nil || retry.Attempt < 0 || retry.Attempt > 30 || retry.Next < 0 {
			d.set("NeedsAction", "retry_checkpoint_invalid", retryState{})
			return
		}
	} else if !os.IsNotExist(err) {
		d.set("NeedsAction", "state_unavailable", retry)
		return
	}
	for {
		now := time.Now().UnixMilli()
		if retry.Next > now+60_000 {
			retry.Next = now + 60_000
			if writeRetry(path, retry) != nil {
				d.set("NeedsAction", "state_unavailable", retry)
				return
			}
		}
		if wait := time.Duration(retry.Next-now) * time.Millisecond; wait > 0 {
			d.set("Recovering", "retry_scheduled", retry)
			select {
			case <-d.ctx.Done():
				return
			case <-time.After(wait):
			}
		}
		if d.ctx.Err() != nil {
			return
		}
		if strings.TrimSpace(d.options.SetupKey) == "" {
			if _, err := os.Stat(filepath.Join(d.options.StateDirectory, "config.json")); err != nil {
				d.set("NeedsAction", "enrollment_required", retry)
				return
			}
		}
		d.mu.RLock()
		peer := d.current
		d.mu.RUnlock()
		if peer == nil {
			var err error
			peer, err = d.makePeer()
			if err != nil {
				d.set("NeedsAction", "capability_invalid", retry)
				return
			}
			d.mu.Lock()
			d.current = peer
			d.mu.Unlock()
		}
		d.set("Starting", "overlay_start", retry)
		result := make(chan error, 1)
		go func() { result <- peer.Start(adapter.StartStateStarted) }()
		var err error
		select {
		case err = <-result:
		case <-d.ctx.Done():
			err = d.ctx.Err()
		case <-time.After(d.startupTimeout):
			err = errors.New("overlay startup deadline")
		}
		if err == nil {
			d.set("Started", "client_started", retry)
			// One sampler only. If recorder access stalls, cache age reveals stale
			// diagnostics; neither the native host heartbeat nor other routes block.
			go func() {
				ticker := time.NewTicker(5 * time.Second)
				defer ticker.Stop()
				stableSince := time.Time{}
				for {
					report := RuntimeStatus()
					d.report.Store(report)
					d.diagnostics.Store(RuntimeDiagnostics())
					var snapshot struct {
						Management bool `json:"management_connected"`
						Signal     bool `json:"signal_connected"`
					}
					if json.Unmarshal([]byte(report), &snapshot) == nil && snapshot.Management && snapshot.Signal {
						if stableSince.IsZero() {
							stableSince = time.Now()
						}
						if retry.Attempt > 0 && time.Since(stableSince) >= 30*time.Second {
							retry = retryState{}
							if writeRetry(path, retry) != nil {
								d.set("NeedsAction", "state_unavailable", retry)
								return
							}
							d.set("Started", "control_session_stable", retry)
						}
					} else {
						stableSince = time.Time{}
					}
					select {
					case <-d.ctx.Done():
						return
					case <-ticker.C:
					}
				}
			}()
			<-d.ctx.Done()
			_ = stopBounded(peer, d.cleanupTimeout)
			return
		}
		if stopBounded(peer, d.cleanupTimeout) != nil {
			d.set("NeedsAction", "cleanup_unconfirmed", retry)
			return
		}
		d.mu.Lock()
		d.current = nil
		d.mu.Unlock()
		if d.ctx.Err() != nil {
			return
		}
		retry.Attempt = min(30, retry.Attempt+1)
		delay := min(60_000.0, float64(int64(1000)<<min(retry.Attempt-1, 6))) * (0.8 + 0.4*rand.Float64())
		retry.Next = time.Now().UnixMilli() + int64(max(1000.0, min(60_000.0, delay)))
		if writeRetry(path, retry) != nil {
			d.set("NeedsAction", "state_unavailable", retry)
			return
		}
		d.set("Recovering", "overlay_unavailable", retry)
	}
}
func writeRetry(path string, state retryState) error {
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".retry-")
	if err != nil {
		return err
	}
	name := file.Name()
	defer os.Remove(name)
	if _, err = file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err = file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}
func (d *Deferred) Close() error {
	d.cancel()
	d.once.Do(func() { close(d.done) })
	select {
	case <-d.done:
		return nil
	case <-time.After(d.cleanupTimeout + time.Second):
		return errors.New("overlay stop deadline")
	}
}

// Cached diagnostics only; no SDK locks/network calls on the host control loop.
func DeferredStatus() string {
	deferredPeer.RLock()
	peer := deferredPeer.current
	deferredPeer.RUnlock()
	if peer == nil {
		return `{"active":false,"phase":"Off"}`
	}
	result := struct {
		moduleState
		PeerState   json.RawMessage `json:"peer_state"`
		Diagnostics json.RawMessage `json:"diagnostics"`
	}{peer.state.Load().(moduleState), json.RawMessage(peer.report.Load().(string)), json.RawMessage(peer.diagnostics.Load().(string))}
	data, err := json.Marshal(result)
	if err != nil || len(data) > 65536 {
		return `{"active":true,"phase":"Unknown","reason":"diagnostics_unavailable"}`
	}
	return string(data)
}
