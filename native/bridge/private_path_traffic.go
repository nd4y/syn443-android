package bridge

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// A real socket owns its candidate reference until confirmed Close. No raw
// adapter or connection is exposed through the public bridge/policy interface.
type privateFlowOwner struct {
	hold           *privatePathHold
	closeSocket    func() error
	cancel         context.CancelFunc
	stop           func() bool
	once           sync.Once
	closed         atomic.Bool
	err            error
	operations     int
	closeConfirmed bool
	released       bool
	probe          *privateProbeDialObservation
	hint           privatePathHintFlow
}

func (f *privateFlowOwner) valid() bool {
	p, e := f.hold.pool, f.hold.entry
	p.mu.Lock()
	defer p.mu.Unlock()
	return f.validLocked(p, e)
}

func (f *privateFlowOwner) validLocked(p *privatePathPool, e *privatePoolEntry) bool {
	p.expireDrainsLocked()
	return !f.closed.Load() && !f.hold.closed.Load() && !p.closed && p.ctx.Err() == nil && privateManagedLease(p.lease) && p.homeCurrent() && p.entries[e.id] == e && p.scope == e.scope && !e.queued && e.path.ctx.Err() == nil
}
func (f *privateFlowOwner) begin() bool {
	p, e := f.hold.pool, f.hold.entry
	p.mu.Lock()
	defer p.mu.Unlock()
	if !f.validLocked(p, e) || p.operations >= 256 || f.operations >= 4 {
		if f.probe != nil {
			f.probe.localRefusal.Store(true)
		}
		return false
	}
	p.operations++
	f.operations++
	return true
}
func (f *privateFlowOwner) end() bool {
	return f.endObserved(nil, false)
}
func (f *privateFlowOwner) endObserved(err error, panicked bool) bool {
	p, e := f.hold.pool, f.hold.entry
	p.mu.Lock()
	valid := f.validLocked(p, e)
	if valid {
		f.hint.observeLocked(p, e, err, panicked)
	}
	f.operations--
	p.operations--
	release := f.closeConfirmed && f.operations == 0 && !f.released
	if release {
		f.released = true
	}
	p.mu.Unlock()
	if release {
		_ = f.hold.Close()
	}
	return valid
}

func (f *privateFlowOwner) Close() error {
	f.once.Do(func() {
		f.closed.Store(true)
		f.stop()
		f.cancel()
		// Even an error/panic can leave a socket alive. Keep its reservation
		// until confirmed owner recovery, rather than retrying with new work.
		failed := true
		func() {
			defer func() {
				if recover() != nil {
					f.err = errPrivatePath
				}
			}()
			failed = f.closeSocket() != nil
			if failed {
				f.err = errPrivatePath
			}
		}()
		p, e := f.hold.pool, f.hold.entry
		p.mu.Lock()
		if failed {
			e.retained = true
			e.cancel()
		} else {
			f.closeConfirmed = true
			delete(e.flows, f)
		}
		release := !failed && f.operations == 0 && !f.released
		if release {
			f.released = true
		}
		p.mu.Unlock()
		if release {
			_ = f.hold.Close()
		}
	})
	return f.err
}

func (f *privateFlowOwner) String() string   { return "PrivateFlow([redacted])" }
func (f *privateFlowOwner) GoString() string { return f.String() }

type privateTCPFlow struct {
	net.Conn
	owner *privateFlowOwner
}

func (f *privateTCPFlow) Close() error { return f.owner.Close() }

// Preserve lazy protocol handshakes without exposing an unwrap/raw socket that
// could bypass the owner fences. TCP probes must actually contact their target.
func (f *privateTCPFlow) NeedHandshake() bool { return N.NeedHandshakeForWrite(f.Conn) }
func (f *privateTCPFlow) Read(b []byte) (n int, err error) {
	if !f.owner.begin() {
		return 0, errPrivatePath
	}
	defer func() {
		panicked := false
		if recover() != nil {
			panicked = true
			f.owner.hold.retain()
			n = 0
			err = errPrivatePath
		}
		if !f.owner.endObserved(err, panicked) {
			n = 0
			err = errPrivatePath
		}
	}()
	return f.Conn.Read(b)
}
func (f *privateTCPFlow) Write(b []byte) (n int, err error) {
	if !f.owner.begin() {
		return 0, errPrivatePath
	}
	defer func() {
		panicked := false
		if recover() != nil {
			panicked = true
			f.owner.hold.retain()
			n = 0
			err = errPrivatePath
		}
		if !f.owner.endObserved(err, panicked) {
			n = 0
			err = errPrivatePath
		}
	}()
	return f.Conn.Write(b)
}
func (f *privateTCPFlow) String() string   { return f.owner.String() }
func (f *privateTCPFlow) GoString() string { return f.String() }

type privateUDPFlow struct {
	net.PacketConn
	owner *privateFlowOwner
}

func (f *privateUDPFlow) Close() error { return f.owner.Close() }
func (f *privateUDPFlow) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	if !f.owner.begin() {
		return 0, nil, errPrivatePath
	}
	defer func() {
		if recover() != nil {
			f.owner.hold.retain()
			n = 0
			addr = nil
			err = errPrivatePath
		}
		if !f.owner.end() {
			n = 0
			addr = nil
			err = errPrivatePath
		}
	}()
	return f.PacketConn.ReadFrom(b)
}
func (f *privateUDPFlow) WriteTo(b []byte, a net.Addr) (n int, err error) {
	if !f.owner.begin() {
		return 0, errPrivatePath
	}
	defer func() {
		if recover() != nil {
			f.owner.hold.retain()
			n = 0
			err = errPrivatePath
		}
		if !f.owner.end() {
			n = 0
			err = errPrivatePath
		}
	}()
	return f.PacketConn.WriteTo(b, a)
}
func (f *privateUDPFlow) String() string   { return f.owner.String() }
func (f *privateUDPFlow) GoString() string { return f.String() }

func (h *privatePathHold) dialContext(parent context.Context) (context.Context, context.CancelFunc, func() bool) {
	duration := 30 * time.Second
	remaining := h.pool.lease.state.Load().deadline - h.pool.lease.clock()
	if remaining < 30_000 {
		duration = time.Duration(remaining) * time.Millisecond
	}
	if duration <= 0 {
		duration = time.Nanosecond
	}
	ctx, cancel := context.WithTimeout(parent, duration)
	stop := context.AfterFunc(h.entry.path.ctx, cancel)
	return ctx, cancel, stop
}

func (h *privatePathHold) attach(closeSocket func() error, cancel context.CancelFunc, stop func() bool, probe *privateProbeDialObservation) *privateFlowOwner {
	f := &privateFlowOwner{hold: h, closeSocket: closeSocket, cancel: cancel, stop: stop, probe: probe}
	p, e := h.pool, h.entry
	p.mu.Lock()
	e.flows[f] = struct{}{}
	p.mu.Unlock()
	return f
}

// Selection/probe admission is deliberately a separate, still unactivated gate.
// These helpers only enforce actual socket ownership, current context and lease.
func (c *privatePathCandidate) dialTCP(scope string, parent context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if parent == nil || parent.Err() != nil || network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, errPrivatePath
	}
	h, err := c.hold(scope)
	if err != nil {
		return nil, err
	}
	return h.dialTCP(scope, parent, network, destination)
}

// Takes ownership of a hold acquired atomically with the current selection.
func (h *privatePathHold) dialTCP(scope string, parent context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if parent == nil || parent.Err() != nil || network != "tcp" && network != "tcp4" && network != "tcp6" {
		_ = h.Close()
		return nil, errPrivatePath
	}
	node, err := h.outbound(scope)
	if err != nil {
		_ = h.Close()
		return nil, errPrivatePath
	}
	ctx, cancel, stop := h.dialContext(parent)
	conn, dialErr, panicked := privateSafeTCPDial(node, ctx, network, destination)
	if panicked {
		stop()
		cancel()
		h.retain()
		return nil, errPrivatePath
	}
	if conn == nil {
		stop()
		cancel()
		_ = h.Close()
		return nil, errPrivatePath
	}
	probe, _ := parent.Value(privateProbeDialKey{}).(*privateProbeDialObservation)
	f := h.attach(conn.Close, cancel, stop, probe)
	if dialErr != nil || ctx.Err() != nil || !f.valid() {
		_ = f.Close()
		return nil, errPrivatePath
	}
	return &privateTCPFlow{Conn: conn, owner: f}, nil
}

func (c *privatePathCandidate) listenUDP(scope string, parent context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if parent == nil || parent.Err() != nil {
		return nil, errPrivatePath
	}
	h, err := c.hold(scope)
	if err != nil {
		return nil, err
	}
	node, err := h.outbound(scope)
	if err != nil {
		_ = h.Close()
		return nil, errPrivatePath
	}
	ctx, cancel, stop := h.dialContext(parent)
	conn, dialErr, panicked := privateSafeUDPListen(node, ctx, destination)
	if panicked {
		stop()
		cancel()
		h.retain()
		return nil, errPrivatePath
	}
	if conn == nil {
		stop()
		cancel()
		_ = h.Close()
		return nil, errPrivatePath
	}
	f := h.attach(conn.Close, cancel, stop, nil)
	if dialErr != nil || ctx.Err() != nil || !f.valid() {
		_ = f.Close()
		return nil, errPrivatePath
	}
	return &privateUDPFlow{PacketConn: conn, owner: f}, nil
}

func (h *privatePathHold) retain() {
	p, e := h.pool, h.entry
	p.mu.Lock()
	e.retained = true
	e.cancel()
	p.mu.Unlock()
}

func privateSafeTCPDial(node adapter.Outbound, ctx context.Context, network string, dst M.Socksaddr) (conn net.Conn, err error, panicked bool) {
	var observation *privateProbeDialObservation
	defer func() {
		if recover() != nil {
			if observation != nil {
				observation.completed.Store(false)
				observation.validConn.Store(false)
				observation.returnedError.Store(false)
			}
			conn = nil
			err = errPrivatePath
			panicked = true
		}
	}()
	if ctx != nil {
		observation, _ = ctx.Value(privateProbeDialKey{}).(*privateProbeDialObservation)
	}
	if observation != nil {
		observation.completed.Store(false)
		observation.validConn.Store(false)
		observation.returnedError.Store(false)
		observation.dispatched.Store(true)
	}
	conn, err = node.DialContext(ctx, network, dst)
	if observation != nil {
		observation.validConn.Store(conn != nil)
		observation.returnedError.Store(err != nil)
		observation.completed.Store(true)
	}
	return
}
func privateSafeUDPListen(node adapter.Outbound, ctx context.Context, dst M.Socksaddr) (conn net.PacketConn, err error, panicked bool) {
	defer func() {
		if recover() != nil {
			conn = nil
			err = errPrivatePath
			panicked = true
		}
	}()
	conn, err = node.ListenPacket(ctx, dst)
	return
}
