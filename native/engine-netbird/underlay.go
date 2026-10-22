package netbird

import (
	"context"
	"errors"
	"net"
	"sync"
)

type tcpDialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}

// trackedUnderlay never resolves names itself and never falls back to net.Dial.
// The selected VLESS outbound receives the original management/relay hostname.
type trackedUnderlay struct {
	dialer      tcpDialer
	ctx         context.Context
	cancel      context.CancelFunc
	epoch       context.Context
	cancelEpoch context.CancelFunc
	mu          sync.Mutex
	closed      bool
	connections map[*trackedConn]struct{}
}

func newUnderlay(ctx context.Context, dialer tcpDialer) *trackedUnderlay {
	ctx, cancel := context.WithCancel(ctx)
	epoch, cancelEpoch := context.WithCancel(ctx)
	return &trackedUnderlay{dialer: dialer, ctx: ctx, cancel: cancel, epoch: epoch, cancelEpoch: cancelEpoch, connections: make(map[*trackedConn]struct{})}
}

func (u *trackedUnderlay) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, errors.New("netbird chained underlay only permits TCP")
	}
	ctx, cancel := context.WithCancel(ctx)
	u.mu.Lock()
	epoch := u.epoch
	u.mu.Unlock()
	stop := context.AfterFunc(epoch, cancel)
	defer stop()
	defer cancel()
	if epoch.Err() != nil {
		return nil, net.ErrClosed
	}
	conn, err := u.dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.closed || ctx.Err() != nil || epoch.Err() != nil {
		conn.Close()
		return nil, net.ErrClosed
	}
	c := &trackedConn{Conn: conn, owner: u}
	u.connections[c] = struct{}{}
	return c, nil
}

// Reset drops old-network connections; NetBird retries through the same detour.
func (u *trackedUnderlay) Reset() {
	u.mu.Lock()
	u.cancelEpoch()
	u.epoch, u.cancelEpoch = context.WithCancel(u.ctx)
	connections := make([]*trackedConn, 0, len(u.connections))
	for conn := range u.connections {
		connections = append(connections, conn)
	}
	u.mu.Unlock()
	for _, conn := range connections {
		conn.Close()
	}
}

func (u *trackedUnderlay) Close() {
	u.mu.Lock()
	u.closed = true
	u.mu.Unlock()
	u.cancel()
	u.Reset()
}

type trackedConn struct {
	net.Conn
	owner *trackedUnderlay
	once  sync.Once
	err   error
}

func (c *trackedConn) Close() error {
	c.once.Do(func() {
		c.owner.mu.Lock()
		delete(c.owner.connections, c)
		c.owner.mu.Unlock()
		c.err = c.Conn.Close()
	})
	return c.err
}
