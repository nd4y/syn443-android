package bridge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
)

// The target performs an actual TCP reset only after a real data byte. TCP
// health probes connect/close without a byte and remain independent positive
// proofs; no injected hint or synthetic successful receipt selects a path.
func privateHintResetTarget(t *testing.T) *wireFixture {
	t.Helper()
	return listenWire(t, func(conn net.Conn) {
		var b [1]byte
		if n, err := conn.Read(b[:]); n == 1 && err == nil {
			if tcp, ok := conn.(*net.TCPConn); ok {
				_ = tcp.SetLinger(0)
			}
			_ = conn.Close()
		}
	})
}

type privateHintFixture struct {
	pool           *privatePathPool
	a, b           *privatePathCandidate
	selector       *privatePathSelector
	now            atomic.Int64
	calls          atomic.Int32
	address        string
	streamContexts []context.Context
}

func newPrivateHintFixture(t *testing.T, stream func() net.Conn) *privateHintFixture {
	t.Helper()
	target := privateHintResetTarget(t)
	_, parent := wireNetworkBox(t, nil, []map[string]any{{"type": "direct", "tag": "existing"}}, nil)
	f := &privateHintFixture{address: target.listener.Addr().String()}
	f.now.Store(bootMillis())
	lease := &leaseGuard{clock: f.now.Load}
	if err := lease.set(f.now.Load() + 1_000_000); err != nil {
		t.Fatal(err)
	}
	var err error
	f.pool, err = newPrivatePathPool(parent, strings.Repeat("a", 64), 3, lease)
	if err != nil {
		t.Fatal(err)
	}
	cleanupPrivatePool(t, f.pool)
	prepare := func(id string) *privatePathCandidate {
		node := &privateTrafficTestNode{dial: func(ctx context.Context, network string, dst M.Socksaddr) (net.Conn, error) {
			f.calls.Add(1)
			if ctx.Value(privateProbeDialKey{}) == nil {
				f.streamContexts = append(f.streamContexts, ctx)
				if stream != nil {
					return stream(), nil
				}
			}
			return routeTestDial(ctx, network, dst)
		}}
		candidate, err := f.pool.prepare(f.pool.scope, []string{id}, func(_ context.Context, _, tag, _ string) (adapter.Outbound, error) {
			node.tag = tag
			return node, nil
		})
		if err != nil {
			t.Fatal(err)
		}
		return candidate
	}
	f.a, f.b = prepare("one"), prepare("two")
	f.selector, err = newPrivatePathSelector(f.pool, f.pool.scope, "inside", []routeCheck{{Method: "tcp", Target: f.address}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.selector.Close)
	f.selectPath(t, f.selector, f.a)
	return f
}

func (f *privateHintFixture) selectPath(t *testing.T, selector *privatePathSelector, candidate *privatePathCandidate) uint64 {
	t.Helper()
	proof, err := selector.probe(context.Background(), candidate)
	if err != nil || proof == nil || !selector.selectVerified(proof, 120_000) {
		t.Fatal("real positive TCP proof was not selected", err)
	}
	return proof.selectionToken
}

func (f *privateHintFixture) flow(t *testing.T, selector *privatePathSelector, ctx context.Context) *privateSelectedTCPFlow {
	t.Helper()
	conn, err := selector.dialTCP(ctx, "tcp", M.ParseSocksaddr(f.address))
	if err != nil {
		t.Fatal("selected flow was not admitted", err)
	}
	flow, ok := conn.(*privateSelectedTCPFlow)
	if !ok {
		t.Fatal("selected stream bypassed actual flow owner")
	}
	t.Cleanup(func() { _ = flow.Close() })
	return flow
}

func privateHintResetFlow(flow net.Conn) error {
	_ = flow.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := flow.Write([]byte{1}); err != nil {
		return err
	}
	var b [1]byte
	_, err := flow.Read(b[:])
	return err
}

func (f *privateHintFixture) fail(t *testing.T, flow net.Conn) {
	t.Helper()
	if err := privateHintResetFlow(flow); !privateHintNetworkError(err) {
		t.Fatal("fixture did not return an actual known TCP reset")
	}
}

func (f *privateHintFixture) hints() []privatePathRecheckHint {
	f.pool.mu.Lock()
	defer f.pool.mu.Unlock()
	return f.pool.recheckHintsLocked(f.now.Load())
}

func TestPrivatePathHintRealTCPFailuresAreDistinctBoundedAndNonVerdict(t *testing.T) {
	f := newPrivateHintFixture(t, nil)
	first := f.flow(t, f.selector, context.Background())
	f.fail(t, first)
	for i := 0; i < 8; i++ {
		_, _ = first.Read(make([]byte, 1))
		_, _ = first.Write([]byte{1})
	}
	if len(f.hints()) != 0 {
		t.Fatal("repeated errors on one flow became independent failures")
	}
	f.fail(t, f.flow(t, f.selector, context.Background()))
	if len(f.hints()) != 0 {
		t.Fatal("two independent flows emitted a hint")
	}
	f.fail(t, f.flow(t, f.selector, context.Background()))
	hints := f.hints()
	if len(hints) != 1 || hints[0].Group != "inside" || hints[0].SelectionToken != 1 || hints[0].Sequence != 1 ||
		hints[0].CompletedBootMS != f.now.Load() || hints[0].Code != "traffic_network_failure" {
		t.Fatal("third actual flow lost its finite recheck hint")
	}
	for i := 0; i < 8; i++ {
		f.fail(t, f.flow(t, f.selector, context.Background()))
		if got := f.hints(); len(got) != 1 || got[0] != hints[0] {
			t.Fatal("pending hint was duplicated or its completion refreshed")
		}
	}
	f.pool.mu.Lock()
	selected := f.selector.active == f.a.entry && f.selector.proof == nil && !f.pool.probing && f.pool.operations == 0
	f.pool.mu.Unlock()
	if !selected {
		t.Fatal("passive observation changed proof, selection or worker ownership")
	}
	f.now.Add(privateHintWindowMS)
	if len(f.hints()) != 1 {
		t.Fatal("exact30s hint boundary was dropped")
	}
	f.now.Add(1)
	if len(f.hints()) != 0 {
		t.Fatal("stale hint was refreshed by heartbeat")
	}
	f.fail(t, f.flow(t, f.selector, context.Background()))
	if len(f.hints()) != 0 {
		t.Fatal("one selected epoch emitted a second hint without an actual verified recheck")
	}
	if token := f.selectPath(t, f.selector, f.a); token != 2 {
		t.Fatal("same-path verified recheck reused its old token")
	}
	for i := 0; i < 3; i++ {
		f.fail(t, f.flow(t, f.selector, context.Background()))
	}
	if got := f.hints(); len(got) != 1 || got[0].SelectionToken != 2 || got[0].Sequence != 2 {
		t.Fatal("new selected epoch did not own its new hint sequence")
	}
}

func TestPrivatePathHintDrainingAAndReselectedARejectOldFlowTokens(t *testing.T) {
	for _, reselect := range []bool{false, true} {
		t.Run(fmt.Sprint(reselect), func(t *testing.T) {
			f := newPrivateHintFixture(t, nil)
			if reselect {
				keeper, err := newPrivatePathSelector(f.pool, f.pool.scope, "keeper", []routeCheck{{Method: "tcp", Target: f.address}})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(keeper.Close)
				f.selectPath(t, keeper, f.a) // A stays active elsewhere, so A->B->A reuses the same entry pointer.
			}
			old := make([]*privateSelectedTCPFlow, 3)
			for i := range old {
				old[i] = f.flow(t, f.selector, context.Background())
			}
			epoch := f.selector.flowEpoch
			if token := f.selectPath(t, f.selector, f.b); token != 2 {
				t.Fatal("B did not receive its own selection token")
			}
			if reselect && f.selectPath(t, f.selector, f.a) != 3 {
				t.Fatal("reselected A reused tokenA")
			}
			if f.selector.flowEpoch != epoch {
				t.Fatal("fixture failed to isolate the insufficient flowEpoch fence")
			}
			for _, flow := range old {
				f.fail(t, flow)
			}
			if len(f.hints()) != 0 {
				t.Fatal("old draining or reselected A traffic attributed failures to current selection")
			}
			for i := 0; i < 3; i++ {
				f.fail(t, f.flow(t, f.selector, context.Background()))
			}
			want := uint64(2)
			if reselect {
				want = 3
			}
			if hints := f.hints(); len(hints) != 1 || hints[0].SelectionToken != want {
				t.Fatal("current selection lost its independent real-flow hints")
			}
		})
	}
}

func TestPrivatePathHintLifetimeSurvivesExpiredDialBudgetAndThirtySecondAge(t *testing.T) {
	f := newPrivateHintFixture(t, nil)
	flows := make([]*privateSelectedTCPFlow, 3)
	for i := range flows {
		flows[i] = f.flow(t, f.selector, context.Background())
		base := flows[i].Conn.(*privateTCPFlow)
		base.owner.cancel() // expire only the completed inner construction context, no30s real sleep.
		if f.streamContexts[len(f.streamContexts)-1].Err() == nil || base.owner.hint.lifetime.Err() != nil {
			t.Fatal("hint borrowed the construction deadline instead of stream lifetime")
		}
	}
	f.now.Add(31_000)
	for _, flow := range flows {
		f.fail(t, flow)
	}
	if hints := f.hints(); len(hints) != 1 || hints[0].CompletedBootMS != f.now.Load() {
		t.Fatal("long-lived current streams lost passive recheck evidence")
	}
}

type privateHintFaultConn struct {
	net.Conn
	err       error
	panicRead bool
	reads     *atomic.Int32
}

func (c *privateHintFaultConn) Read([]byte) (int, error) {
	if c.reads != nil {
		c.reads.Add(1)
	}
	if c.panicRead {
		panic("synthetic-private-error")
	}
	return 0, c.err
}
func (c *privateHintFaultConn) Write(b []byte) (int, error) { return len(b), nil }
func (*privateHintFaultConn) Close() error                  { return nil }

func TestPrivatePathHintCancellationQuotaDeadlinesEOFUnknownAndPanicStayLocal(t *testing.T) {
	t.Run("caller cancelled lifetime", func(t *testing.T) {
		f := newPrivateHintFixture(t, nil)
		for i := 0; i < 3; i++ {
			ctx, cancel := context.WithCancel(context.Background())
			flow := f.flow(t, f.selector, ctx)
			cancel()
			f.fail(t, flow)
		}
		if len(f.hints()) != 0 {
			t.Fatal("caller cancellation became a route hint")
		}
	})
	t.Run("caller socket deadline", func(t *testing.T) {
		f := newPrivateHintFixture(t, nil)
		for i := 0; i < 3; i++ {
			flow := f.flow(t, f.selector, context.Background())
			_ = flow.SetReadDeadline(time.Now().Add(-time.Second))
			if _, err := flow.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatal("fixture did not reach caller's socket deadline")
			}
		}
		if len(f.hints()) != 0 {
			t.Fatal("caller deadline was attributed to the network")
		}
	})
	t.Run("local operation quota", func(t *testing.T) {
		var reads atomic.Int32
		f := newPrivateHintFixture(t, func() net.Conn { return &privateHintFaultConn{err: syscall.ECONNRESET, reads: &reads} })
		flow := f.flow(t, f.selector, context.Background())
		f.pool.mu.Lock()
		f.pool.operations = 256
		f.pool.mu.Unlock()
		t.Cleanup(func() { f.pool.mu.Lock(); f.pool.operations = 0; f.pool.mu.Unlock() })
		for i := 0; i < 3; i++ {
			if _, err := flow.Read(make([]byte, 1)); err != errPrivatePath {
				t.Fatal("local quota was bypassed")
			}
		}
		f.pool.mu.Lock()
		f.pool.operations = 0
		f.pool.mu.Unlock()
		if reads.Load() != 0 || len(f.hints()) != 0 {
			t.Fatal("unadmitted operations touched a socket or hint lane")
		}
	})
	for _, mode := range []string{"EOF", "unknown", "panic"} {
		t.Run(mode, func(t *testing.T) {
			var failure error = io.EOF
			if mode == "unknown" {
				failure = errors.New("synthetic-private-error")
			}
			f := newPrivateHintFixture(t, func() net.Conn { return &privateHintFaultConn{err: failure, panicRead: mode == "panic"} })
			limit := 3
			if mode == "panic" {
				limit = 1
			}
			for i := 0; i < limit; i++ {
				flow := f.flow(t, f.selector, context.Background())
				_, _ = flow.Read(make([]byte, 1))
			}
			if len(f.hints()) != 0 || f.pool.snapshot().Operations != 0 {
				t.Fatal("nonnetwork completion minted a hint or released operation ownership incorrectly")
			}
		})
	}
}

func TestPrivatePathHintClockRollbackAndSafeIntegerOverflowDisableOnlyHintLane(t *testing.T) {
	for _, mode := range []string{"clock", "token", "sequence"} {
		t.Run(mode, func(t *testing.T) {
			f := newPrivateHintFixture(t, nil)
			if mode == "clock" {
				f.fail(t, f.flow(t, f.selector, context.Background()))
				previous := f.now.Load()
				f.now.Add(-1)
				if len(f.hints()) != 0 {
					t.Fatal("clock rollback emitted a hint")
				}
				f.now.Store(previous)
			} else {
				f.pool.mu.Lock()
				if mode == "token" {
					f.selector.hint.token = privateHintIntegerLimit
				} else {
					f.selector.hint.sequence = privateHintIntegerLimit
				}
				f.pool.mu.Unlock()
			}
			if token := f.selectPath(t, f.selector, f.a); token != 0 {
				t.Fatal("disabled lane recycled a safe integer token")
			}
			for i := 0; i < 3; i++ {
				f.fail(t, f.flow(t, f.selector, context.Background()))
			}
			f.pool.mu.Lock()
			selected := f.selector.validLocked() && f.selector.active == f.a.entry
			f.pool.mu.Unlock()
			if !selected || len(f.hints()) != 0 {
				t.Fatal("optional hint exhaustion changed actual selection or revived stale observations")
			}
		})
	}
}

func TestPrivatePathHintSixteenSelectorSlotsAndFiniteErrorClassification(t *testing.T) {
	f := newPrivateHintFixture(t, nil)
	selectors := []*privatePathSelector{f.selector}
	for i := 1; i < privateGroupLimit; i++ {
		s, err := newPrivatePathSelector(f.pool, f.pool.scope, fmt.Sprintf("group-%02d", i), []routeCheck{{Method: "tcp", Target: f.address}})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(s.Close)
		f.selectPath(t, s, f.a)
		selectors = append(selectors, s)
	}
	if s, err := newPrivatePathSelector(f.pool, f.pool.scope, "overflow", []routeCheck{{Method: "tcp", Target: f.address}}); err == nil || s != nil {
		t.Fatal("seventeenth selector/hint slot was admitted")
	}
	for _, s := range selectors {
		for i := 0; i < 3; i++ {
			flow := f.flow(t, s, context.Background())
			f.fail(t, flow)
			_ = flow.Close()
		}
	}
	hints := f.hints()
	if len(hints) != privateGroupLimit {
		t.Fatal("bounded selector hints were dropped or expanded")
	}
	for i, h := range hints {
		if i > 0 && hints[i-1].Group >= h.Group {
			t.Fatal("heartbeat hints were not deterministically ordered")
		}
		raw, _ := json.Marshal(h)
		var members map[string]any
		_ = json.Unmarshal(raw, &members)
		if len(members) != 5 || members["group"] == nil || members["selectionToken"] == nil || members["sequence"] == nil || members["completedBootMs"] == nil || members["code"] != "traffic_network_failure" || strings.Contains(string(raw), f.address) ||
			strings.Contains(fmt.Sprintf("%v %#v", h, h), h.Group) {
			t.Fatal("hint exposed a target/private diagnostic or expanded its closed shape")
		}
	}
	for _, err := range []error{io.EOF, context.Canceled, context.DeadlineExceeded, os.ErrDeadlineExceeded, net.ErrClosed,
		syscall.ETIMEDOUT, syscall.EINVAL, &net.OpError{Op: "dial", Err: syscall.ECONNRESET}, fmt.Errorf("unknown wrapper: %w", syscall.ECONNRESET)} {
		if privateHintNetworkError(err) {
			t.Fatal("unknown, deadline, local or dial error entered the finite stream-error lane")
		}
	}
	if !privateHintNetworkError(&net.OpError{Op: "read", Err: &os.SyscallError{Syscall: "read", Err: syscall.ECONNRESET}}) {
		t.Fatal("known concrete socket reset was ignored")
	}
}

func TestPrivatePathHintRequiresThreeFailuresInsideOneCompletionWindow(t *testing.T) {
	f := newPrivateHintFixture(t, nil)
	for i := 0; i < 2; i++ {
		f.fail(t, f.flow(t, f.selector, context.Background()))
	}
	f.now.Add(privateHintWindowMS + 1)
	f.fail(t, f.flow(t, f.selector, context.Background()))
	if len(f.hints()) != 0 {
		t.Fatal("old completions extended the three-flow window")
	}
	for i := 0; i < 2; i++ {
		f.fail(t, f.flow(t, f.selector, context.Background()))
	}
	if hints := f.hints(); len(hints) != 1 || hints[0].CompletedBootMS != f.now.Load() {
		t.Fatal("three current independent completions did not request a recheck")
	}
}

func TestPrivatePathHintIOUsesOnlyPoolLockAndHeartbeatKeepsExactSelectedACK(t *testing.T) {
	var admissions, releases atomic.Int32
	f := newPrivateAdaptiveOwnerFixture(t, func(bool) (func(), bool) {
		admissions.Add(1)
		return func() { releases.Add(1) }, true
	})
	o := f.owner
	epoch, scope, _ := o.context()
	if !o.start("owner-selected", epoch, scope, "inside", f.path) {
		t.Fatal("actual owner probe was denied")
	}
	verified := awaitPrivateAdaptiveOwner(t, o)
	if verified.Code != "verified" || verified.SelectionToken != 0 || len(verified.RecheckHints) != 0 {
		t.Fatal("uncommitted probe acquired a selection token or traffic hint")
	}
	o.mu.Lock()
	consumed := o.receipt.proof
	o.mu.Unlock()
	if !o.commit("owner-selected", verified.Receipt, epoch, scope, 120_000) {
		t.Fatal("actual owner commit failed")
	}
	ack := readPrivateAdaptiveOwner(t, o)
	if ack.Code != "selected" || ack.SelectionToken == 0 || ack.SelectionToken != consumed.selectionToken || !ack.GroupSelected || ack.Receipt != verified.Receipt {
		t.Fatal("selected ACK lost its exact consumed-proof token or receipt echo")
	}
	if o.commit("owner-selected", verified.Receipt, epoch, scope, 120_000) {
		t.Fatal("diagnostic receipt echo authorized a replay after actual consumption")
	}
	flows := make([]net.Conn, 3)
	for i := range flows {
		flow, err := f.managed.DialContext(context.Background(), "tcp", M.ParseSocksaddr(f.address))
		if err != nil {
			t.Fatal(err)
		}
		flows[i] = flow
		t.Cleanup(func() { _ = flow.Close() })
		privateAdaptiveEcho(t, flow, "actual-admitted-flow-before-reset")
	}
	entryCalls, exitCalls := f.entry.calls.Load(), f.exit.calls.Load()
	// Abruptly reset the actual first-hop accepted sockets, rather than relying
	// on downstream EOF propagation through the two relay fixtures.
	f.entry.mu.Lock()
	reset := 0
	for conn := range f.entry.connections {
		if tcp, ok := conn.(*net.TCPConn); ok {
			_ = tcp.SetLinger(0)
			_ = tcp.Close()
			reset++
		}
	}
	f.entry.mu.Unlock()
	if reset < len(flows) {
		t.Fatal("fixture did not own all three actual first-hop sockets")
	}
	// The traffic completion hook must not acquire either mutex. These are
	// actual owner/hub mutexes from the same runtime, held until the reads exit.
	o.mu.Lock()
	o.hub.mu.Lock()
	done := make(chan []error, 1)
	go func() {
		failures := make([]error, 0, len(flows))
		for _, flow := range flows {
			_ = flow.SetReadDeadline(time.Now().Add(2 * time.Second))
			var b [1]byte
			_, err := flow.Read(b[:])
			failures = append(failures, err)
		}
		done <- failures
	}()
	var failures []error
	completed := false
	select {
	case failures = <-done:
		completed = true
	case <-time.After(3 * time.Second):
	}
	o.hub.mu.Unlock()
	o.mu.Unlock()
	if !completed {
		// Join the same actual read owner after releasing the test-held locks;
		// timeout is not permission to leave a background test operation behind.
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("hint read owner did not retire")
		}
		t.Fatal("traffic completion waited for an owner/hub mutex")
	}
	for _, err := range failures {
		if !privateHintNetworkError(err) {
			t.Fatal("actual first-hop reset did not reach admitted TCP completion")
		}
	}
	observed := readPrivateAdaptiveOwner(t, o)
	if observed.Code != "selected" || !observed.GroupSelected || observed.SelectionToken != ack.SelectionToken || len(observed.RecheckHints) != 1 ||
		observed.RecheckHints[0].SelectionToken != ack.SelectionToken || observed.RecheckHints[0].Group != "inside" || observed.RecheckHints[0].CompletedBootMS != f.now.Load() {
		t.Fatal("heartbeat hint changed selection proof/readiness or lost its ACK binding")
	}
	if admissions.Load() != 1 || releases.Load() != 1 || observed.Running || f.entry.calls.Load() != entryCalls || f.exit.calls.Load() != exitCalls {
		t.Fatal("passive hint created a worker, admission or extra target I/O")
	}
	if raw := o.snapshot(); strings.Contains(raw, f.address) || strings.Contains(raw, "127.0.0.1:") {
		t.Fatal("heartbeat exposed an endpoint")
	}
	// An actual subsequent primitive commit can move the selector before an
	// older owner result is read. The old ACK must keep its consumed proof token,
	// never borrow the new current selector token beside old request/hops.
	s := o.hub.groups["inside"]
	proof, err := s.probe(context.Background(), &privatePathCandidate{pool: o.hub.pool, entry: consumed.entry})
	if err != nil || !s.selectVerified(proof, 120_000) || proof.selectionToken <= ack.SelectionToken {
		t.Fatal("fresh real primitive recheck did not advance selection token", err)
	}
	old := readPrivateAdaptiveOwner(t, o)
	if old.Request != ack.Request || old.SelectionToken != ack.SelectionToken || old.SelectionToken == proof.selectionToken || len(old.RecheckHints) != 0 {
		t.Fatal("old selected result borrowed new selector token or stale hint")
	}
	if !o.invalidate() {
		t.Fatal("actual network scope could not be revoked")
	}
	stale := readPrivateAdaptiveOwner(t, o)
	if stale.Ready || stale.SelectionToken != 0 || len(stale.RecheckHints) != 0 {
		t.Fatal("revoked owner exposed a current hint or selected token")
	}
}
