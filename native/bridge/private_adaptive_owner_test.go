package bridge

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
)

type privateAdaptiveOwnerFixture struct {
	owner       *privateAdaptiveOwner
	ref         *privateAdaptiveReference
	managed     *privateAdaptiveOutbound
	now         *atomic.Int64
	path        []string
	address     string
	entry, exit *wireFixture
}

func newPrivateAdaptiveOwnerFixture(t *testing.T, admit privateAdaptiveAdmission) privateAdaptiveOwnerFixture {
	t.Helper()
	target := listenWire(t, func(c net.Conn) { _, _ = io.Copy(c, c) })
	address := target.listener.Addr().String()
	exit := httpWire(t, address, "", "")
	entry := socksWire(t, exit.listener.Addr().String())
	r, instance := privateAdaptiveOutboundFixture(t, map[string]string{"managed": "inside"}, nil)
	c := privateAdaptiveOutboundCatalogue(t, r.ctx, instance.Router(), map[string]map[string]any{
		"entry": entry.node("socks", "entry"), "exit": exit.node("http", "exit"),
	})
	path := []string{"entry", "exit"}
	h, now := privateAdaptiveNewHub(t, c, privateAdaptiveMetadata(t, [][]string{path}, "INTERNAL", []string{"TCP", "IPV4"}),
		map[string][]routeCheck{"inside": {{Method: "tcp", Target: address}}}, 8)
	if !r.initialize(h) {
		t.Fatal("actual reference initialization failed")
	}
	o, err := newPrivateAdaptiveOwner(r, strings.Repeat("b", 64), "WIFI", strings.Repeat("c", 64), admit)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(o.Close)
	if err := instance.Start(); err != nil {
		t.Fatal("owner-bound actual box failed to start", err)
	}
	return privateAdaptiveOwnerFixture{o, r, privateAdaptiveOutboundNode(t, instance, "managed"), now, path, address, entry, exit}
}

func readPrivateAdaptiveOwner(t *testing.T, o *privateAdaptiveOwner) privateAdaptiveOwnerReport {
	t.Helper()
	raw := o.snapshot()
	var report privateAdaptiveOwnerReport
	if len(raw) > 32768 || json.Unmarshal([]byte(raw), &report) != nil {
		t.Fatal("owner returned an unbounded or invalid report")
	}
	return report
}

func awaitPrivateAdaptiveOwner(t *testing.T, o *privateAdaptiveOwner) privateAdaptiveOwnerReport {
	t.Helper()
	awaitPrivatePool(t, func() bool { return !readPrivateAdaptiveOwner(t, o).Running })
	return readPrivateAdaptiveOwner(t, o)
}

func TestPrivateAdaptiveOwnerReportsFreshCheckFailuresWithoutProofOrProxyVerdict(t *testing.T) {
	for _, lateRelease := range []bool{false, true} {
		t.Run(fmt.Sprintf("late-release-%t", lateRelease), func(t *testing.T) {
			var fixture privateAdaptiveOwnerFixture
			var releases atomic.Int32
			fixture = newPrivateAdaptiveOwnerFixture(t, func(bool) (func(), bool) {
				return func() {
					if releases.Add(1) == 2 && lateRelease {
						fixture.now.Add(30_000)
					}
				}, true
			})
			o := fixture.owner
			epoch, scope, _ := o.context()
			if !o.start("healthy", epoch, scope, "inside", fixture.path) {
				t.Fatal("healthy request denied")
			}
			proof := awaitPrivateAdaptiveOwner(t, o)
			if proof.Code != "verified" || !o.commit("healthy", proof.Receipt, epoch, scope, 1000) {
				t.Fatal("healthy actual chain was not selected")
			}
			flow, e := fixture.managed.DialContext(context.Background(), "tcp", M.ParseSocksaddr(fixture.address))
			if e != nil {
				t.Fatal(e)
			}
			defer flow.Close()
			privateAdaptiveEcho(t, flow, "actual-selected-chain-before-negative-check")
			_ = fixture.entry.listener.Close() // Existing accepted flow remains alive; a new probe is refused.
			completed := fixture.now.Load()
			if !o.start("observed-failure", epoch, scope, "inside", fixture.path) {
				t.Fatal("fresh same-group check denied")
			}
			report := awaitPrivateAdaptiveOwner(t, o)
			if report.Receipt != "" || !report.GroupSelected || o.commit("observed-failure", proof.Receipt, epoch, scope, 1000) {
				t.Fatal("negative check withdrew selection or acquired receipt authority")
			}
			if lateRelease {
				if report.Code != "probe_unavailable" || report.CheckCode != "" || report.CheckCompletedBootMS != 0 || strings.Contains(o.snapshot(), "checkCompletedBootMs") {
					t.Fatal("owner-deadline-expired observation gained attribution")
				}
			} else if report.Code != "check_failed" || report.CheckCode != "dial_failed" || report.CheckCompletedBootMS != completed || completed <= 0 {
				t.Fatal("actual refused adapter check lost its finite observation code")
			}
			privateAdaptiveEcho(t, flow, "target-failure-alone-never-withdraws-active-flow")
			if raw := o.snapshot(); strings.Contains(raw, fixture.address) || strings.Contains(raw, "127.0.0.1:") {
				t.Fatal("observed check report exposed a target")
			}
			if !lateRelease {
				if debug := fmt.Sprintf("%v %#v", report, report); strings.Contains(debug, fmt.Sprint(completed)) || strings.Contains(debug, scope) {
					t.Fatal("ordinary diagnostic formatting exposed private observation metadata")
				}
				fixture.now.Add(30_000)
				boundary := readPrivateAdaptiveOwner(t, o)
				if boundary.Code != "check_failed" || boundary.CheckCompletedBootMS != completed {
					t.Fatal("an exact 30-second completion bound was not preserved")
				}
				fixture.now.Add(1)
				late := readPrivateAdaptiveOwner(t, o)
				if late.Code != "probe_unavailable" || late.CheckCode != "" || late.CheckCompletedBootMS != 0 || strings.Contains(o.snapshot(), "checkCompletedBootMs") {
					t.Fatal("a delayed status read restarted the failure freshness window")
				}
				privateAdaptiveEcho(t, flow, "expired-observation-does-not-withdraw-owned-flow")
			}
		})
	}
	t.Run("expired work budget starts no target check", func(t *testing.T) {
		var f privateAdaptiveOwnerFixture
		f = newPrivateAdaptiveOwnerFixture(t, func(bool) (func(), bool) { f.now.Add(30_000); return func() {}, true })
		epoch, scope, _ := f.owner.context()
		if !f.owner.start("expired-before-dispatch", epoch, scope, "inside", f.path) {
			t.Fatal("bounded request denied")
		}
		report := awaitPrivateAdaptiveOwner(t, f.owner)
		if report.Code != "probe_unavailable" || report.CheckCode != "" || report.CheckCompletedBootMS != 0 || strings.Contains(f.owner.snapshot(), "checkCompletedBootMs") || report.Receipt != "" || f.entry.calls.Load() != 0 || f.exit.calls.Load() != 0 {
			t.Fatal("expired aggregate work budget became a target failure")
		}
	})
	t.Run("constructor callback cannot forge a checked failure", func(t *testing.T) {
		f := newPrivateAdaptiveOwnerFixture(t, nil)
		f.owner.hub.create = func(context.Context, string, string, string) (adapter.Outbound, error) {
			return nil, &privateCheckedFailure{code: "dial_failed", completedBootMS: f.now.Load()}
		}
		epoch, scope, _ := f.owner.context()
		if !f.owner.start("forged-constructor", epoch, scope, "inside", f.path) {
			t.Fatal("bounded request denied")
		}
		report := awaitPrivateAdaptiveOwner(t, f.owner)
		if report.Code != "probe_unavailable" || report.CheckCode != "" || report.CheckCompletedBootMS != 0 || strings.Contains(f.owner.snapshot(), "checkCompletedBootMs") || report.Receipt != "" || f.entry.calls.Load() != 0 {
			t.Fatal("constructor error forged actual check attribution")
		}
	})
}

func TestPrivateAdaptiveOwnerRealTwoHopReceiptAndLocalContextBindings(t *testing.T) {
	var admitted, released atomic.Int32
	var recovery sync.Map
	f := newPrivateAdaptiveOwnerFixture(t, func(critical bool) (func(), bool) {
		recovery.Store(admitted.Add(1), critical)
		return func() { released.Add(1) }, true
	})
	o := f.owner
	epoch, scope, ready := o.context()
	if epoch != 1 || !ready || !privateScopeID.MatchString(scope) || scope == strings.Repeat("b", 64) || scope != o.hub.scope {
		t.Fatal("owner did not bind the actual hub to a fresh opaque context")
	}
	if other, err := newPrivateAdaptiveOwner(f.ref, strings.Repeat("b", 64), "WIFI", strings.Repeat("c", 64), nil); other != nil || err != errPrivatePath {
		t.Fatal("second owner borrowed the same initialized reference")
	}
	for _, call := range []func() bool{
		func() bool { return o.start(strings.Repeat("x", 65), epoch, scope, "inside", f.path) },
		func() bool { return o.start("bad", epoch+1, scope, "inside", f.path) },
		func() bool { return o.start("bad", epoch, strings.Repeat("d", 64), "inside", f.path) },
		func() bool { return o.start("bad", epoch, scope, "unknown", f.path) },
		func() bool { return o.start("bad", epoch, scope, "inside", nil) },
		func() bool { return o.start("bad", epoch, scope, "inside", []string{"exit", "entry"}) },
	} {
		if call() {
			t.Fatal("invalid request obtained worker admission")
		}
	}
	if admitted.Load() != 0 {
		t.Fatal("rejected request consumed scheduler admission")
	}
	path := append([]string(nil), f.path...)
	if !o.start("first", epoch, scope, "inside", path) {
		t.Fatal("valid request was not admitted")
	}
	path[0] = "changed-caller-buffer"
	proof := awaitPrivateAdaptiveOwner(t, o)
	if proof.Code != "verified" || len(proof.Receipt) != 64 || proof.Hops[0] != "entry" || proof.Request != "first" || proof.ElapsedMS < 0 ||
		released.Load() != 1 || o.start("pending", epoch, scope, "inside", f.path) {
		t.Fatal("owned checks did not retain exactly one pending receipt")
	}
	if conn, err := f.managed.DialContext(context.Background(), "tcp", M.ParseSocksaddr(f.address)); conn != nil || err != errPrivatePath {
		t.Fatal("successful checks switched the data path without explicit commit")
	}
	if o.commit("other", proof.Receipt, epoch, scope, 1000) || o.commit("first", strings.Repeat("e", 64), epoch, scope, 1000) ||
		o.commit("first", proof.Receipt, epoch+1, scope, 1000) || o.commit("first", proof.Receipt, epoch, strings.Repeat("d", 64), 1000) {
		t.Fatal("substituted receipt binding committed")
	}
	if proof.CheckCompletedBootMS != f.now.Load() {
		t.Fatal("receipt timestamp does not match the actual check completion")
	}
	f.now.Add(250)
	if !o.commit("first", proof.Receipt, epoch, scope, 1000) || o.commit("first", proof.Receipt, epoch, scope, 1000) {
		t.Fatal("fresh receipt was rejected or replayed")
	}
	selected := readPrivateAdaptiveOwner(t, o)
	if selected.Code != "selected" || selected.CheckCompletedBootMS != proof.CheckCompletedBootMS {
		t.Fatal("selection acknowledgement changed the age of the verified check")
	}
	flow, err := f.managed.DialContext(context.Background(), "tcp", M.ParseSocksaddr(f.address))
	if err != nil {
		t.Fatal(err)
	}
	defer flow.Close()
	privateAdaptiveEcho(t, flow, "actual-owner-selected-two-hop")
	if f.entry.calls.Load() == 0 || f.exit.calls.Load() == 0 {
		t.Fatal("owner-mediated payload bypassed a real declared hop")
	}
	if !o.start("maintenance", epoch, scope, "inside", f.path) {
		t.Fatal("active group could not request fresh maintenance evidence")
	}
	maintenance := awaitPrivateAdaptiveOwner(t, o)
	if first, _ := recovery.Load(int32(1)); first != true {
		t.Fatal("group without active path did not receive recovery admission")
	}
	if second, _ := recovery.Load(int32(2)); second != false {
		t.Fatal("request could promote an active group to recovery priority")
	}
	if !o.discard("maintenance", maintenance.Receipt, epoch, scope) || o.discard("maintenance", maintenance.Receipt, epoch, scope) ||
		o.commit("maintenance", maintenance.Receipt, epoch, scope, 1000) {
		t.Fatal("discarded receipt retained selection authority")
	}
	for index, raw := range []string{fmt.Sprintf("%v %#v", o, o), o.snapshot()} {
		if strings.Contains(raw, f.address) || strings.Contains(raw, strings.Repeat("c", 64)) ||
			(index == 0 && strings.Contains(raw, strings.Repeat("b", 64))) {
			t.Fatal("owner diagnostics exposed endpoint or private policy binding")
		}
	}
	if !o.invalidate() {
		t.Fatal("actual native invalidation failed")
	}
	newEpoch, newScope, newReady := o.context()
	if newEpoch != epoch+1 || newScope == scope || newReady || o.start("old", epoch, scope, "inside", f.path) ||
		o.configure(epoch, strings.Repeat("b", 64), "WIFI") {
		t.Fatal("network invalidation accepted stale local authority")
	}
	if n, err := flow.Write([]byte("stale")); n != 0 || err != errPrivatePath {
		t.Fatal("network invalidation retained old data authority")
	}
	if !o.configure(newEpoch, strings.Repeat("b", 64), "WIFI") {
		t.Fatal("current local configuration could not acknowledge new native epoch")
	}
	other := newPrivateAdaptiveOwnerFixture(t, nil)
	_, otherScope, _ := other.owner.context()
	if otherScope == newScope || otherScope == scope {
		t.Fatal("replacement native owner reused its predecessor's nonce binding")
	}
}

func TestPrivateAdaptiveOwnerCancellationRetainsWorkerAndPermitUntilActualExit(t *testing.T) {
	entered, unblockConstructor := make(chan struct{}), make(chan struct{})
	releasing, unblockRelease := make(chan struct{}), make(chan struct{})
	var constructorOnce, releaseOnce sync.Once
	unblock := func() {
		constructorOnce.Do(func() { close(unblockConstructor) })
		releaseOnce.Do(func() { close(unblockRelease) })
	}
	var admitted, released atomic.Int32
	f := newPrivateAdaptiveOwnerFixture(t, func(bool) (func(), bool) {
		admitted.Add(1)
		return func() { close(releasing); <-unblockRelease; released.Add(1) }, true
	})
	t.Cleanup(unblock)
	o := f.owner
	o.hub.create = func(context.Context, string, string, string) (adapter.Outbound, error) {
		close(entered)
		<-unblockConstructor
		return nil, errPrivatePath // No hidden allocation in this fixture.
	}
	epoch, scope, _ := o.context()
	if !o.start("blocked", epoch, scope, "inside", f.path) {
		t.Fatal("bounded worker did not start")
	}
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("constructor was not entered")
	}
	if !o.invalidate() {
		t.Fatal("invalidation failed while construction was pending")
	}
	epoch, scope, _ = o.context()
	if !o.configure(epoch, strings.Repeat("b", 64), "WIFI") || o.start("replacement", epoch, scope, "inside", f.path) ||
		!readPrivateAdaptiveOwner(t, o).Running || admitted.Load() != 1 || released.Load() != 0 || o.hub.pool.snapshot().Dynamic != 2 {
		t.Fatal("cancelled constructor lost its worker, reservation or admission")
	}
	constructorOnce.Do(func() { close(unblockConstructor) })
	select {
	case <-releasing:
	case <-time.After(5 * time.Second):
		t.Fatal("actual worker did not reach admission cleanup")
	}
	if o.start("permit-still-owned", epoch, scope, "inside", f.path) || !readPrivateAdaptiveOwner(t, o).Running || released.Load() != 0 {
		t.Fatal("blocked admission cleanup admitted replacement work")
	}
	o.Close()
	if o.stopped() {
		t.Fatal("Close acknowledged a worker whose permit release was blocked")
	}
	releaseOnce.Do(func() { close(unblockRelease) })
	awaitPrivatePool(t, o.stopped)
	if released.Load() != 1 || admitted.Load() != 1 || readPrivateAdaptiveOwner(t, o).Running {
		t.Fatal("actual worker exit did not release exactly its own admission")
	}
}

func TestPrivateAdaptiveOwnerLeaseUnknownConstructorAndAdmissionFailClosed(t *testing.T) {
	t.Run("hard lease fences pending receipt and actual selected stream", func(t *testing.T) {
		f := newPrivateAdaptiveOwnerFixture(t, nil)
		epoch, scope, _ := f.owner.context()
		if !f.owner.start("lease", epoch, scope, "inside", f.path) {
			t.Fatal("request denied")
		}
		proof := awaitPrivateAdaptiveOwner(t, f.owner)
		if !f.owner.commit("lease", proof.Receipt, epoch, scope, 1000) {
			t.Fatal("fresh lease did not authorize actual selected path")
		}
		flow, err := f.managed.DialContext(context.Background(), "tcp", M.ParseSocksaddr(f.address))
		if err != nil {
			t.Fatal(err)
		}
		defer flow.Close()
		privateAdaptiveEcho(t, flow, "before-hard-lease-expiry")
		if !f.owner.start("lease-pending", epoch, scope, "inside", f.path) {
			t.Fatal("maintenance request denied")
		}
		proof = awaitPrivateAdaptiveOwner(t, f.owner)
		f.now.Add(1_000_001)
		if f.owner.commit("lease-pending", proof.Receipt, epoch, scope, 1000) || f.owner.start("expired", epoch, scope, "inside", f.path) ||
			readPrivateAdaptiveOwner(t, f.owner).Ready {
			t.Fatal("expired hard lease admitted new authority")
		}
		if n, err := flow.Write([]byte("expired")); n != 0 || err != errPrivatePath {
			t.Fatal("selected stream outlived its hard lease")
		}
		_ = flow.Close()
		f.owner.Close()
		awaitPrivatePool(t, f.owner.stopped)
	})
	t.Run("unknown constructor requires actual process retirement", func(t *testing.T) {
		var releases atomic.Int32
		f := newPrivateAdaptiveOwnerFixture(t, func(bool) (func(), bool) { return func() { releases.Add(1) }, true })
		f.owner.hub.create = func(context.Context, string, string, string) (adapter.Outbound, error) {
			panic("synthetic unknown allocation must stay private")
		}
		epoch, scope, _ := f.owner.context()
		if !f.owner.start("unknown", epoch, scope, "inside", f.path) {
			t.Fatal("request denied")
		}
		report := awaitPrivateAdaptiveOwner(t, f.owner)
		if report.Code != "probe_unavailable" || report.Receipt != "" || releases.Load() != 1 || strings.Contains(f.owner.snapshot(), "allocation") {
			t.Fatal("unknown allocation produced authority or leaked details")
		}
		f.owner.Close()
		select {
		case <-f.owner.hub.pool.workerExited:
		case <-time.After(5 * time.Second):
			t.Fatal("retirement worker did not exit")
		}
		if f.owner.stopped() || f.owner.hub.pool.snapshot().Dynamic != 2 || f.owner.hub.pool.snapshot().Retained != 1 {
			t.Fatal("successful Close hid uncertain constructor ownership")
		}
	})
	t.Run("denied admission starts no worker", func(t *testing.T) {
		var calls atomic.Int32
		f := newPrivateAdaptiveOwnerFixture(t, func(bool) (func(), bool) { calls.Add(1); return nil, false })
		epoch, scope, _ := f.owner.context()
		if f.owner.start("denied", epoch, scope, "inside", f.path) || readPrivateAdaptiveOwner(t, f.owner).Running ||
			calls.Load() != 1 || f.owner.hub.pool.snapshot().Dynamic != 0 {
			t.Fatal("denied admission created work or adapters")
		}
	})
	for _, malformed := range []string{"panic", "missing release"} {
		t.Run(malformed, func(t *testing.T) {
			f := newPrivateAdaptiveOwnerFixture(t, func(bool) (func(), bool) {
				if malformed == "panic" {
					panic("synthetic admission details must remain private")
				}
				return nil, true
			})
			epoch, scope, _ := f.owner.context()
			if f.owner.start("uncertain-permit", epoch, scope, "inside", f.path) || readPrivateAdaptiveOwner(t, f.owner).Ready ||
				strings.Contains(f.owner.snapshot(), "admission details") {
				t.Fatal("uncertain compiled admission acquired authority or leaked details")
			}
			awaitPrivatePool(t, f.owner.hub.stopped)
			if f.owner.stopped() {
				t.Fatal("unknown admission cleanup was presented as confirmed retirement")
			}
		})
	}
}

func TestHalfOpenDeadlineRemainsBoundThroughActualNativeSelection(t *testing.T) {
	for _, offset := range []int64{-1, 0, 1} {
		t.Run(fmt.Sprintf("commit-offset-%d", offset), func(t *testing.T) {
			var permits atomic.Int32
			f := newPrivateAdaptiveOwnerFixture(t, func(bool) (func(), bool) { permits.Add(1); return func() {}, true })
			runtime := &Runtime{adaptive: f.owner}
			report := readPrivateAdaptiveOwner(t, f.owner)
			command := map[string]any{"command": "start", "nativeEpoch": report.NativeEpoch, "scope": report.Scope,
				"group": "inside", "request": "bounded-retry", "hops": f.path}
			call := func() bool {
				raw, err := json.Marshal(command)
				if err != nil {
					t.Fatal(err)
				}
				return runtime.AdaptiveCommand(string(raw))
			}
			now := f.now.Load()
			for _, bad := range []any{nil, "later", 0, float64(now) + 0.5, now, now + 15_001} {
				command["retryUntilBootMs"] = bad
				if call() {
					t.Fatal("invalid retry window reached worker")
				}
			}
			if permits.Load() != 0 {
				t.Fatal("malformed operation used a permit")
			}
			deadline := now + 13_000
			command["retryUntilBootMs"] = deadline
			if !call() {
				t.Fatal("current retry not admitted")
			}
			proof := awaitPrivateAdaptiveOwner(t, f.owner)
			if proof.Code != "verified" || proof.Receipt == "" || f.entry.calls.Load() == 0 || f.exit.calls.Load() == 0 {
				t.Fatal("native two-hop verification missing")
			}
			// Delay the bare commit after the probe. Omitting the retry field
			// on that later message cannot extend the already-issued proof.
			f.now.Store(deadline + offset)
			command = map[string]any{"command": "commit", "nativeEpoch": report.NativeEpoch, "scope": report.Scope, "request": "bounded-retry", "receipt": proof.Receipt}
			if got := call(); got != (offset < 0) {
				t.Fatal("wrong exclusive commit boundary", offset)
			}
			conn, err := f.managed.DialContext(context.Background(), "tcp", M.ParseSocksaddr(f.address))
			if offset < 0 {
				if err != nil || conn == nil {
					t.Fatal("selected path unavailable")
				}
				defer conn.Close()
				privateAdaptiveEcho(t, conn, "confirmed-before-expiry")
			} else if conn != nil || err != errPrivatePath || readPrivateAdaptiveOwner(t, f.owner).GroupSelected {
				if conn != nil {
					conn.Close()
				}
				t.Fatal("late commit selected a data path")
			}
		})
	}
}
