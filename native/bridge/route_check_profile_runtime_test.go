package bridge

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
)

func checkPlanProgram(t *testing.T, checks []routeCheck, gates []string, stages []routeCheckExpr) *routeCheckProgram {
	t.Helper()
	leaves := make([]routeCheckLeaf, len(checks))
	for i, check := range checks {
		leaves[i] = routeCheckLeaf{ID: fmt.Sprintf("l%d", i), Check: check}
	}
	p, err := newRouteCheckProgram(nil, &routeCheckProfile{SchemaVersion: 2, ID: "owned-profile", Revision: 1, DeadlineMS: 12000,
		Leaves: leaves, Gates: gates, Stages: stages})
	if err != nil {
		t.Fatal("invalid owned fixture profile", err)
	}
	return p
}
func checkPlanLeaf(id string) routeCheckExpr { return routeCheckExpr{Leaf: id} }
func checkPlanRunner(t *testing.T, program *routeCheckProgram, node routeNode, dial routeDial) *routeRunner {
	t.Helper()
	r := newRouteRunner(context.Background(), func(string) (adapter.Outbound, bool) { return routeTestOutbound{dial: dial}, true })
	r.nodes = map[string]routeNode{"owned": node}
	if !r.configureProfiles(map[string]*routeCheckProgram{"owned": program}, nil) {
		t.Fatal("valid concrete profile was not approved")
	}
	return r
}

func TestCheckPlanV2MetadataCannotDowngradeOrMutateApprovedProfiles(t *testing.T) {
	p := checkPlanProgram(t, []routeCheck{{Method: "tcp", Target: "192.0.2.1:443"}}, []string{"l0"}, []routeCheckExpr{})
	row := `{"outbound":"owned","required":true,"profile":` + string(p.encoded) + `}`
	raw := `{"outbounds":[{"type":"direct","tag":"owned"}],"route_checks":[` + row + `]}`
	clean, programs, err := routeProfileMetadata(raw)
	if err != nil || len(programs) != 1 || !programs["owned"].equal(p) || bytes.Contains(clean, []byte("route_checks")) {
		t.Fatal("approved ordinary profile was lost or leaked into SDK options")
	}
	legacy := `{"outbounds":[],"route_checks":[{"outbound":"owned","checks":[{"method":"tcp","target":"192.0.2.1:443"}]}]}`
	if clean, programs, err := routeProfileMetadata(legacy); err != nil || string(clean) != legacy || len(programs) != 0 {
		t.Fatal("legacy SDK input bytes changed")
	}
	// A V2-only rendered bound must not retroactively cap legacy engines.
	// Repeated synthetic domains are ordinary SDK route data, not a keyword or
	// padding-field shortcut around the structured metadata-presence scan.
	largeRoute := `,"route":{"rules":[{"domain":[` + strings.Repeat(`"large.example.invalid",`, 25000) + `"last.example.invalid"],"outbound":"owned"}]}}`
	largeLegacy := strings.TrimSuffix(strings.Replace(legacy, `"outbounds":[]`, `"outbounds":[{"type":"direct","tag":"owned"}]`, 1), "}") + largeRoute
	if len(largeLegacy) <= 524288 {
		t.Fatal("large legacy regression fixture did not cross the new-format bound")
	}
	if clean, programs, err := routeProfileMetadata(largeLegacy); err != nil || string(clean) != largeLegacy || len(programs) != 0 {
		t.Fatal("V2 presence detection imposed a new legacy size cap")
	}
	largeV2 := strings.TrimSuffix(raw, "}") + largeRoute
	if clean, programs, err := routeProfileMetadata(largeV2); err == nil || clean != nil || programs != nil {
		t.Fatal("oversized detected V2 metadata acquired SDK input")
	}
	protector := &checkPlanNoPlatform{}
	if runtime, err := NewRuntime(largeV2, "", 0, protector, "fixture", 1, bootMillis()+60000); err == nil || runtime != nil || protector.calls.Load() != 0 {
		t.Fatal("oversized V2 engine reached runtime/platform construction")
	}
	for _, bad := range []string{
		strings.Replace(raw, `"required":true,`, "", 1), strings.Replace(raw, `"required":true`, `"required":null`, 1),
		strings.Replace(raw, `"required":true`, `"required":"true"`, 1), strings.Replace(raw, `"required":true`, `"Required":true`, 1),
		strings.Replace(raw, `"profile":`, `"Profile":`, 1), strings.Replace(raw, `"profile":`, `"profile":null,"\u0070rofile":`, 1),
		strings.Replace(raw, `"route_checks":`, `"route_checks":[],"route_checks":`, 1),
		strings.TrimSuffix(raw, "}") + `,"route_checks":[]}`,
		strings.TrimSuffix(raw, "}") + `,"Route_Checks":[]}`,
		strings.Replace(raw, `"route_checks":`, `"Route_Checks":`, 1),
		strings.TrimSuffix(raw, "}") + `,"route_failover":{}}`,
	} {
		if clean, programs, err := routeProfileMetadata(bad); err == nil || clean != nil || programs != nil {
			t.Fatal("malformed or shadowed metadata downgraded to legacy")
		}
	}
	// Constructor ownership includes all program fields; caller mutation is inert.
	p.profile.Leaves[0].Check.Target = "192.0.2.2:443"
	if strings.Contains(string(programs["owned"].encoded), "192.0.2.2") {
		t.Fatal("runtime retained caller profile storage")
	}
}

func TestCheckPlanV2OrdinaryRequiresExactApprovedConcreteProgram(t *testing.T) {
	target := listenWire(t, func(c net.Conn) { _, _ = io.Copy(c, c) })
	address := target.listener.Addr().String()
	p := checkPlanProgram(t, []routeCheck{{Method: "tcp", Target: address}}, []string{"l0"}, []routeCheckExpr{})
	var calls atomic.Int32
	r := checkPlanRunner(t, p, routeNode{ID: "route-1", Kind: "direct"}, func(ctx context.Context, network string, dst M.Socksaddr) (net.Conn, error) {
		calls.Add(1)
		return routeTestDial(ctx, network, dst)
	})
	plan := routePlan{ID: "route-1", Outbound: "owned", Profile: p.profile}
	result := r.runPlan(context.Background(), plan)
	if !result.OK || !result.Complete || result.CheckPlan == nil || result.CheckPlan.Outcome != checkTrue || calls.Load() != 1 || result.selectionProof {
		t.Fatal("ordinary profile did not use its approved concrete adapter")
	}
	for _, mutation := range []string{"id", "revision", "deadline", "target", "stages", "route-id", "unapproved"} {
		owned, err := newRouteCheckProgram(nil, p.profile)
		if err != nil {
			t.Fatal(err)
		}
		q := routePlan{ID: "route-1", Outbound: "owned", Profile: owned.profile}
		switch mutation {
		case "id":
			q.Profile.ID = "substitution"
		case "revision":
			q.Profile.Revision++
		case "deadline":
			q.Profile.DeadlineMS--
		case "target":
			q.Profile.Leaves[0].Check.Target = "192.0.2.9:443"
		case "stages":
			q.Profile.Gates, q.Profile.Stages = []string{}, []routeCheckExpr{checkPlanLeaf("l0")}
		case "route-id":
			q.ID = "route-2"
		case "unapproved":
			q.Outbound = "foreign"
		}
		before := calls.Load()
		result := r.runPlan(context.Background(), q)
		if result.OK || result.Complete || result.Code != "unsupported" || calls.Load() != before {
			t.Fatal("unapproved profile acquired I/O or a proof", mutation)
		}
	}
}

func TestCheckPlanV2VariablePathsAndMissingLeaseCannotDispatch(t *testing.T) {
	p := checkPlanProgram(t, []routeCheck{{Method: "tcp", Target: "192.0.2.1:443"}}, []string{"l0"}, []routeCheckExpr{})
	var calls atomic.Int32
	r := newRouteRunner(context.Background(), func(string) (adapter.Outbound, bool) {
		return routeTestOutbound{dial: func(context.Context, string, M.Socksaddr) (net.Conn, error) { calls.Add(1); return nil, errPrivatePath }}, true
	})
	for _, kind := range []string{"selector", "urltest", "netbird", privateAdaptiveOutboundType} {
		r.nodes = map[string]routeNode{"owned": {ID: "route-1", Kind: kind}}
		if r.configureProfiles(map[string]*routeCheckProgram{"owned": p}, nil) || len(r.v2ConcretePath("owned")) != 0 {
			t.Fatal("variable root was declared concrete", kind)
		}
	}
	for _, nodes := range []map[string]routeNode{
		{"owned": {Kind: "http", Detour: "missing"}},
		{"owned": {Kind: "http", Detour: "owned"}},
		{"owned": {Kind: "direct", Detour: "last"}, "last": {Kind: "http"}},
		{"owned": {Kind: "http", Detour: "last"}, "last": {Kind: "selector"}},
		{"owned": {Kind: "http", Detour: "b"}, "b": {Kind: "socks", Detour: "c"}, "c": {Kind: "vless", Detour: "d"}, "d": {Kind: "ssh", Detour: "e"}, "e": {Kind: "direct"}},
	} {
		r.nodes = nodes
		if r.configureProfiles(map[string]*routeCheckProgram{"owned": p}, nil) {
			t.Fatal("unowned detour acquired approval")
		}
	}
	r.nodes = map[string]routeNode{"owned": {ID: "route-1", Kind: "http", Detour: "last"}, "last": {ID: "route-2", Kind: "direct"}}
	if len(r.v2ConcretePath("owned")) != 2 || len(r.fixedPath("owned")) != 0 {
		t.Fatal("legacy selector predicate was widened")
	}
	config := `{"outbounds":[{"type":"direct","tag":"owned"}],"route_checks":[{"outbound":"owned","required":true,"profile":` + string(p.encoded) + `}]}`
	protector := &checkPlanNoPlatform{}
	if runtime, err := NewRuntime(config, "", 0, protector, "fixture", 1, 0); err == nil || runtime != nil || protector.calls.Load() != 0 || calls.Load() != 0 {
		t.Fatal("profile without positive lease reached platform or I/O")
	}
}

type checkPlanNoPlatform struct{ calls atomic.Int32 }

func (p *checkPlanNoPlatform) Protect(int32) error { p.calls.Add(1); return errPrivatePath }
func (p *checkPlanNoPlatform) ExchangeDNS([]byte) ([]byte, error) {
	p.calls.Add(1)
	return nil, errPrivatePath
}
func (p *checkPlanNoPlatform) PhysicalInterfaces() (string, error) {
	p.calls.Add(1)
	return "", errPrivatePath
}

func TestCheckPlanV2AdmissionCountsAllDeclaredAlternativeLeaves(t *testing.T) {
	p := checkPlanProgram(t, []routeCheck{{Method: "tcp", Target: "192.0.2.1:443"}, {Method: "tcp", Target: "192.0.2.2:443"}, {Method: "tcp", Target: "192.0.2.3:443"}, {Method: "tcp", Target: "192.0.2.4:443"}}, []string{}, []routeCheckExpr{{Any: []routeCheckExpr{checkPlanLeaf("l0"), checkPlanLeaf("l1"), checkPlanLeaf("l2"), checkPlanLeaf("l3")}}})
	q := routeRequest{Request: "bounded"}
	for i := 0; i < 16; i++ {
		q.Routes = append(q.Routes, routePlan{ID: fmt.Sprintf("route-%d", i), Outbound: fmt.Sprintf("out-%d", i), Profile: p.profile})
	}
	if !validRouteRequest(q) {
		t.Fatal("exact 64-leaf admission was rejected")
	}
	q.Routes = append(q.Routes, routePlan{ID: "extra", Outbound: "extra", Checks: []routeCheck{{Method: "tcp", Target: "192.0.2.5:443"}}})
	if validRouteRequest(q) {
		t.Fatal("short-circuit alternatives bypassed aggregate 64-leaf bound")
	}
	for _, raw := range []string{
		`{"id":"x","outbound":"owned","checks":[],"profile":` + string(p.encoded) + `}`,
		`{"id":"x","outbound":"owned","profile":` + string(p.encoded) + `,"Profile":` + string(p.encoded) + `}`,
	} {
		var plan routePlan
		if json.Unmarshal([]byte(raw), &plan) == nil {
			t.Fatal("request XOR/case guard collapsed")
		}
	}
}

func TestCheckPlanV2GlobalAbortAndLeafWitnessAreIndependent(t *testing.T) {
	p := checkPlanProgram(t, []routeCheck{{Method: "tcp", Target: "192.0.2.1:443"}, {Method: "tcp", Target: "192.0.2.2:443"}}, []string{}, []routeCheckExpr{{All: []routeCheckExpr{checkPlanLeaf("l0"), checkPlanLeaf("l1")}}})
	for _, abort := range []string{"parent", "clock-backward", "deadline", "lease", "final-fence"} {
		ctx, cancel := context.WithCancel(context.Background())
		now, current, calls := int64(1000), true, 0
		result := evaluateRouteCheckProfile(ctx, p.profile, func() int64 { return now }, func() bool { return current }, func(context.Context, routeCheck) routeCheckProbeResult {
			calls++
			if calls == 1 && abort != "final-fence" || calls == 2 && abort == "final-fence" {
				switch abort {
				case "parent":
					cancel()
				case "clock-backward":
					now = 999
				case "deadline":
					now = 13000
				default:
					current = false
				}
			}
			if abort == "final-fence" {
				return routeCheckProbeResult{code: "ok", complete: true, witness: true}
			}
			return routeCheckProbeResult{code: "dial_failed", complete: true, witness: true}
		})
		cancel()
		if result.report.Outcome != checkUnknown || result.witness != -1 || result.hardExit {
			t.Fatal("global invalidity published partial authority", abort)
		}
		attempted := 0
		for _, leaf := range result.report.Leaves {
			if leaf.Outcome == checkUnknown {
				attempted++
			}
		}
		if attempted != calls || abort == "final-fence" && result.report.Leaves[1].Outcome != checkUnknown || abort != "final-fence" && result.report.Leaves[0].Outcome != checkUnknown {
			t.Fatal("interrupted actual leaf was presented as never attempted", abort)
		}
	}
	calls := 0
	result := evaluateRouteCheckProfile(context.Background(), p.profile, func() int64 { return 1000 }, func() bool { return true }, func(context.Context, routeCheck) routeCheckProbeResult {
		calls++
		if calls == 1 {
			return routeCheckProbeResult{code: "ok", complete: true, witness: true}
		}
		return routeCheckProbeResult{code: "tls_failed", complete: true, witness: false}
	})
	if result.report.Outcome != checkUnknown || result.witness != -1 || result.report.Leaves[1].Code != "probe_unavailable" {
		t.Fatal("successful sibling supplied another leaf's failure witness")
	}
	any := checkPlanProgram(t, p.allChecks(), []string{}, []routeCheckExpr{{Any: []routeCheckExpr{checkPlanLeaf("l0"), checkPlanLeaf("l1")}}})
	calls = 0
	result = evaluateRouteCheckProfile(context.Background(), any.profile, func() int64 { return 1000 }, func() bool { return true }, func(context.Context, routeCheck) routeCheckProbeResult {
		calls++
		if calls == 1 {
			return routeCheckProbeResult{code: "dial_failed", complete: true, witness: true}
		}
		return routeCheckProbeResult{code: "ok", complete: true, witness: true}
	})
	if result.report.Outcome != checkTrue || result.witness != -1 || result.code != "ok" || calls != 2 {
		t.Fatal("nondecisive alternative failure became proxy/path verdict")
	}
}

func TestCheckPlanV2AdaptiveTwoHopAlternativesNeverReachTargetDirectly(t *testing.T) {
	rejected := listenWire(t, func(c net.Conn) { _, _ = io.Copy(c, c) })
	accepted := listenWire(t, func(c net.Conn) { _, _ = io.Copy(c, c) })
	a, b := rejected.listener.Addr().String(), accepted.listener.Addr().String()
	exit := httpWire(t, b, "", "")
	entry := socksWire(t, exit.listener.Addr().String())
	c := privateAdaptiveCatalogue(t, map[string]map[string]any{"entry": entry.node("socks", "entry"), "exit": exit.node("http", "exit")})
	path := []string{"entry", "exit"}
	p := checkPlanProgram(t, []routeCheck{{Method: "tcp", Target: a}, {Method: "tcp", Target: b}}, []string{}, []routeCheckExpr{{Any: []routeCheckExpr{checkPlanLeaf("l0"), checkPlanLeaf("l1")}}})
	lease := privatePoolLease(t)
	h, err := newPrivateAdaptiveHubWithPrograms(c, privateAdaptiveMetadata(t, [][]string{path}, "INTERNAL", []string{"TCP", "IPV4"}), map[string]*routeCheckProgram{"inside": p}, strings.Repeat("a", 64), "WIFI", 5, lease)
	if err != nil {
		t.Fatal(err)
	}
	cleanupPrivatePool(t, h.pool)
	t.Cleanup(h.Close)
	receipt, err := h.prepareProbe(context.Background(), "inside", path)
	if err != nil || receipt == nil || receipt.proof.checkPlan.Outcome != checkTrue || receipt.proof.checkPlan.Leaves[0].Outcome != checkFalse || receipt.proof.checkPlan.Leaves[1].Outcome != checkTrue || rejected.calls.Load() != 0 || accepted.calls.Load() == 0 || entry.calls.Load() < 2 || exit.calls.Load() < 2 {
		t.Fatal("alternatives escaped pinned two-hop path or lost real outcomes", err)
	}
	if conn, err := h.dialTCP("inside", context.Background(), "tcp", M.ParseSocksaddr(b)); conn != nil || err != errPrivatePath {
		t.Fatal("probe selected without commit")
	}
	if !h.commit(receipt, 1000) || h.commit(receipt, 1000) {
		t.Fatal("receipt was not one-use")
	}
	conn, err := h.dialTCP("inside", context.Background(), "tcp", M.ParseSocksaddr(b))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	privateAdaptiveEcho(t, conn, "profile-any-through-two-real-proxies")
	if rejected.calls.Load() != 0 {
		t.Fatal("failed first alternative fell back directly")
	}
}

type checkPlanJumpContext struct {
	context.Context
	once sync.Once
	jump func()
}

func (c *checkPlanJumpContext) Value(key any) any {
	if _, ok := key.(privateAdaptiveWorkDeadlineKey); ok {
		c.once.Do(c.jump)
		return int64(31000)
	}
	return c.Context.Value(key)
}

func TestCheckPlanV2AdaptiveOriginalDeadlinePrecedesFirstIOAndFinalProof(t *testing.T) {
	for _, phase := range []string{"before-first", "after-connection", "lease", "scope", "cancel"} {
		t.Run(phase, func(t *testing.T) {
			target := listenWire(t, func(c net.Conn) { _, _ = io.Copy(c, c) })
			var calls atomic.Int32
			var now atomic.Int64
			now.Store(1000)
			var pool *privatePathPool
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			node := &privateTrafficTestNode{dial: func(ctx context.Context, n string, d M.Socksaddr) (net.Conn, error) {
				calls.Add(1)
				conn, err := routeTestDial(ctx, n, d)
				switch phase {
				case "after-connection":
					now.Store(2000)
				case "lease":
					_ = pool.lease.set(1000)
				case "scope":
					pool.mu.Lock()
					pool.scope = strings.Repeat("b", 64)
					pool.mu.Unlock()
				case "cancel":
					cancel()
				}
				return conn, err
			}}
			p, c, scope := privateTrafficCandidate(t, node)
			pool = p
			p.lease.clock = now.Load
			_ = p.lease.set(1000000)
			program := checkPlanProgram(t, []routeCheck{{Method: "tcp", Target: target.listener.Addr().String()}}, []string{"l0"}, []routeCheckExpr{})
			program.profile.DeadlineMS = 1000
			s, err := newPrivatePathSelectorProgram(p, scope, "one", program)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			var parent context.Context = ctx
			if phase == "before-first" {
				parent = &checkPlanJumpContext{Context: ctx, jump: func() { now.Store(6000) }}
			}
			proof, err := s.probe(parent, c)
			report := profileErrorReport(err)
			var observed *privateCheckedFailure
			if proof != nil || err == nil || report == nil || report.Outcome != checkUnknown || errors.As(err, &observed) {
				t.Fatal("expired/cancelled work minted proof or attributed a target failure", phase)
			}
			if phase == "before-first" && calls.Load() != 0 {
				t.Fatal("profile clock was restarted after suspend before first leaf")
			}
		})
	}
}

func TestCheckPlanV2AdaptiveProofBindsWholeProgramAndExistingReceiptTTL(t *testing.T) {
	target := listenWire(t, func(c net.Conn) { _, _ = io.Copy(c, c) })
	p, c, scope := privateTrafficCandidate(t, &privateTrafficTestNode{dial: routeTestDial})
	var now atomic.Int64
	now.Store(1000)
	p.lease.clock = now.Load
	_ = p.lease.set(1000000)
	program := checkPlanProgram(t, []routeCheck{{Method: "tcp", Target: target.listener.Addr().String()}}, []string{"l0"}, []routeCheckExpr{})
	program.profile.DeadlineMS = 1000
	s, err := newPrivatePathSelectorProgram(p, scope, "one", program)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	proof, err := s.probe(context.Background(), c)
	if err != nil || proof == nil {
		t.Fatal(err)
	}
	program.profile.Revision++
	program.profile.Leaves[0].Check.Target = "192.0.2.1:443"
	if s.program.profile.Revision != 1 || s.program.profile.Leaves[0].Check.Target != target.listener.Addr().String() {
		t.Fatal("owned selector program mutated")
	}
	forged := *proof
	forged.checksHash = strings.Repeat("0", 64)
	if s.selectVerified(&forged, 1000) {
		t.Fatal("copied/modified proof acquired selection")
	}
	// Timely evaluation has its original 15s receipt window, not profileDeadline again.
	now.Store(3000)
	if !s.selectVerified(proof, 1000) || s.selectVerified(proof, 1000) {
		t.Fatal("profile deadline reset receipt freshness or receipt replayed")
	}
	late, err := s.probe(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	now.Add(15001)
	if s.selectVerified(late, 1000) {
		t.Fatal("old receipt exceeded existing native freshness")
	}
	if err := p.lease.set(now.Load()); err != nil {
		t.Fatal(err)
	}
	if proof, err := s.probe(context.Background(), c); proof != nil || err == nil {
		t.Fatal("expired lease retained profile authority")
	}
}

func TestCheckPlanV2ProfileTimeoutClosesRealReadAndSkipsLaterStage(t *testing.T) {
	// This owned target accepts but never sends an SSH banner. The ordinary
	// primitive's context-owned Close, rather than a new worker, ends its read.
	target := listenWire(t, func(c net.Conn) { _, _ = io.Copy(io.Discard, c) })
	var calls atomic.Int32
	node := &privateTrafficTestNode{dial: func(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
		calls.Add(1)
		return routeTestDial(ctx, network, destination)
	}}
	p, candidate, scope := privateTrafficCandidate(t, node)
	program := checkPlanProgram(t, []routeCheck{{Method: "ssh_banner", Target: target.listener.Addr().String()}, {Method: "tcp", Target: "192.0.2.1:443"}},
		[]string{}, []routeCheckExpr{checkPlanLeaf("l0"), checkPlanLeaf("l1")})
	program.profile.DeadlineMS = 100
	selector, err := newPrivatePathSelectorProgram(p, scope, "one", program)
	if err != nil {
		t.Fatal(err)
	}
	defer selector.Close()
	proof, err := selector.probe(context.Background(), candidate)
	report := profileErrorReport(err)
	var failure *privateCheckedFailure
	if proof != nil || err == nil || errors.As(err, &failure) || report == nil || report.Outcome != checkUnknown || report.Leaves[0].Outcome != checkUnknown || report.Leaves[1].Outcome != checkSkipped || calls.Load() != 1 {
		t.Fatal("aggregate timeout retained partial failure authority or admitted later I/O")
	}
}

func TestCheckPlanV2MandatoryExitGateWithdrawsOnlyItsActiveGroup(t *testing.T) {
	for _, method := range []string{"https_exit_country", "https_exit_ip"} {
		t.Run(method, func(t *testing.T) {
			var body atomic.Value
			good, bad := `{"ip":"192.0.2.1","country":"RU"}`, `{"ip":"192.0.2.1","country":"DE"}`
			if method == "https_exit_ip" {
				good, bad = "192.0.2.1", "192.0.2.2"
			}
			body.Store(good)
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, body.Load().(string)) }))
			defer server.Close()
			roots := x509.NewCertPool()
			roots.AddCert(server.Certificate())
			echo := listenWire(t, func(c net.Conn) { _, _ = io.Copy(c, c) })
			address := echo.listener.Addr().String()
			p, c, scope := privateTrafficCandidate(t, &privateTrafficTestNode{dial: routeTestDial})
			check := routeCheck{Method: method, Target: server.URL, ExpectedExitClass: "RU"}
			if method == "https_exit_ip" {
				check.ExpectedExitClass, check.ExpectedIP = "", "192.0.2.1"
			}
			program := checkPlanProgram(t, []routeCheck{check, {Method: "tcp", Target: address}}, []string{"l0"}, []routeCheckExpr{checkPlanLeaf("l1")})
			a, err := newPrivatePathSelectorProgram(p, scope, "one", program)
			if err != nil {
				t.Fatal(err)
			}
			defer a.Close()
			b, err := newPrivatePathSelector(p, scope, "two", []routeCheck{{Method: "tcp", Target: address}})
			if err != nil {
				t.Fatal(err)
			}
			defer b.Close()
			selectionExitActivate(t, a, c, roots)
			selectionExitActivate(t, b, c, nil)
			flowA, flowB := selectionExitFlow(t, a, address), selectionExitFlow(t, b, address)
			selectionExitEcho(t, flowA, "before")
			selectionExitEcho(t, flowB, "other")
			body.Store("malformed")
			if proof, err := a.probeWithRoots(context.Background(), c, roots); proof != nil || err == nil || errors.Is(err, errPrivateExitMismatch) {
				t.Fatal("malformed evidence became hard exit verdict")
			}
			selectionExitEcho(t, flowA, "uncertain-retained")
			body.Store(bad)
			proof, err := a.probeWithRoots(context.Background(), c, roots)
			report := profileErrorReport(err)
			if proof != nil || !errors.Is(err, errPrivateExitMismatch) || report == nil || report.Outcome != checkFalse || report.Leaves[1].Outcome != checkSkipped {
				t.Fatal("mandatory wrong exit did not stop later stage or withdraw")
			}
			if conn, err := a.dialTCP(context.Background(), "tcp", M.ParseSocksaddr(address)); conn != nil || err != errPrivatePath {
				t.Fatal("wrong exit retained new-flow authority")
			}
			if _, err := flowA.Write([]byte("revoked")); err != errPrivatePath {
				t.Fatal("wrong exit retained old-flow authority")
			}
			selectionExitEcho(t, flowB, "other-group-unaffected")
		})
	}
}

func TestCheckPlanV2AdaptiveRuntimeAndHubRetainMandatoryCountryGate(t *testing.T) {
	raw, _, control := adaptiveRuntimeTestConfig(t, 1)
	root := privateAdaptiveObject(t, raw)
	program := checkPlanProgram(t, []routeCheck{{Method: "tcp", Target: "192.0.2.9:443"}}, []string{"l0"}, []routeCheckExpr{})
	row := root["route_checks"].([]any)[0].(map[string]any)
	delete(row, "checks")
	row["profile"] = json.RawMessage(program.encoded)
	encoded := privateAdaptiveMarshal(t, root)
	clean, input, err := adaptiveRuntimeConfig(string(encoded), control)
	if err != nil || input == nil || !input.programs["inside"].equal(program) || bytes.Contains(clean, []byte("route_checks")) {
		t.Fatal("actual adaptive handoff lost approved profile", err)
	}
	for _, badRequired := range []any{nil, "true", 1} {
		row["required"] = badRequired
		rejectAdaptiveRuntimeConfig(t, privateAdaptiveMarshal(t, root), control)
	}
	delete(row, "required")
	rejectAdaptiveRuntimeConfig(t, privateAdaptiveMarshal(t, root), control)
	target := listenWire(t, func(c net.Conn) { _, _ = io.Copy(c, c) })
	proxy := httpWire(t, target.listener.Addr().String(), "", "")
	catalogue := privateAdaptiveCatalogue(t, map[string]map[string]any{"one": proxy.node("http", "one")})
	metadata := privateAdaptiveMetadata(t, [][]string{{"one"}}, "RU", []string{"TCP", "IPV4"})
	if h, err := newPrivateAdaptiveHubWithPrograms(catalogue, metadata, map[string]*routeCheckProgram{"inside": program}, strings.Repeat("a", 64), "WIFI", 3, privatePoolLease(t)); err == nil || h != nil {
		t.Fatal("RU graph accepted a profile without unconditional matching country gate")
	}
	check := routeCheck{Method: "https_exit_country", Target: "https://192.0.2.1", ExpectedExitClass: "RU"}
	gate := checkPlanProgram(t, []routeCheck{check}, []string{"l0"}, []routeCheckExpr{})
	h, err := newPrivateAdaptiveHubWithPrograms(catalogue, metadata, map[string]*routeCheckProgram{"inside": gate}, strings.Repeat("a", 64), "WIFI", 3, privatePoolLease(t))
	if err != nil {
		t.Fatal("matching country gate was rejected", err)
	}
	cleanupPrivatePool(t, h.pool)
	t.Cleanup(h.Close)
	if proxy.calls.Load() != 0 {
		t.Fatal("metadata validation performed I/O")
	}
}

func TestCheckPlanV2OwnerReportsArePassiveBoundedAndFresh(t *testing.T) {
	target := listenWire(t, func(c net.Conn) { _, _ = io.Copy(c, c) })
	address := target.listener.Addr().String()
	exit := httpWire(t, address, "", "")
	entry := socksWire(t, exit.listener.Addr().String())
	ref, instance := privateAdaptiveOutboundFixture(t, map[string]string{"managed": "inside"}, nil)
	catalogue := privateAdaptiveOutboundCatalogue(t, ref.ctx, instance.Router(), map[string]map[string]any{"entry": entry.node("socks", "entry"), "exit": exit.node("http", "exit")})
	path := []string{"entry", "exit"}
	program := checkPlanProgram(t, []routeCheck{{Method: "tcp", Target: address}}, []string{"l0"}, []routeCheckExpr{})
	var now atomic.Int64
	now.Store(bootMillis())
	lease := &leaseGuard{clock: now.Load}
	_ = lease.set(now.Load() + 1000000)
	h, err := newPrivateAdaptiveHubWithPrograms(catalogue, privateAdaptiveMetadata(t, [][]string{path}, "INTERNAL", []string{"TCP", "IPV4"}), map[string]*routeCheckProgram{"inside": program}, strings.Repeat("a", 64), "WIFI", 5, lease)
	if err != nil {
		t.Fatal(err)
	}
	cleanupPrivatePool(t, h.pool)
	t.Cleanup(h.Close)
	if !ref.initialize(h) {
		t.Fatal("reference initialization failed")
	}
	o, err := newPrivateAdaptiveOwner(ref, strings.Repeat("b", 64), "WIFI", strings.Repeat("c", 64), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(o.Close)
	if err = instance.Start(); err != nil {
		t.Fatal(err)
	}
	epoch, scope, _ := o.context()
	if !o.start("verified", epoch, scope, "inside", path) {
		t.Fatal("profile request denied")
	}
	report := awaitPrivateAdaptiveOwner(t, o)
	if report.Code != "verified" || report.CheckPlan == nil || report.CheckPlan.Outcome != checkTrue || !o.commit("verified", report.Receipt, epoch, scope, 1000) {
		t.Fatal("actual owner lost checked profile receipt")
	}
	_ = entry.listener.Close()
	if !o.start("failure", epoch, scope, "inside", path) {
		t.Fatal("recheck denied")
	}
	report = awaitPrivateAdaptiveOwner(t, o)
	if report.Code != "check_failed" || report.CheckPlan == nil || report.CheckPlan.Outcome != checkFalse || !report.GroupSelected || report.Receipt != "" {
		t.Fatal("admitted failed recheck gained authority or lost passive report")
	}
	copy := report.CheckPlan.clone()
	copy.Leaves[0].Code = "mutable"
	if readPrivateAdaptiveOwner(t, o).CheckPlan.Leaves[0].Code == "mutable" {
		t.Fatal("report storage was borrowed")
	}
	now.Add(30001)
	report = readPrivateAdaptiveOwner(t, o)
	if report.Code != "probe_unavailable" || report.CheckPlan == nil || report.CheckPlan.Outcome != checkUnknown {
		t.Fatal("stale failed observation retained outcome authority")
	}
	rawReport := o.snapshot()
	for _, secret := range []string{address, "127.0.0.1:", "dispatched", "witness"} {
		if strings.Contains(rawReport, secret) {
			t.Fatal("passive report leaked target/attribution internals")
		}
	}
	if !slices.Equal([]string{report.CheckPlan.Leaves[0].ID}, []string{"l0"}) || len(rawReport) > 32768 {
		t.Fatal("unbounded passive report")
	}
}
