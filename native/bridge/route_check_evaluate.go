package bridge

import (
	"context"
	"errors"
	"math"
	"time"
)

const (
	checkTrue    = "TRUE"
	checkFalse   = "FALSE"
	checkUnknown = "UNKNOWN"
	checkSkipped = "SKIPPED"
)

// Passive bounded diagnostics. These values cannot become a selection receipt.
type routeCheckLeafReport struct {
	ID      string `json:"id"`
	Outcome string `json:"outcome"`
	Code    string `json:"code"`
	cause   string
}
type routeCheckPlanReport struct {
	ID       string                 `json:"id"`
	Revision int64                  `json:"revision"`
	Outcome  string                 `json:"outcome"`
	Leaves   []routeCheckLeafReport `json:"leaves"`
}

func (*routeCheckPlanReport) String() string     { return "RouteCheckPlanReport([redacted])" }
func (r *routeCheckPlanReport) GoString() string { return r.String() }
func (r *routeCheckPlanReport) clone() *routeCheckPlanReport {
	if r == nil {
		return nil
	}
	copy := *r
	copy.Leaves = append([]routeCheckLeafReport(nil), r.Leaves...)
	return &copy
}
func (r *routeCheckPlanReport) unknown() *routeCheckPlanReport {
	copy := r.clone()
	if copy == nil {
		return nil
	}
	copy.Outcome = checkUnknown
	for i := range copy.Leaves {
		if copy.Leaves[i].Outcome != checkSkipped {
			copy.Leaves[i].Outcome, copy.Leaves[i].Code = checkUnknown, "probe_unavailable"
			copy.Leaves[i].cause = ""
		}
	}
	return copy
}
func (p *routeCheckProfile) emptyReport() *routeCheckPlanReport {
	r := &routeCheckPlanReport{ID: p.ID, Revision: p.Revision, Outcome: checkUnknown, Leaves: make([]routeCheckLeafReport, 0, len(p.Leaves))}
	for _, leaf := range p.Leaves {
		r.Leaves = append(r.Leaves, routeCheckLeafReport{ID: leaf.ID, Outcome: checkSkipped, Code: "not_checked"})
	}
	return r
}

type routeCheckProbeResult struct {
	code     string
	cause    string
	complete bool
	witness  bool // This leaf's actual admitted dispatch only. Never a sibling's.
}
type routeCheckEvaluation struct {
	report   *routeCheckPlanReport
	code     string
	witness  int
	hardExit bool
}

func (r routeCheckEvaluation) complete() bool {
	return r.report != nil && r.report.Outcome != checkUnknown
}

// Sequential, at most four primitive invocations. No workers, retries or
// replacement timers are created; the existing owner retains admission.
func evaluateRouteCheckProfile(parent context.Context, p *routeCheckProfile, clock func() int64,
	current func() bool, probe func(context.Context, routeCheck) routeCheckProbeResult) (result routeCheckEvaluation) {
	result = routeCheckEvaluation{report: p.emptyReport(), code: "probe_unavailable", witness: -1}
	started := clock()
	if parent == nil || started < 0 || started > math.MaxInt64-p.DeadlineMS {
		return
	}
	ctx, cancel := context.WithTimeout(parent, time.Duration(p.DeadlineMS)*time.Millisecond)
	defer cancel()
	last := started
	valid := func() bool {
		now := clock()
		if now < last || now < started || now-started >= p.DeadlineMS || ctx.Err() != nil || !current() {
			return false
		}
		last = now
		return true
	}
	defer func() {
		if recover() != nil || !valid() {
			result.report, result.code, result.witness, result.hardExit = result.report.unknown(), "probe_unavailable", -1, false
		}
	}()
	indices := make(map[string]int, len(p.Leaves))
	for i, leaf := range p.Leaves {
		indices[leaf.ID] = i
	}
	invalid := false
	visit := func(id string) (string, int) {
		index := indices[id]
		if invalid || !valid() {
			invalid = true
			return checkUnknown, -1
		}
		leaf := p.Leaves[index]
		// SKIPPED means no invocation was attempted. A callback interrupted by
		// a global boundary stays UNKNOWN even if its result cannot be promoted.
		result.report.Leaves[index].Outcome, result.report.Leaves[index].Code = checkUnknown, "probe_unavailable"
		observed := probe(ctx, leaf.Check)
		if !valid() {
			invalid = true
			return checkUnknown, -1
		}
		state, code := checkUnknown, observed.code
		if observed.complete && observed.witness && code == "ok" {
			state = checkTrue
		}
		if observed.complete && observed.witness && (privateCheckedProbeCode(code) ||
			leaf.Check.Method == "https_exit_ip" && code == "exit_ip_mismatch" ||
			leaf.Check.Method == "https_exit_country" && code == "exit_country_mismatch") {
			state = checkFalse
		}
		unknownCode := code == "probe_unavailable" || code == "cancelled" || code == "check_timeout" || code == "unsupported" || code == "outbound_unavailable"
		if !routeCheckFiniteCode(code) || state == checkUnknown && !unknownCode {
			code = "probe_unavailable"
		}
		result.report.Leaves[index].Outcome, result.report.Leaves[index].Code = state, code
		if state == checkFalse {
			result.report.Leaves[index].cause = observed.cause
			if code == "exit_ip_mismatch" || code == "exit_country_mismatch" {
				result.hardExit = true
			}
			return state, index
		}
		return state, -1
	}
	var expression func(routeCheckExpr) (string, int)
	expression = func(node routeCheckExpr) (string, int) {
		if invalid {
			return checkUnknown, -1
		}
		if node.Leaf != "" {
			return visit(node.Leaf)
		}
		children, k := node.All, len(node.All)
		if node.Any != nil {
			children, k = node.Any, 1
		}
		if node.Quorum != nil {
			children, k = node.Quorum.Of, node.Quorum.K
		}
		passed, unknown, witness := 0, 0, -1
		for i, child := range children {
			state, observed := expression(child)
			if invalid {
				return checkUnknown, -1
			}
			switch state {
			case checkTrue:
				passed++
			case checkUnknown:
				unknown++
			case checkFalse:
				if witness < 0 {
					witness = observed
				}
			}
			if passed >= k {
				return checkTrue, -1
			}
			if passed+unknown+len(children)-i-1 < k {
				return checkFalse, witness
			}
		}
		return checkUnknown, -1
	}
	unknown := false
	finish := func(state string, witness int) bool {
		if invalid {
			return true
		}
		if state == checkFalse {
			// A false aggregate without this evaluation's concrete admitted
			// failing leaf cannot produce a failure observation or bad-proxy claim.
			if witness >= 0 && result.report.Leaves[witness].Outcome == checkFalse {
				result.report.Outcome, result.witness = checkFalse, witness
				result.code = result.report.Leaves[witness].Code
			}
			return true
		}
		unknown = unknown || state == checkUnknown
		return false
	}
	if !valid() {
		return
	}
	for _, gate := range p.Gates {
		state, witness := visit(gate)
		if finish(state, witness) {
			return
		}
	}
	// Gates and stages are an implicit ALL. UNKNOWN does not hide a later
	// decisive FALSE; a global cancellation/deadline, however, stops all I/O.
	for _, stage := range p.Stages {
		state, witness := expression(stage)
		if finish(state, witness) {
			return
		}
	}
	if !unknown && !invalid {
		result.report.Outcome, result.code = checkTrue, "ok"
	}
	return
}

func routeCheckFiniteCode(code string) bool {
	switch code {
	case "ok", "not_checked", "probe_unavailable", "unsupported", "outbound_unavailable", "cancelled",
		"dial_failed", "check_timeout", "tls_failed", "ssh_banner_mismatch", "request_failed", "response_failed",
		"exit_evidence_invalid", "http_response_mismatch", "exit_ip_mismatch", "exit_country_mismatch":
		return true
	}
	return false
}

type routeCheckProfileError struct {
	cause  error
	report *routeCheckPlanReport
}

func (*routeCheckProfileError) Error() string      { return "private check profile unavailable" }
func (e *routeCheckProfileError) Unwrap() error    { return e.cause }
func (*routeCheckProfileError) String() string     { return "RouteCheckProfileError([redacted])" }
func (e *routeCheckProfileError) GoString() string { return e.String() }

func profileErrorReport(err error) *routeCheckPlanReport {
	var failure *privateCheckedFailure
	if errors.As(err, &failure) && failure != nil && failure.checkPlan != nil {
		return failure.checkPlan.clone()
	}
	var profile *routeCheckProfileError
	if errors.As(err, &profile) && profile != nil {
		return profile.report.clone()
	}
	return nil
}
