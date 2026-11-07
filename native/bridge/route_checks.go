package bridge

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type routeCheck struct {
	Method string `json:"method"`
	Target string `json:"target"`
}
type routePlan struct {
	ID       string       `json:"id"`
	Outbound string       `json:"outbound"`
	Checks   []routeCheck `json:"checks"`
}
type routeRequest struct {
	Request string      `json:"request"`
	Routes  []routePlan `json:"routes"`
}
type routeResult struct {
	ID               string   `json:"id"`
	Complete         bool     `json:"complete"`
	OK               bool     `json:"ok"`
	Code             string   `json:"code"`
	ElapsedMS        int64    `json:"elapsedMs"`
	SampledElapsedMS int64    `json:"sampledElapsedMs"`
	Path             []string `json:"path"`
	outbound         string
}
type routeNode struct{ ID, Detour, Kind string }
type routeReport struct {
	Request string        `json:"request"`
	Running bool          `json:"running"`
	Results []routeResult `json:"results"`
}

type routeRunner struct {
	mu            sync.Mutex
	ctx           context.Context
	lookup        func(string) (adapter.Outbound, bool)
	cancel        context.CancelFunc
	serial        uint64
	busy          bool
	report        routeReport
	nodes         map[string]routeNode       // Immutable once a runtime starts.
	selectors     map[string]map[string]bool // Membership of noninterrupting selectors.
	selectionUsed bool
	restore       map[string]string
	limit         func() time.Duration
}

func (r *routeRunner) path(tag string) []string {
	path := []string{}
	seen := map[string]bool{}
	for tag != "" && !seen[tag] && len(path) < 64 {
		seen[tag] = true
		node, ok := r.nodes[tag]
		if !ok {
			break
		}
		path = append(path, node.ID)
		outbound, ok := r.lookup(tag)
		if !ok {
			break
		}
		if selected, ok := outbound.(interface{ Now() string }); ok {
			tag = selected.Now()
		} else {
			tag = node.Detour
		}
	}
	return path
}
func newRouteRunner(ctx context.Context, lookup func(string) (adapter.Outbound, bool)) *routeRunner {
	return &routeRunner{ctx: ctx, lookup: lookup, report: routeReport{Results: []routeResult{}}}
}
func (r *routeRunner) snapshot() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	b, _ := json.Marshal(r.report)
	return string(b)
}
func (r *routeRunner) stop() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.stopLocked()
}
func (r *routeRunner) stopLocked() {
	if r.cancel != nil {
		r.cancel()
		r.cancel = nil
	}
	r.serial++
	r.selectionUsed = false
	r.report = routeReport{Results: []routeResult{}}
}

type routeSelector interface {
	Now() string
	SelectOutbound(string) bool
}

func (r *routeRunner) networkChanged() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.stopLocked()
	for group, previous := range r.restore {
		outbound, ok := r.lookup(group)
		if !ok || !r.selectors[group][previous] {
			continue
		}
		if selector, ok := outbound.(routeSelector); ok {
			selector.SelectOutbound(previous)
		}
	}
	r.restore = nil
}

// The check must cover one concrete end-to-end path, not a group whose
// selected member can change between evidence and selection.
func (r *routeRunner) fixedPath(tag string) []string {
	path := []string{}
	seen := map[string]bool{}
	for tag != "" {
		node, ok := r.nodes[tag]
		if !ok || seen[tag] || len(path) == 4 {
			return nil
		}
		switch node.Kind {
		case "http", "socks", "vless", "ssh":
		default:
			return nil
		}
		seen[tag] = true
		path = append(path, node.ID)
		tag = node.Detour
	}
	return path
}

func (r *routeRunner) selectVerified(request, checkID, group, previous, candidate string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if request == "" || request != r.report.Request || r.busy || r.selectionUsed ||
		r.ctx.Err() != nil || !r.allowed() || candidate == previous || !r.selectors[group][candidate] {
		return false
	}
	path := r.fixedPath(candidate)
	if len(path) == 0 {
		return false
	}
	var verified bool
	now := bootMillis()
	for _, result := range r.report.Results {
		if result.ID == checkID && result.outbound == candidate && result.OK && result.Complete &&
			now != math.MaxInt64 && result.SampledElapsedMS > 0 && result.SampledElapsedMS <= now &&
			now-result.SampledElapsedMS < 15_000 && strings.Join(result.Path, "/") == strings.Join(path, "/") {
			verified = true
			break
		}
	}
	if !verified {
		return false
	}
	outbound, ok := r.lookup(group)
	if !ok {
		return false
	}
	selector, ok := outbound.(routeSelector)
	if !ok || selector.Now() != previous || !r.allowed() || !selector.SelectOutbound(candidate) {
		return false
	}
	r.selectionUsed = true
	if r.restore == nil {
		r.restore = map[string]string{}
	}
	if _, restored := r.restore[group]; !restored {
		r.restore[group] = previous
	}
	return true
}
func validRouteRequest(q routeRequest) bool {
	if len(q.Request) < 1 || len(q.Request) > 80 || len(q.Routes) < 1 || len(q.Routes) > 64 {
		return false
	}
	seen := map[string]bool{}
	count := 0
	for _, p := range q.Routes {
		if len(p.ID) < 1 || len(p.ID) > 24 || seen[p.ID] || len(p.Outbound) < 1 || len(p.Outbound) > 256 || len(p.Checks) < 1 || len(p.Checks) > 4 {
			return false
		}
		seen[p.ID] = true
		for _, c := range p.Checks {
			count++
			if !validRouteCheck(c) {
				return false
			}
		}
	}
	return count <= 64
}
func validRouteCheck(c routeCheck) bool {
	if len(c.Target) < 1 || len(c.Target) > 2048 {
		return false
	}
	switch c.Method {
	case "tcp", "ssh_banner":
		host, port, err := net.SplitHostPort(c.Target)
		return err == nil && host != "" && validRoutePort(port) && !strings.ContainsAny(host, " /\\\r\n\t")
	case "tls", "https_204":
		u, err := url.Parse(c.Target)
		return err == nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil && u.Fragment == "" && (u.Port() == "" || validRoutePort(u.Port()))
	}
	return false
}
func validRoutePort(port string) bool {
	n, e := strconv.ParseUint(port, 10, 16)
	return e == nil && n > 0
}
func (r *routeRunner) start(raw string) bool {
	if len(raw) > 32768 {
		return false
	}
	var q routeRequest
	d := json.NewDecoder(strings.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&q) != nil || d.Decode(new(any)) != io.EOF || !validRouteRequest(q) {
		return false
	}
	for _, p := range q.Routes {
		if _, ok := r.lookup(p.Outbound); !ok {
			return false
		}
	}
	r.mu.Lock()
	// One batch at a time; a stuck or cancelled dial cannot grow worker count.
	if r.busy || r.ctx.Err() != nil {
		r.mu.Unlock()
		return false
	}
	duration := 30 * time.Second
	if r.limit != nil {
		duration = r.limit()
	}
	if duration <= 0 {
		r.mu.Unlock()
		return false
	}
	ctx, cancel := context.WithTimeout(r.ctx, duration)
	startedBoot := bootMillis()
	if startedBoot == math.MaxInt64 {
		cancel()
		r.mu.Unlock()
		return false
	}
	ctx = context.WithValue(ctx, routeDeadlineKey{}, startedBoot+duration.Milliseconds())
	r.cancel = cancel
	r.serial++
	serial := r.serial
	r.busy = true
	r.selectionUsed = false
	r.report = routeReport{Request: q.Request, Running: true, Results: []routeResult{}}
	r.mu.Unlock()
	go func() {
		defer cancel()
		tasks := make(chan routePlan)
		var workers sync.WaitGroup
		for i := 0; i < 2; i++ {
			workers.Add(1)
			go func() {
				defer workers.Done()
				for p := range tasks {
					result := r.runPlan(ctx, p)
					r.mu.Lock()
					if r.serial == serial {
						r.report.Results = append(r.report.Results, result)
					}
					r.mu.Unlock()
				}
			}()
		}
		for _, p := range q.Routes {
			select {
			case tasks <- p:
			case <-ctx.Done():
			}
		}
		close(tasks)
		workers.Wait()
		r.mu.Lock()
		r.busy = false
		if r.serial == serial {
			r.report.Running = false
			r.cancel = nil
		}
		r.mu.Unlock()
	}()
	return true
}

type routeDial func(context.Context, string, M.Socksaddr) (net.Conn, error)

func (r *routeRunner) allowed() bool { return r.limit == nil || r.limit() > 0 }

type routeDeadlineKey struct{}

func routeBudgetCurrent(ctx context.Context) bool {
	deadline, present := ctx.Value(routeDeadlineKey{}).(int64)
	return ctx.Err() == nil && (!present || bootMillis() < deadline)
}

type authorizedRouteConn struct {
	net.Conn
	allowed func() bool
}

func (c *authorizedRouteConn) Read(b []byte) (int, error) {
	if !c.allowed() {
		return 0, errLeaseExpired
	}
	n, e := c.Conn.Read(b)
	if !c.allowed() {
		return 0, errLeaseExpired
	}
	return n, e
}
func (c *authorizedRouteConn) Write(b []byte) (int, error) {
	if !c.allowed() {
		return 0, errLeaseExpired
	}
	return c.Conn.Write(b)
}
func (c *authorizedRouteConn) NeedHandshakeForWrite() bool { return N.NeedHandshakeForWrite(c.Conn) }
func (r *routeRunner) runPlan(ctx context.Context, p routePlan) (result routeResult) {
	start := time.Now()
	result = routeResult{ID: p.ID, Complete: true, OK: true, Code: "ok", outbound: p.Outbound}
	defer func() {
		if recover() != nil {
			result.OK = false
			result.Complete = false
			result.Code = "probe_unavailable"
		}
		// CLOCK_BOOTTIME authorization remains decisive after suspend, even when a
		// normal monotonic timer did not advance. Never publish an expired success.
		if !routeBudgetCurrent(ctx) || !r.allowed() {
			result.OK = false
			result.Complete = false
			result.Code = "cancelled"
		}
		result.ElapsedMS = time.Since(start).Milliseconds()
		result.SampledElapsedMS = bootMillis()
	}()
	if !r.allowed() || !routeBudgetCurrent(ctx) {
		result.OK = false
		result.Complete = false
		result.Code = "cancelled"
		return
	}
	result.Path = r.path(p.Outbound)
	outbound, ok := r.lookup(p.Outbound)
	if !ok {
		result.OK = false
		result.Complete = false
		result.Code = "outbound_unavailable"
		return
	}
	dial := func(c context.Context, n string, a M.Socksaddr) (net.Conn, error) {
		if !r.allowed() || !routeBudgetCurrent(ctx) {
			return nil, errLeaseExpired
		}
		conn, err := outbound.DialContext(c, n, a)
		if err != nil {
			return nil, err
		}
		if conn == nil {
			return nil, nil
		} // Invalid adapter result is contained by probeRoute.
		if !r.allowed() || !routeBudgetCurrent(ctx) {
			conn.Close()
			return nil, errLeaseExpired
		}
		return &authorizedRouteConn{Conn: conn, allowed: func() bool { return r.allowed() && routeBudgetCurrent(ctx) }}, nil
	}
	for _, c := range p.Checks {
		code, complete := probeRoute(ctx, dial, c)
		if code != "ok" {
			result.OK = false
			result.Complete = complete
			result.Code = code
			break
		}
	}
	if strings.Join(result.Path, "/") != strings.Join(r.path(p.Outbound), "/") {
		result.OK = false
		result.Complete = false
		result.Code = "path_changed"
	}
	return
}

func probeRoute(parent context.Context, dial routeDial, c routeCheck) (string, bool) {
	return probeRouteWithRoots(parent, dial, c, nil)
}
func probeRouteWithRoots(parent context.Context, dial routeDial, c routeCheck, roots *x509.CertPool) (string, bool) {
	return probeRouteWithClock(parent, dial, c, roots, bootMillis)
}
func probeRouteWithClock(parent context.Context, dial routeDial, c routeCheck, roots *x509.CertPool, clock func() int64) (code string, complete bool) {
	started := clock()
	if started < 0 || started == math.MaxInt64 {
		return "probe_unavailable", false
	}
	defer func() {
		now := clock()
		if now < started || now-started > 3000 {
			code = "check_timeout"
			complete = false
		}
	}()
	if !validRouteCheck(c) {
		return "unsupported", false
	}
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	defer cancel()
	target := c.Target
	var u *url.URL
	if c.Method == "tls" || c.Method == "https_204" {
		u, _ = url.Parse(target)
		port := u.Port()
		if port == "" {
			port = "443"
		}
		target = net.JoinHostPort(u.Hostname(), port)
	}
	conn, err := dial(ctx, "tcp", M.ParseSocksaddr(target))
	if err != nil {
		if parent.Err() != nil {
			return "cancelled", false
		}
		return "dial_failed", true
	}
	if conn == nil {
		return "outbound_unavailable", false
	}
	defer conn.Close()
	deadline, _ := ctx.Deadline()
	_ = conn.SetDeadline(deadline)
	after := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer after()
	if parent.Err() != nil {
		return "cancelled", false
	}
	if ctx.Err() != nil {
		return "check_timeout", true
	}
	if c.Method == "tcp" {
		if N.NeedHandshakeForWrite(conn) {
			if _, err := conn.Write(nil); err != nil {
				return "dial_failed", true
			}
		}
		if ctx.Err() != nil {
			return "check_timeout", true
		}
		return "ok", true
	}
	if c.Method == "ssh_banner" {
		// VLESS lazy streams must send their request before a server-first banner.
		if N.NeedHandshakeForWrite(conn) {
			if _, err := conn.Write(nil); err != nil {
				return "dial_failed", true
			}
		}
		raw, err := bufio.NewReader(io.LimitReader(conn, 256)).ReadString('\n')
		if parent.Err() != nil {
			return "cancelled", false
		}
		if ctx.Err() != nil {
			return "check_timeout", true
		}
		if err != nil || !strings.HasPrefix(raw, "SSH-2.0-") {
			return "ssh_banner_mismatch", true
		}
		return "ok", true
	}
	secure := tls.Client(conn, &tls.Config{ServerName: u.Hostname(), MinVersion: tls.VersionTLS12, RootCAs: roots})
	if err := secure.HandshakeContext(ctx); err != nil {
		if parent.Err() != nil {
			return "cancelled", false
		}
		return "tls_failed", true
	}
	if ctx.Err() != nil {
		return "check_timeout", true
	}
	if c.Method == "tls" {
		return "ok", true
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, c.Target, nil)
	req.Header.Set("Connection", "close")
	if req.Write(secure) != nil {
		return "request_failed", true
	}
	response, err := http.ReadResponse(bufio.NewReaderSize(io.LimitReader(secure, 8193), 4096), req)
	if err != nil {
		if parent.Err() != nil {
			return "cancelled", false
		}
		return "response_failed", true
	}
	if ctx.Err() != nil {
		return "check_timeout", true
	}
	defer response.Body.Close()
	length := response.Header.Get("Content-Length")
	if response.StatusCode != 204 || response.ContentLength > 0 || len(response.TransferEncoding) > 0 || (length != "" && length != "0") {
		return "http_response_mismatch", true
	}
	return "ok", true
}
