package bridge

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
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
}
type routeNode struct{ ID, Detour string }
type routeReport struct {
	Request string        `json:"request"`
	Running bool          `json:"running"`
	Results []routeResult `json:"results"`
}

type routeRunner struct {
	mu     sync.Mutex
	ctx    context.Context
	lookup func(string) (adapter.Outbound, bool)
	cancel context.CancelFunc
	serial uint64
	busy   bool
	report routeReport
	nodes  map[string]routeNode // Immutable once a runtime starts.
	limit  func() time.Duration
}

func (r *routeRunner) path(tag string) []string {
	path := []string{}
	seen := map[string]bool{}
	for tag != "" && !seen[tag] && len(path) < 8 {
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
	if r.cancel != nil {
		r.cancel()
		r.cancel = nil
	}
	r.serial++
	r.report = routeReport{Results: []routeResult{}}
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
	r.cancel = cancel
	r.serial++
	serial := r.serial
	r.busy = true
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
					start := time.Now()
					result := routeResult{ID: p.ID, Complete: true, OK: true, Code: "ok", Path: r.path(p.Outbound)}
					outbound, ok := r.lookup(p.Outbound)
					if !ok {
						result.OK = false
						result.Code = "outbound_unavailable"
					} else {
						for _, c := range p.Checks {
							code, complete := probeRoute(ctx, outbound.DialContext, c)
							if code != "ok" {
								result.OK = false
								result.Code = code
								result.Complete = complete
								break
							}
						}
					}
					if strings.Join(result.Path, "/") != strings.Join(r.path(p.Outbound), "/") {
						result.Complete = false
						result.OK = false
						result.Code = "path_changed"
					}
					result.ElapsedMS = time.Since(start).Milliseconds()
					result.SampledElapsedMS = bootMillis()
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

func probeRoute(parent context.Context, dial routeDial, c routeCheck) (string, bool) {
	return probeRouteWithRoots(parent, dial, c, nil)
}
func probeRouteWithRoots(parent context.Context, dial routeDial, c routeCheck, roots *x509.CertPool) (string, bool) {
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
	defer conn.Close()
	deadline, _ := ctx.Deadline()
	_ = conn.SetDeadline(deadline)
	after := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer after()
	if parent.Err() != nil {
		return "cancelled", false
	}
	if c.Method == "tcp" {
		if _, err := conn.Write(nil); err != nil {
			return "dial_failed", true
		}
		return "ok", true
	}
	if c.Method == "ssh_banner" {
		raw, err := bufio.NewReader(io.LimitReader(conn, 256)).ReadString('\n')
		if parent.Err() != nil {
			return "cancelled", false
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
	defer response.Body.Close()
	length := response.Header.Get("Content-Length")
	if response.StatusCode != 204 || response.ContentLength > 0 || len(response.TransferEncoding) > 0 || (length != "" && length != "0") {
		return "http_response_mismatch", true
	}
	return "ok", true
}
