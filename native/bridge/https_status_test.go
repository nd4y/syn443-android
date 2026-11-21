package bridge

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestHTTPSStatusSharedWireAndPortability(t *testing.T) {
	raw, err := os.ReadFile("../../contracts/v1/https-status-check-vectors.json")
	var vectors struct{ Valid, Invalid []json.RawMessage }
	if err != nil || json.Unmarshal(raw, &vectors) != nil || len(vectors.Valid) != 3 || len(vectors.Invalid) != 12 {
		t.Fatal("missing HTTPS status contract")
	}
	for _, example := range vectors.Valid {
		var check routeCheck
		if json.Unmarshal(example, &check) != nil || !validV2ProfileCheck(check) {
			t.Fatal("valid check rejected")
		}
		wire, err := json.Marshal(check)
		var again routeCheck
		if err != nil || json.Unmarshal(wire, &again) != nil || again != check {
			t.Fatal("status predicate lost")
		}
	}
	for _, example := range vectors.Invalid {
		var check routeCheck
		if json.Unmarshal(example, &check) == nil {
			t.Fatal("invalid check admitted")
		}
	}
}

func TestHTTPSStatusUsesChosenMethodAndFinalHeadersWithoutFollowingOrDraining(t *testing.T) {
	var unexpected atomic.Int32
	clientClosed := make(chan struct{})
	service := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept-Encoding") != "identity" || r.Header.Get("Cache-Control") != "no-cache, no-store" {
			t.Error("probe cache or encoding constraints lost")
		}
		switch r.URL.Path {
		case "/head":
			if r.Method != "HEAD" {
				t.Error("HEAD replaced by GET")
			}
			w.WriteHeader(103)
			w.WriteHeader(200)
		case "/redirect":
			if r.Method != "GET" {
				t.Error("GET method lost")
			}
			w.Header().Set("Location", "/unrequested")
			w.WriteHeader(302)
		case "/stream":
			w.Header().Set("Content-Length", "67108864")
			w.WriteHeader(200)
			w.(http.Flusher).Flush()
			select {
			case <-r.Context().Done():
				close(clientClosed)
			case <-time.After(5 * time.Second):
			}
		case "/oversized":
			w.Header().Set("X-Fixture", strings.Repeat("a", 9000))
			w.WriteHeader(200)
		default:
			unexpected.Add(1)
		}
	}))
	defer service.Close()
	roots := x509.NewCertPool()
	roots.AddCert(service.Certificate())
	for _, tc := range []struct {
		path, verb string
		status     int
		code       string
	}{
		{"/head", "HEAD", 200, "ok"}, {"/redirect", "GET", 302, "ok"},
		{"/redirect", "GET", 200, "http_response_mismatch"}, {"/stream", "GET", 200, "ok"},
		{"/oversized", "GET", 200, "response_failed"},
	} {
		check := routeCheck{Method: "https_status", Target: service.URL + tc.path, HTTPMethod: tc.verb, ExpectedStatus: tc.status}
		if code, complete := probeRouteWithRoots(context.Background(), routeTestDial, check, roots); code != tc.code || !complete {
			t.Fatalf("%s: got %s, complete=%t", tc.path, code, complete)
		}
	}
	select {
	case <-clientClosed:
	case <-time.After(time.Second):
		t.Fatal("status-only GET waited for the body")
	}
	if unexpected.Load() != 0 {
		t.Fatal("redirect opened another endpoint")
	}
	check := routeCheck{Method: "https_status", Target: service.URL + "/head", HTTPMethod: "HEAD", ExpectedStatus: 200}
	if code, _ := probeRoute(context.Background(), routeTestDial, check); code != "tls_failed" {
		t.Fatal("untrusted TLS accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if code, done := probeRouteWithRoots(ctx, routeTestDial, check, roots); code != "cancelled" || done {
		t.Fatal("cancellation counted as an observation")
	}
}
