package bridge

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

func TestRouteExitCountryStrictTargetsAndJSON(t *testing.T) {
	for _, country := range strings.Fields(exitCountryISO) {
		if !validExitCountry(country) {
			t.Fatal("pinned region data rejected a current ISO assignment")
		}
	}
	valid := routeCheck{Method: "https_exit_country", Target: "https://example.org/", ExpectedExitClass: "RU"}
	if !validRouteCheck(valid) {
		t.Fatal("country check rejected")
	}
	for _, target := range []string{
		"http://example.org/", "https://example.org/a", "https://example.org/%2f", "https://example.org/?", "https://example.org/?ip=192.0.2.1",
		"https://example.org/#", "https://example.org/#fragment", "https://example.org:/", "https://example.org:0/", "https://example.org:65536/",
		"https:example.org", "https://example.org/\n", "https://example.org/é", "https://example.org\\other/",
		(&url.URL{Scheme: "https", Host: "example.org", User: url.User("fixture-user")}).String(),
	} {
		check := valid
		check.Target = target
		if validRouteCheck(check) {
			t.Fatal("unsafe country target admitted")
		}
	}
	for _, method := range []string{"tcp", "ssh_banner", "tls", "https_204", "https_exit_ip"} {
		check := valid
		check.Method = method
		if method == "https_exit_ip" {
			check.ExpectedIP = "192.0.2.1"
		}
		if validRouteCheck(check) {
			t.Fatal("country class admitted for another method")
		}
	}
	for _, class := range []string{"", "INTERNAL", "PUBLIC", "ru", "NON-RU"} {
		check := valid
		check.ExpectedExitClass = class
		if validRouteCheck(check) {
			t.Fatal("unsupported country class admitted")
		}
	}
	valid.ExpectedIP = "192.0.2.1"
	if validRouteCheck(valid) {
		t.Fatal("mixed expected evidence admitted")
	}
	for _, tc := range []struct{ body, class string }{
		{`{"ip":"192.0.2.1","country":"RU"}`, "RU"},
		{`{"country":"DE","ip":"2001:db8::1"}`, "NON_RU"},
		{" \n{\"ip\":\"192.0.2.1\",\"country\":\"US\"}\r\n", "NON_RU"},
	} {
		if class, ok := exitCountryClass([]byte(tc.body)); !ok || class != tc.class {
			t.Fatal("valid country evidence rejected")
		}
	}
	for _, body := range []string{
		`null`, `[]`, `{}`, `{"ip":"192.0.2.1"}`, `{"country":"RU"}`,
		`{"ip":"192.0.2.1","IP":"192.0.2.2","country":"RU"}`,
		`{"ip":"192.0.2.1","ip":"192.0.2.2","country":"RU"}`,
		`{"ip":"192.0.2.1","country":"RU","country":"DE"}`,
		`{"ip":"192.0.2.1","Country":"RU"}`,
		`{"ip":"192.0.2.1","country":"RU","extra":"ignored"}`,
		`{"ip":null,"country":"RU"}`, `{"ip":12,"country":"RU"}`, `{"ip":{},"country":"RU"}`,
		`{"ip":"192.0.2.1","country":null}`, `{"ip":"192.0.2.1","country":["RU"]}`,
		`{"ip":"example.org","country":"RU"}`, `{"ip":"192.0.2.1:443","country":"RU"}`,
		`{"ip":"fe80::1%wlan0","country":"RU"}`, `{"ip":"::ffff:192.0.2.1","country":"RU"}`,
		`{"ip":"192.0.2.1","country":"ru"}`, `{"ip":"192.0.2.1","country":"RUS"}`,
		`{"ip":"192.0.2.1","country":"ZZ"}`, `{"ip":"192.0.2.1","country":"EU"}`,
		`{"ip":"192.0.2.1","country":"XK"}`, `{"ip":"192.0.2.1","country":"SU"}`,
		`{"ip":"192.0.2.1","country":"AC"}`, `{"ip":"192.0.2.1","country":"UK"}`,
		`{"ip":"192.0.2.1","country":"RU"}null`, `{"ip":"192.0.2.1","country":"RU"} {}`,
		"{\"ip\":\"192.0.2.1\",\"country\":\"R\xff\"}",
		`{"ip":"192.0.2.1","country":"\ud800"}`,
		strings.Repeat(" ", exitCountryBodyLimit) + `{"ip":"192.0.2.1","country":"RU"}`,
	} {
		if _, ok := exitCountryClass([]byte(body)); ok {
			t.Fatal("invalid evidence invented a country")
		}
	}
}

func TestRouteExitCountryUsesExactCandidateAndVerifiedTLS(t *testing.T) {
	for _, tc := range []struct{ name, body, expected, want string }{
		{"ru", `{"ip":"192.0.2.1","country":"RU"}`, "RU", "ok"},
		{"non ru ipv4", `{"ip":"192.0.2.2","country":"DE"}`, "NON_RU", "ok"},
		{"non ru ipv6", `{"ip":"2001:db8::1","country":"US"}`, "NON_RU", "ok"},
		{"wrong ru", `{"ip":"192.0.2.1","country":"RU"}`, "NON_RU", "exit_country_mismatch"},
		{"wrong non ru", `{"ip":"192.0.2.1","country":"DE"}`, "RU", "exit_country_mismatch"},
		{"unknown country", `{"ip":"192.0.2.1","country":"ZZ"}`, "NON_RU", "exit_evidence_invalid"},
		{"duplicate country", `{"ip":"192.0.2.1","country":"RU","country":"DE"}`, "NON_RU", "exit_evidence_invalid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var requests, calls atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if r.Method != "GET" || r.URL.RequestURI() != "/" || r.Header.Get("Cache-Control") != "no-cache, no-store" || r.Header.Get("Accept-Encoding") != "identity" {
					w.WriteHeader(400)
					return
				}
				_, _ = io.WriteString(w, tc.body)
			}))
			defer server.Close()
			roots := x509.NewCertPool()
			roots.AddCert(server.Certificate())
			dial := func(ctx context.Context, network string, target M.Socksaddr) (net.Conn, error) {
				calls.Add(1)
				if network != "tcp" || "https://"+target.String() != server.URL {
					return nil, errors.New("unexpected selected destination")
				}
				return routeTestDial(ctx, network, target)
			}
			check := routeCheck{Method: "https_exit_country", Target: server.URL, ExpectedExitClass: tc.expected}
			code, complete := probeRouteWithRoots(context.Background(), dial, check, roots)
			if code != tc.want || !complete || calls.Load() != 1 || requests.Load() != 1 {
				t.Fatalf("unexpected country probe: %s complete=%t calls=%d requests=%d", code, complete, calls.Load(), requests.Load())
			}
			code, _ = probeRouteWithRoots(context.Background(), dial, check, nil)
			if code != "tls_failed" || calls.Load() != 2 || requests.Load() != 1 {
				t.Fatal("untrusted TLS reached the country endpoint")
			}
			code, _ = probeRouteWithRoots(context.Background(), func(context.Context, string, M.Socksaddr) (net.Conn, error) {
				return nil, errors.New("candidate unavailable")
			}, check, roots)
			if code != "dial_failed" || requests.Load() != 1 {
				t.Fatal("failed candidate escaped through a default dialer")
			}
		})
	}
}

func exitCountryRawFixture(t *testing.T, raw string) (*httptest.Server, *x509.CertPool) {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, buffered, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error("fixture hijack failed")
			return
		}
		defer conn.Close()
		_, _ = buffered.WriteString(raw)
		_ = buffered.Flush()
	}))
	t.Cleanup(server.Close)
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	return server, roots
}

func TestRouteExitCountryRejectsUnboundedFramingAndLateEvidence(t *testing.T) {
	body := `{"ip":"192.0.2.1","country":"RU"}`
	length := "Content-Length: " + strconv.Itoa(len(body)) + "\r\n"
	chunked := fmt.Sprintf("%x\r\n%s\r\n0\r\n\r\n", len(body), body)
	maxHeaderPad := exitCountryHeaderLimit - len("HTTP/1.1 200 OK\r\nX-Pad: \r\n"+length+"Connection: close\r\n\r\n")
	maxBody := body + strings.Repeat(" ", exitCountryBodyLimit-len(body))
	for _, tc := range []struct{ name, headers, body, want string }{
		{"bounded content length", length, body, "ok"},
		{"close delimited", "", body, "ok"},
		{"bounded chunked", "Transfer-Encoding: chunked\r\n", chunked, "ok"},
		{"body exactly limit", "Content-Length: 512\r\n", maxBody, "ok"},
		{"large legal header", "X-Pad: " + strings.Repeat("a", 8000) + "\r\n" + length, body, "ok"},
		{"header exactly limit", "X-Pad: " + strings.Repeat("a", maxHeaderPad) + "\r\n" + length, body, "ok"},
		{"header over limit", "X-Pad: " + strings.Repeat("a", 8200) + "\r\n" + length, body, "response_failed"},
		{"empty age", "Age:\r\n" + length, body, "exit_evidence_invalid"},
		{"cached", "Age: 0\r\n" + length, body, "exit_evidence_invalid"},
		{"encoded", "Content-Encoding: gzip\r\n" + length, body, "exit_evidence_invalid"},
		{"empty encoding", "Content-Encoding:\r\n" + length, body, "exit_evidence_invalid"},
		{"encoded identity", "Content-Encoding: identity\r\n" + length, body, "exit_evidence_invalid"},
		{"truncated", length, body[:len(body)-1], "exit_evidence_invalid"},
		{"content length over limit", "Content-Length: 513\r\n", strings.Repeat(" ", 513), "exit_evidence_invalid"},
		{"close body over limit", "", body + strings.Repeat(" ", 513), "exit_evidence_invalid"},
		{"chunked body over limit", "Transfer-Encoding: chunked\r\n", "201\r\n" + strings.Repeat(" ", 513) + "\r\n0\r\n\r\n", "exit_evidence_invalid"},
		{"declared trailer", "Transfer-Encoding: chunked\r\nTrailer: X-Proof\r\n", fmt.Sprintf("%x\r\n%s\r\n0\r\nX-Proof: yes\r\n\r\n", len(body), body), "exit_evidence_invalid"},
		{"undeclared trailer", "Transfer-Encoding: chunked\r\n", fmt.Sprintf("%x\r\n%s\r\n0\r\nX-Proof: yes\r\n\r\n", len(body), body), "exit_evidence_invalid"},
		{"framing over budget", "Transfer-Encoding: chunked\r\n", fmt.Sprintf("%x;%s\r\n%s\r\n0\r\n\r\n", len(body), strings.Repeat("a", 2100), body), "exit_evidence_invalid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, roots := exitCountryRawFixture(t, "HTTP/1.1 200 OK\r\n"+tc.headers+"Connection: close\r\n\r\n"+tc.body)
			code, complete := probeRouteWithRoots(context.Background(), routeTestDial, routeCheck{Method: "https_exit_country", Target: server.URL, ExpectedExitClass: "RU"}, roots)
			if code != tc.want || !complete {
				t.Fatalf("unexpected framing observation: %s complete=%t", code, complete)
			}
		})
	}
	server, roots := exitCountryRawFixture(t, "HTTP/1.1 302 Found\r\nLocation: /other\r\n"+length+"\r\n"+body)
	check := routeCheck{Method: "https_exit_country", Target: server.URL, ExpectedExitClass: "RU"}
	if code, complete := probeRouteWithRoots(context.Background(), routeTestDial, check, roots); code != "exit_evidence_invalid" || !complete {
		t.Fatal("redirect became country evidence")
	}
	for _, late := range []int64{4101, 99} {
		server, roots := exitCountryRawFixture(t, "HTTP/1.1 200 OK\r\n"+length+"\r\n"+body)
		calls := 0
		code, complete := probeRouteWithClock(context.Background(), routeTestDial, routeCheck{Method: "https_exit_country", Target: server.URL, ExpectedExitClass: "RU"}, roots, func() int64 {
			calls++
			if calls == 1 {
				return 100
			}
			return late
		})
		if code != "check_timeout" || complete {
			t.Fatal("late or clock-rollback evidence published")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	code, complete := probeRouteWithRoots(ctx, func(c context.Context, _ string, _ M.Socksaddr) (net.Conn, error) {
		<-c.Done()
		return nil, c.Err()
	}, check, roots)
	if code != "cancelled" || complete {
		t.Fatal("parent cancellation became confirmed country failure")
	}
}
