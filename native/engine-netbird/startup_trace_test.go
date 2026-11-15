package netbird

import (
	"encoding/json"
	"strings"
	"sync"
	"testing"

	"github.com/sagernet/sing/common/logger"
)

func TestStartupTraceKeepsOnlyFixedCodesWithDisabledLogger(t *testing.T) {
	var trace startupTrace
	w := logWriter{logger: logger.NOP(), secret: "synthetic-secret", startup: &trace}
	line := []byte("failed registering peer: rpc error: code = PermissionDenied desc = setup key is invalid synthetic-secret account-private https://private.invalid/path\n")
	n, e := w.Write(line)
	if e != nil || n != len(line) {
		t.Fatal("writer contract", n, e)
	}
	got, _ := json.Marshal(trace.snapshot())
	want := `["grpc_permission_denied","setup_key_invalid","management_registration_failed"]`
	if string(got) != want {
		t.Fatal("diagnostic classification", string(got))
	}
	for _, private := range []string{"synthetic-secret", "account-private", "private.invalid", "PermissionDenied"} {
		if strings.Contains(string(got), private) {
			t.Fatal("SDK text entered diagnostics")
		}
	}
	w.Write([]byte("arbitrary provider message with synthetic-secret"))
	w.Write(line)
	got2, _ := json.Marshal(trace.snapshot())
	if string(got2) != want {
		t.Fatal("unknown/duplicate text changed fixed codes")
	}
}

func TestStartupTraceClassifiesTransportCausesWithoutKeepingText(t *testing.T) {
	for _, pattern := range startupPatterns {
		t.Run(pattern.code+"/"+pattern.fragment, func(t *testing.T) {
			var trace startupTrace
			trace.observe([]byte(strings.ToUpper(pattern.fragment) + " private-identifier"))
			codes := trace.snapshot()
			if len(codes) != 1 || codes[0] != pattern.code {
				t.Fatal("cause classification", codes)
			}
			codes[0] = "tampered"
			if trace.snapshot()[0] != pattern.code {
				t.Fatal("caller mutated retained state")
			}
		})
	}
}

func TestStartupTraceBoundsWorkMemoryAndConcurrentAccess(t *testing.T) {
	var absent *startupTrace
	absent.observe([]byte("anything"))
	if absent.snapshot() != nil {
		t.Fatal("nil collector")
	}
	var trace startupTrace
	trace.observe(nil)
	trace.observe([]byte(strings.Repeat("x", 8192) + "connection refused"))
	if len(trace.snapshot()) != 0 {
		t.Fatal("unbounded input scanned")
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for _, pattern := range startupPatterns {
				trace.observe([]byte(pattern.fragment))
				trace.snapshot()
			}
		}()
	}
	wg.Wait()
	if len(trace.snapshot()) != startupTraceLimit {
		t.Fatal("retention bound", trace.snapshot())
	}
}
