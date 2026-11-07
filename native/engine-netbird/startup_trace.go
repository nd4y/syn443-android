package netbird

import (
	"strings"
	"sync"
)

// Startup may fail before the SDK recorder is usable. Preserve a bounded set of
// diagnostic codes independently of sing-box logging, which is disabled in the
// Android runtime. Never retain SDK text: it may contain keys, account data or
// endpoints. This collector cannot authorize registration or change retry rules.
type startupTrace struct {
	mu    sync.Mutex
	codes []string
}

const startupTraceLimit = 16

var startupPatterns = []struct{ fragment, code string }{
	{"certificate has expired", "tls_certificate_expired"},
	{"certificate is not yet valid", "tls_certificate_time"},
	{"unknown authority", "tls_unknown_authority"},
	{"certificate is valid for", "tls_hostname_mismatch"},
	{"tls handshake timeout", "tls_handshake_timeout"},
	{"context deadline exceeded", "operation_deadline"},
	{"i/o timeout", "transport_timeout"},
	{"connection refused", "connection_refused"},
	{"no route to host", "network_unreachable"},
	{"network is unreachable", "network_unreachable"},
	{"no such host", "dns_name_unavailable"},
	{"temporary failure in name resolution", "dns_resolution_failed"},
	{"code = unavailable", "grpc_unavailable"},
	{"code = permissiondenied", "grpc_permission_denied"},
	{"code = unauthenticated", "grpc_unauthenticated"},
	{"code = notfound", "grpc_not_found"},
	{"code = invalidargument", "grpc_invalid_argument"},
	{"code = internal", "grpc_internal"},
	{"code = unknown", "grpc_unknown"},
	{"code = deadlineexceeded", "grpc_deadline_exceeded"},
	{"code = resourceexhausted", "grpc_resource_exhausted"},
	{"code = failedprecondition", "grpc_failed_precondition"},
	{"code = aborted", "grpc_aborted"},
	{"code = outofrange", "grpc_out_of_range"},
	{"code = unimplemented", "grpc_unimplemented"},
	{"code = dataloss", "grpc_data_loss"},
	{"code = canceled", "grpc_cancelled"},
	{"code = alreadyexists", "grpc_already_exists"},
	{"no connection to management", "management_connection_not_ready"},
	{"invalid peer hostname", "peer_hostname_invalid"},
	{"empty label list", "peer_hostname_empty"},
	{"setup key is invalid", "setup_key_invalid"},
	{"setup-key is invalid", "setup_key_invalid"},
	{"context canceled", "operation_cancelled"},
	{"context cancelled", "operation_cancelled"},
	{"failed connecting to management", "management_connect_failed"},
	{"failed to connect to management", "management_connect_failed"},
	{"failed logging in", "management_login_failed"},
	{"failed to login to management", "management_login_failed"},
	{"failed registering peer", "management_registration_failed"},
	{"failed to get server public key", "management_server_key_failed"},
	{"unexpected eof", "transport_eof"},
	{"connection reset by peer", "connection_reset"},
}

func (t *startupTrace) observe(raw []byte) {
	if t == nil || len(raw) == 0 {
		return
	}
	// Bound both transient allocation and matching work for a hostile SDK line.
	if len(raw) > 8192 {
		raw = raw[:8192]
	}
	line := strings.ToLower(string(raw))
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, pattern := range startupPatterns {
		if len(t.codes) == startupTraceLimit {
			return
		}
		if !strings.Contains(line, pattern.fragment) {
			continue
		}
		found := false
		for _, prior := range t.codes {
			found = found || prior == pattern.code
		}
		if !found {
			t.codes = append(t.codes, pattern.code)
		}
	}
}

func (t *startupTrace) snapshot() []string {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]string(nil), t.codes...)
}
