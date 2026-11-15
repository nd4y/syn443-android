# Test frame and route observation boundaries

Exact Actions43701380800/5b9ec93240dc288e0b0ed719262510851105aa8e
reported two distinct failures. API35 ChatUiTest's recreation case applied a
TestMonotonicFrameClock frame on DefaultDispatcher-worker-3 and Android rejected
view layout from that thread. The pinned Compose1.12.1 test sources document the
legacy UnconfinedTestDispatcher default and recommend the same-version junit4.v2
API with StandardTestDispatcher. Only this chat rule uses the v2 factory; actual
Activity/title/status, five recreation and five background transitions remain.
No application dispatcher, exception suppression or timing sleep is substituted.

API29's route driver observed Online/required_https_ok with route1working,
route2failed/ssh_banner_mismatch, and route3stillchecking/not_checked. Independent
HTTPS readiness cannot authorize an assertion about the unfinished selector.
The driver now awaits one actual complete report within35seconds, preserves
membership/required-ready/selected-path assertions, requires fresh numeric ages,
and fails immediately on a wrong completed outcome. It never retries a probe or
connect, resets a fixture, or accepts Online in place of route evidence.
Seven host negatives/positive boundaries accompany the unchanged238-outcome gate.

These are test-only corrections pending exact-head Actions acceptance. They do
not prove a permanent upstream Compose/emulator RCA or physical network quality.

A separate API29 failure in the updated chat run43707907162/8db4bfbf56af1eecb9fc863f1e2dbed9dda3123d
came from the loopback fixture reader while the native engine was intentionally
fully frozen. A10-second socket read timeout escaped its executor worker and was
reported as an instrumentation Error. The fixture now closes expected idle/reset
peer streams, retains unexpected worker failures for assertions, closes every
owned socket on teardown and confirms worker retirement. The actual frozen-host
new-PID/Online/desired-On/tunnel-count assertions are unchanged. A real idle-client
case proves EOF without any false health counter; all239outcomes are mandatory.
No client exception, timeout or crash is suppressed by this test-only correction.
