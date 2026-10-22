package netbird

import "github.com/sagernet/sing-box/option"

// OutboundOptions explicitly selects normal physical networking or a fail-closed VLESS underlay.
// There is no automatic fallback between modes.
type OutboundOptions struct {
	option.DialerOptions
	ConnectionMode string `json:"connection_mode,omitempty"`
	ManagementURL  string `json:"management_url"`
	SetupKey       string `json:"setup_key"`
	Hostname       string `json:"hostname,omitempty"`
	StateDirectory string `json:"state_directory"`
}
