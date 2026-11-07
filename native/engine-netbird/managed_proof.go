package netbird

import "net"

// This is private controller input, not UI telemetry or authority to activate a
// route. A durable public-key fingerprint alone is not registration: require the
// current owner's authenticated management/signal connection and assigned IP.
// Call on a disposable host worker; the SDK recorder can block. Recheck ownership
// after the recorder returns so Stop/revoke cannot publish a late receipt.
type managedRegistrationProof struct {
	Namespace        string `json:"namespace"`
	IdentityEvidence string `json:"identityEvidence"`
}

func ManagedRegistrationProof() string {
	if DiagnosticsAllowed != nil && !DiagnosticsAllowed() {
		return "{}"
	}
	o := activeOutbound()
	if o == nil {
		return "{}"
	}
	o.mu.RLock()
	client, namespace, evidence, current := o.client, o.options.ManagedNamespace, o.identityEvidence, o.ready && !o.closed
	o.mu.RUnlock()
	p, ok := client.(observablePeer)
	if !current || !ok || namespace == "" || !managedDigest(evidence) {
		return "{}"
	}
	snapshot := p.ConnectionSnapshot()
	ip := net.ParseIP(snapshot.IP)
	if ip == nil {
		ip, _, _ = net.ParseCIDR(snapshot.IP)
	}
	if !snapshot.ManagementConnected || !snapshot.SignalConnected || ip == nil || ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast() || ip.IsLinkLocalUnicast() {
		return "{}"
	}
	o.mu.RLock()
	current = !o.closed && o.ready && o.client == client && o.identityEvidence == evidence
	o.mu.RUnlock()
	if !current || activeOutbound() != o || DiagnosticsAllowed != nil && !DiagnosticsAllowed() {
		return "{}"
	}
	return marshal(managedRegistrationProof{namespace, evidence})
}
