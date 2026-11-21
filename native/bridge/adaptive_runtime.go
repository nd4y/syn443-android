package bridge

import (
	"encoding/json"
	"math"
)

// The local host supplies context, never replacement probes or graph data.
// Both declarations and predicates originate in the same signed engine config.
type adaptiveRuntimeInput struct {
	wire        *privateAdaptiveWire
	plans       map[string][]routeCheck
	programs    map[string]*routeCheckProgram
	scope, mode string
}

func adaptiveRuntimeConfig(raw, control string) ([]byte, *adaptiveRuntimeInput, error) {
	// Legacy decoding remains unchanged. Only the new negotiated format gets
	// this dedicated duplicate-preserving preflight before the SDK decoder.
	var presence map[string]json.RawMessage
	if json.Unmarshal([]byte(raw), &presence) != nil {
		return nil, nil, errPrivatePath
	}
	if _, exists := presence["adaptive_routes"]; !exists {
		var nodes []struct {
			Type string `json:"type"`
		}
		if json.Unmarshal(presence["outbounds"], &nodes) != nil {
			return nil, nil, errPrivatePath
		}
		for _, node := range nodes {
			if node.Type == privateAdaptiveOutboundType {
				return nil, nil, errPrivatePath
			}
		}
		return []byte(raw), nil, nil
	}
	budget := 65536
	parsed, ok := readPrivateAdaptiveJSON([]byte(raw), &budget, privateAdaptiveJSONLimits{rootMembers: 128, arrayItems: 256, maxBytes: 524288})
	root, object := parsed.(map[string]any)
	if !ok || !object {
		return nil, nil, errPrivatePath
	}
	wireRaw := presence["adaptive_routes"]
	wire, err := decodePrivateAdaptiveWire(wireRaw)
	if err != nil {
		return nil, nil, errPrivatePath
	}
	budget = 256
	frame, ok := readPrivateAdaptiveJSON([]byte(control), &budget, privateAdaptiveJSONLimits{rootMembers: 3, arrayItems: 4})
	f, object := frame.(map[string]any)
	if !ok || !object || len(f) != 3 || f["schemaVersion"] != json.Number("1") {
		return nil, nil, errPrivatePath
	}
	scope, _ := f["scope"].(string)
	mode, _ := f["mode"].(string)
	if !privateScopeID.MatchString(scope) || !privateAdaptiveMode(mode) {
		return nil, nil, errPrivatePath
	}
	if _, exists := root["route_failover"]; exists {
		return nil, nil, errPrivatePath
	}
	nodes, ok := root["outbounds"].([]any)
	if !ok || len(nodes) < 1 || len(nodes) > 64 {
		return nil, nil, errPrivatePath
	}
	tags, bound := map[string]map[string]any{}, map[string]bool{}
	for _, value := range nodes {
		node, ok := value.(map[string]any)
		if !ok {
			return nil, nil, errPrivatePath
		}
		tag, ok := node["tag"].(string)
		if !ok || tag == "" || tags[tag] != nil {
			return nil, nil, errPrivatePath
		}
		tags[tag] = node
		if node["type"] == "urltest" {
			return nil, nil, errPrivatePath
		}
		if node["type"] == privateAdaptiveOutboundType {
			group, ok := node["group"].(string)
			if !ok || len(node) != 3 || wire.groups[group] != tag || bound[group] {
				return nil, nil, errPrivatePath
			}
			bound[group] = true
		}
	}
	if len(bound) != len(wire.groups) {
		return nil, nil, errPrivatePath
	}
	checksRaw, err := json.Marshal(root["route_checks"])
	if err != nil || len(checksRaw) > 24000 {
		return nil, nil, errPrivatePath
	}
	var checks []struct {
		Outbound string             `json:"outbound"`
		Required bool               `json:"required"`
		Checks   []routeCheck       `json:"checks"`
		Profile  *routeCheckProfile `json:"profile"`
	}
	// The raw member preflight precedes typed bool/string zero-value collapse.
	checkValues, ok := root["route_checks"].([]any)
	if !ok || len(checkValues) > 16 || json.Unmarshal(checksRaw, &checks) != nil {
		return nil, nil, errPrivatePath
	}
	seen := map[string]bool{}
	plans := map[string][]routeCheck{}
	programs := map[string]*routeCheckProgram{}
	for i, check := range checks {
		item, ok := checkValues[i].(map[string]any)
		if !ok || len(item) < 2 || len(item) > 3 || tags[check.Outbound] == nil || seen[check.Outbound] {
			return nil, nil, errPrivatePath
		}
		_, legacy := item["checks"]
		_, current := item["profile"]
		if legacy == current || current && check.Profile == nil {
			return nil, nil, errPrivatePath
		}
		if current {
			if _, required := item["required"].(bool); !required {
				return nil, nil, errPrivatePath
			}
		}
		for key, value := range item {
			switch key {
			case "outbound", "checks", "profile":
			case "required":
				if _, ok := value.(bool); !ok {
					return nil, nil, errPrivatePath
				}
			default:
				return nil, nil, errPrivatePath
			}
		}
		seen[check.Outbound] = true
		program, err := newRouteCheckProgram(check.Checks, check.Profile)
		if err != nil {
			return nil, nil, errPrivatePath
		}
		for _, predicate := range program.allChecks() {
			if !validRouteCheck(predicate) {
				return nil, nil, errPrivatePath
			}
		}
		for group, tag := range wire.groups {
			if tag == check.Outbound {
				plans[group] = append([]routeCheck(nil), check.Checks...)
				programs[group] = program
			}
		}
	}
	if len(plans) != len(wire.groups) {
		return nil, nil, errPrivatePath
	}
	// Never allow the overlay SDK to borrow a dynamic group's hidden prefix.
	var depends func(string, map[string]bool) bool
	depends = func(tag string, seen map[string]bool) bool {
		if tag == "" {
			return false
		}
		n := tags[tag]
		if n == nil || seen[tag] {
			return true
		}
		seen[tag] = true
		if n["type"] == privateAdaptiveOutboundType {
			return true
		}
		if detour, _ := n["detour"].(string); detour != "" && depends(detour, seen) {
			return true
		}
		if members, ok := n["outbounds"].([]any); ok {
			for _, member := range members {
				name, ok := member.(string)
				if !ok || depends(name, copyAdaptiveSeen(seen)) {
					return true
				}
			}
		}
		return false
	}
	for _, node := range tags {
		if node["type"] == "netbird" {
			if tag, _ := node["detour"].(string); depends(tag, map[string]bool{}) {
				return nil, nil, errPrivatePath
			}
		}
	}
	delete(root, "adaptive_routes")
	delete(root, "route_checks")
	clean, err := json.Marshal(root)
	if err != nil {
		return nil, nil, errPrivatePath
	}
	return clean, &adaptiveRuntimeInput{wire: wire, plans: plans, programs: programs, scope: scope, mode: mode}, nil
}

func copyAdaptiveSeen(source map[string]bool) map[string]bool {
	out := make(map[string]bool, len(source))
	for k, v := range source {
		out[k] = v
	}
	return out
}

// These bridge calls only manipulate owned bounded control state. SDK I/O runs
// on the owner's single worker, never the Binder/heartbeat thread.
func (e *Runtime) AdaptiveStatus() string {
	if e.adaptive == nil {
		return "{}"
	}
	return e.adaptive.snapshot()
}
func (e *Runtime) InvalidateAdaptiveContext() {
	if e.adaptive != nil {
		e.adaptive.invalidate()
	}
}
func (e *Runtime) AdaptiveCommand(raw string) bool {
	if e.adaptive == nil || len(raw) < 1 || len(raw) > 4096 {
		return false
	}
	budget := 256
	v, ok := readPrivateAdaptiveJSON([]byte(raw), &budget, privateAdaptiveJSONLimits{rootMembers: 8, arrayItems: 4})
	f, ok2 := v.(map[string]any)
	if !ok || !ok2 {
		return false
	}
	command, _ := f["command"].(string)
	epochNumber, ok := f["nativeEpoch"].(json.Number)
	if !ok {
		return false
	}
	epoch, err := epochNumber.Int64()
	if err != nil || epoch < 1 || epoch > math.MaxInt64 {
		return false
	}
	scope, _ := f["scope"].(string)
	switch command {
	case "configure":
		mode, _ := f["mode"].(string)
		var deadline int64
		if mode == "HOME_WIFI" {
			value, ok := f["homeProofUntilBootMs"].(json.Number)
			if !ok || len(f) != 6 {
				return false
			}
			deadline, err = value.Int64()
			if err != nil || deadline <= 0 {
				return false
			}
		} else if len(f) != 5 {
			return false
		}
		if f["schemaVersion"] != json.Number("1") {
			return false
		}
		return e.adaptive.configureHomeDeadline(uint64(epoch), scope, mode, deadline)
	case "start":
		var retryUntil int64
		if value, present := f["retryUntilBootMs"]; present {
			number, ok := value.(json.Number)
			if !ok || len(f) != 7 {
				return false
			}
			retryUntil, err = number.Int64()
			if err != nil || retryUntil <= 0 {
				return false
			}
		} else if len(f) != 6 {
			return false
		}
		request, _ := f["request"].(string)
		group, _ := f["group"].(string)
		items, ok := f["hops"].([]any)
		if !ok {
			return false
		}
		hops := make([]string, len(items))
		for i, item := range items {
			hop, ok := item.(string)
			if !ok {
				return false
			}
			hops[i] = hop
		}
		return e.adaptive.startUntil(request, uint64(epoch), scope, group, hops, retryUntil)
	case "commit", "discard":
		if len(f) != 5 {
			return false
		}
		request, _ := f["request"].(string)
		receipt, _ := f["receipt"].(string)
		if command == "commit" {
			return e.adaptive.commit(request, receipt, uint64(epoch), scope, 5000)
		}
		return e.adaptive.discard(request, receipt, uint64(epoch), scope)
	}
	return false
}
