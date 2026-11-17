package bridge

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
)

// Scan all duplicate-preserving top-level route_checks values before deciding
// whether this is legacy. A first profile cannot be hidden by a later legacy
// row/root value or by a case variant that the SDK would otherwise ignore.
func routeProfilePresence(raw []byte) (bool, error) {
	if len(raw) < 2 {
		return false, errPrivatePath
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber() // Presence scanning must not coerce legacy numeric lexemes.
	first, err := d.Token()
	if err != nil || first != json.Delim('{') {
		return false, errPrivatePath
	}
	found, wrongCase, count := false, false, 0
	for d.More() {
		token, err := d.Token()
		key, ok := token.(string)
		if err != nil || !ok {
			return false, errPrivatePath
		}
		inspect := strings.EqualFold(key, "route_checks")
		if inspect {
			count++
			wrongCase = wrongCase || key != "route_checks"
		}
		// Presence detection must not impose a new admission limit on legacy
		// engines. Token-walk the already-owned input without retaining field
		// RawMessages or recursive copies. The JSON decoder's existing syntax
		// and nesting limits apply; V2's smaller bounds are enforced only once
		// its actual object member has been observed, never by keyword search.
		token, err = d.Token()
		if err != nil {
			return false, errPrivatePath
		}
		stack := []json.Delim{}
		if delim, container := token.(json.Delim); container {
			if delim != '[' && delim != '{' {
				return false, errPrivatePath
			}
			stack = append(stack, delim)
		}
		for len(stack) > 0 {
			delim := stack[len(stack)-1]
			if !d.More() {
				end, err := d.Token()
				if err != nil || !(delim == '[' && end == json.Delim(']') || delim == '{' && end == json.Delim('}')) {
					return false, errPrivatePath
				}
				stack = stack[:len(stack)-1]
				continue
			}
			if delim == '{' {
				key, err := d.Token()
				name, ok := key.(string)
				if err != nil || !ok {
					return false, errPrivatePath
				}
				if inspect && strings.EqualFold(name, "profile") {
					found = true
				}
			}
			token, err := d.Token()
			if err != nil {
				return false, errPrivatePath
			}
			if child, container := token.(json.Delim); container {
				if child != '[' && child != '{' {
					return false, errPrivatePath
				}
				stack = append(stack, child)
			}
		}
	}
	end, err := d.Token()
	if err != nil || end != json.Delim('}') {
		return false, errPrivatePath
	}
	if _, err := d.Token(); err != io.EOF {
		return false, errPrivatePath
	}
	if found && (count != 1 || wrongCase) {
		return false, errPrivatePath
	}
	return found, nil
}

// Only the negotiated profile format gets new ordinary metadata handling.
// Legacy input bytes and SDK decoding remain unchanged when no profile exists.
func routeProfileMetadata(raw string) ([]byte, map[string]*routeCheckProgram, error) {
	found, err := routeProfilePresence([]byte(raw))
	if err != nil {
		return nil, nil, errPrivatePath
	}
	if !found {
		return []byte(raw), nil, nil
	}
	if len(raw) > 524288 {
		return nil, nil, errPrivatePath
	}
	var presence map[string]json.RawMessage
	if json.Unmarshal([]byte(raw), &presence) != nil {
		return nil, nil, errPrivatePath
	}
	budget := 65536
	parsed, ok := readPrivateAdaptiveJSON([]byte(raw), &budget, privateAdaptiveJSONLimits{rootMembers: 128, arrayItems: 256, maxBytes: 524288})
	root, object := parsed.(map[string]any)
	if !ok || !object {
		return nil, nil, errPrivatePath
	}
	if _, failover := root["route_failover"]; failover {
		return nil, nil, errPrivatePath
	}
	rows, err := checkProfileArray(presence["route_checks"], 16)
	if err != nil || len(presence["route_checks"]) > 24000 {
		return nil, nil, errPrivatePath
	}
	programs, seen := map[string]*routeCheckProgram{}, map[string]bool{}
	for _, rawRow := range rows {
		row, err := checkProfileObject(rawRow, "outbound", "required", "checks", "profile")
		if err != nil || len(row) < 2 || len(row) > 3 {
			return nil, nil, errPrivatePath
		}
		var tag string
		if json.Unmarshal(row["outbound"], &tag) != nil || len(tag) < 1 || len(tag) > 256 || seen[tag] {
			return nil, nil, errPrivatePath
		}
		seen[tag] = true
		if value, exists := row["required"]; exists {
			var required bool
			if json.Unmarshal(value, &required) != nil {
				return nil, nil, errPrivatePath
			}
		}
		checks, legacy := row["checks"]
		profile, current := row["profile"]
		if legacy == current {
			return nil, nil, errPrivatePath
		}
		if current {
			if _, required := row["required"]; !required {
				return nil, nil, errPrivatePath
			}
		}
		if legacy {
			var leaves []routeCheck
			if json.Unmarshal(checks, &leaves) != nil {
				return nil, nil, errPrivatePath
			}
			if _, err = newRouteCheckProgram(leaves, nil); err != nil {
				return nil, nil, errPrivatePath
			}
		} else {
			var value routeCheckProfile
			if json.Unmarshal(profile, &value) != nil {
				return nil, nil, errPrivatePath
			}
			program, err := newRouteCheckProgram(nil, &value)
			if err != nil {
				return nil, nil, errPrivatePath
			}
			programs[tag] = program
		}
	}
	if _, adaptive := root["adaptive_routes"]; adaptive {
		return []byte(raw), programs, nil
	}
	delete(root, "route_checks")
	clean, err := json.Marshal(root)
	if err != nil {
		return nil, nil, errPrivatePath
	}
	return clean, programs, nil
}

func (r *routeRunner) configureProfiles(programs map[string]*routeCheckProgram, adaptive map[string]string) bool {
	owned := make(map[string]routePlan, len(programs))
	for tag, program := range programs {
		node, exists := r.nodes[tag]
		if !exists || program == nil || program.profile == nil {
			return false
		}
		if _, managed := adaptive[tag]; managed {
			continue
		}
		if len(r.v2ConcretePath(tag)) == 0 {
			return false
		}
		copy, err := newRouteCheckProgram(nil, program.profile)
		if err != nil {
			return false
		}
		owned[tag] = routePlan{ID: node.ID, Outbound: tag, Profile: copy.profile}
	}
	r.profilePlans = owned
	return true
}
