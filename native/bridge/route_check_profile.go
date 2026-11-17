package bridge

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

var routeCheckProfileID = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,63}$`)

// Closed data only, never remote executable code. A decoded profile owns all
// arrays; constructors clone again before it becomes immutable runtime policy.
type routeCheckProfile struct {
	SchemaVersion int              `json:"schemaVersion"`
	ID            string           `json:"id"`
	Revision      int64            `json:"revision"`
	DeadlineMS    int64            `json:"deadlineMs"`
	Leaves        []routeCheckLeaf `json:"leaves"`
	Gates         []string         `json:"gates"`
	Stages        []routeCheckExpr `json:"stages"`
}
type routeCheckLeaf struct {
	ID    string     `json:"id"`
	Check routeCheck `json:"check"`
}
type routeCheckExpr struct {
	Leaf   string            `json:"leaf,omitempty"`
	All    []routeCheckExpr  `json:"all,omitempty"`
	Any    []routeCheckExpr  `json:"any,omitempty"`
	Quorum *routeCheckQuorum `json:"quorum,omitempty"`
}
type routeCheckQuorum struct {
	K  int              `json:"k"`
	Of []routeCheckExpr `json:"of"`
}

func (*routeCheckProfile) String() string     { return "RouteCheckProfile([redacted])" }
func (p *routeCheckProfile) GoString() string { return p.String() }

// The separate decoder keeps exact key presence, case and duplicate detection.
// No existing generic parser/leaf guard is widened for this new format.
func checkProfileObject(raw []byte, keys ...string) (map[string]json.RawMessage, error) {
	if len(raw) < 2 || len(raw) > 24000 || !utf8.Valid(raw) {
		return nil, errPrivatePath
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	first, err := d.Token()
	if err != nil || first != json.Delim('{') {
		return nil, errPrivatePath
	}
	result := make(map[string]json.RawMessage)
	for d.More() {
		token, err := d.Token()
		key, ok := token.(string)
		if err != nil || !ok || !slices.Contains(keys, key) {
			return nil, errPrivatePath
		}
		if _, duplicate := result[key]; duplicate {
			return nil, errPrivatePath
		}
		var value json.RawMessage
		if d.Decode(&value) != nil || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return nil, errPrivatePath
		}
		result[key] = append(json.RawMessage(nil), value...)
	}
	end, err := d.Token()
	if err != nil || end != json.Delim('}') {
		return nil, errPrivatePath
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, errPrivatePath
	}
	return result, nil
}
func checkProfileInteger(raw json.RawMessage, maximum int64) (int64, error) {
	value := bytes.TrimSpace(raw)
	if len(value) == 0 {
		return 0, errPrivatePath
	}
	for _, b := range value {
		if b < '0' || b > '9' {
			return 0, errPrivatePath
		}
	}
	n, err := strconv.ParseInt(string(value), 10, 64)
	if err != nil || n < 1 || n > maximum {
		return 0, errPrivatePath
	}
	return n, nil
}
func checkProfileString(raw json.RawMessage) (string, error) {
	var value string
	if len(raw) == 0 || json.Unmarshal(raw, &value) != nil || !routeCheckProfileID.MatchString(value) {
		return "", errPrivatePath
	}
	return value, nil
}
func checkProfileArray(raw json.RawMessage, maximum int) ([]json.RawMessage, error) {
	var result []json.RawMessage
	if len(raw) == 0 || json.Unmarshal(raw, &result) != nil || result == nil || len(result) > maximum {
		return nil, errPrivatePath
	}
	return result, nil
}
func decodeCheckExpr(raw json.RawMessage, depth int, nodes *int) (routeCheckExpr, error) {
	var expression routeCheckExpr
	*nodes++
	if depth > 4 || *nodes > 7 {
		return expression, errPrivatePath
	}
	object, err := checkProfileObject(raw, "leaf", "all", "any", "quorum")
	if err != nil || len(object) != 1 {
		return expression, errPrivatePath
	}
	if value, exists := object["leaf"]; exists {
		expression.Leaf, err = checkProfileString(value)
		return expression, err
	}
	var children []json.RawMessage
	for _, key := range []string{"all", "any", "quorum"} {
		value, exists := object[key]
		if !exists {
			continue
		}
		if key == "quorum" {
			quorum, e := checkProfileObject(value, "k", "of")
			if e != nil || len(quorum) != 2 {
				return expression, errPrivatePath
			}
			children, err = checkProfileArray(quorum["of"], 4)
			k, e := checkProfileInteger(quorum["k"], 4)
			if err != nil || e != nil || k > int64(len(children)) {
				return expression, errPrivatePath
			}
			expression.Quorum = &routeCheckQuorum{K: int(k)}
		} else {
			children, err = checkProfileArray(value, 4)
		}
		if err != nil || len(children) < 2 {
			return expression, errPrivatePath
		}
		decoded := make([]routeCheckExpr, 0, len(children))
		for _, child := range children {
			x, e := decodeCheckExpr(child, depth+1, nodes)
			if e != nil {
				return expression, e
			}
			decoded = append(decoded, x)
		}
		switch key {
		case "all":
			expression.All = decoded
		case "any":
			expression.Any = decoded
		case "quorum":
			expression.Quorum.Of = decoded
		}
	}
	return expression, nil
}
func (p *routeCheckProfile) UnmarshalJSON(raw []byte) error {
	object, err := checkProfileObject(raw, "schemaVersion", "id", "revision", "deadlineMs", "leaves", "gates", "stages")
	if err != nil || len(object) != 7 {
		return errPrivatePath
	}
	version, err := checkProfileInteger(object["schemaVersion"], 2)
	if err != nil || version != 2 {
		return errPrivatePath
	}
	id, err := checkProfileString(object["id"])
	if err != nil {
		return err
	}
	revision, err := checkProfileInteger(object["revision"], 9007199254740991)
	if err != nil {
		return err
	}
	deadline, err := checkProfileInteger(object["deadlineMs"], 12000)
	if err != nil {
		return err
	}
	leaves, err := checkProfileArray(object["leaves"], 4)
	if err != nil || len(leaves) < 1 {
		return errPrivatePath
	}
	result := routeCheckProfile{SchemaVersion: 2, ID: id, Revision: revision, DeadlineMS: deadline,
		Leaves: make([]routeCheckLeaf, 0, len(leaves)), Gates: []string{}, Stages: []routeCheckExpr{}}
	ids, definitions := map[string]routeCheck{}, map[string]bool{}
	for _, leaf := range leaves {
		value, e := checkProfileObject(leaf, "id", "check")
		if e != nil || len(value) != 2 {
			return errPrivatePath
		}
		id, e := checkProfileString(value["id"])
		if e != nil {
			return e
		}
		if _, duplicate := ids[id]; duplicate {
			return errPrivatePath
		}
		var check routeCheck
		if json.Unmarshal(value["check"], &check) != nil || !validV2ProfileCheck(check) {
			return errPrivatePath
		}
		definition, e := json.Marshal(check)
		if e != nil || definitions[string(definition)] {
			return errPrivatePath
		}
		definitions[string(definition)], ids[id] = true, check
		result.Leaves = append(result.Leaves, routeCheckLeaf{ID: id, Check: check})
	}
	gateValues, err := checkProfileArray(object["gates"], 4)
	if err != nil {
		return err
	}
	used, gated := map[string]bool{}, map[string]bool{}
	for _, rawID := range gateValues {
		id, e := checkProfileString(rawID)
		if e != nil {
			return e
		}
		if _, exists := ids[id]; !exists || used[id] {
			return errPrivatePath
		}
		used[id], gated[id] = true, true
		result.Gates = append(result.Gates, id)
	}
	stageValues, err := checkProfileArray(object["stages"], 4)
	if err != nil || len(gateValues)+len(stageValues) == 0 {
		return errPrivatePath
	}
	nodes := 0
	var references func(routeCheckExpr) bool
	references = func(expression routeCheckExpr) bool {
		if expression.Leaf != "" {
			if _, exists := ids[expression.Leaf]; !exists || used[expression.Leaf] {
				return false
			}
			used[expression.Leaf] = true
			return true
		}
		children := expression.All
		if expression.Any != nil {
			children = expression.Any
		}
		if expression.Quorum != nil {
			children = expression.Quorum.Of
		}
		for _, child := range children {
			if !references(child) {
				return false
			}
		}
		return true
	}
	for _, stage := range stageValues {
		x, e := decodeCheckExpr(stage, 1, &nodes)
		if e != nil || !references(x) {
			return errPrivatePath
		}
		result.Stages = append(result.Stages, x)
	}
	if len(used) != len(ids) {
		return errPrivatePath
	}
	for id, check := range ids {
		if (check.Method == "tls" || check.Method == "https_exit_ip" || check.Method == "https_exit_country") && !gated[id] {
			return errPrivatePath
		}
	}
	sort.Slice(result.Leaves, func(i, j int) bool { return result.Leaves[i].ID < result.Leaves[j].ID })
	*p = result
	return nil
}

// V2 target contract matches the compiler without changing legacy primitives.
func validV2ProfileCheck(check routeCheck) bool {
	if !validRouteCheck(check) || strings.ContainsAny(check.Target, "\\#") || strings.IndexFunc(check.Target, func(r rune) bool { return r <= 32 || r > 126 }) >= 0 {
		return false
	}
	host := func(value string) bool {
		if address, err := netip.ParseAddr(value); err == nil {
			return address.Zone() == ""
		}
		if len(value) < 1 || len(value) > 253 || value != strings.ToLower(value) || strings.HasSuffix(value, ".") {
			return false
		}
		for _, label := range strings.Split(value, ".") {
			if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return false
			}
			for _, r := range label {
				if r != '-' && (r < 'a' || r > 'z') && (r < '0' || r > '9') {
					return false
				}
			}
		}
		return true
	}
	port := func(value string) bool {
		return len(value) >= 1 && len(value) <= 5 && strings.IndexFunc(value, func(r rune) bool { return r < '0' || r > '9' }) < 0 && validRoutePort(value)
	}
	if check.Method == "tcp" || check.Method == "ssh_banner" {
		h, p, err := net.SplitHostPort(check.Target)
		return err == nil && host(h) && port(p)
	}
	u, err := url.Parse(check.Target)
	return err == nil && u.Scheme == "https" && u.User == nil && u.Opaque == "" && !strings.HasSuffix(u.Host, ":") && host(u.Hostname()) && (u.Port() == "" || port(u.Port())) &&
		(check.Method != "https_exit_country" || (u.Path == "" || u.Path == "/") && u.RawPath == "" && u.RawQuery == "" && !u.ForceQuery)
}

type routeCheckProgram struct {
	checks  []routeCheck
	profile *routeCheckProfile
	encoded []byte
	hash    string
}

func newRouteCheckProgram(checks []routeCheck, profile *routeCheckProfile) (*routeCheckProgram, error) {
	p := &routeCheckProgram{}
	if profile == nil {
		if len(checks) < 1 || len(checks) > 4 {
			return nil, errPrivatePath
		}
		p.checks = append([]routeCheck(nil), checks...)
		for _, check := range p.checks {
			if !validRouteCheck(check) {
				return nil, errPrivatePath
			}
		}
		raw, err := json.Marshal(p.checks)
		if err != nil {
			return nil, errPrivatePath
		}
		p.encoded = raw
		// Preserve the existing legacy selector hash literally.
		digest := sha256.Sum256(raw)
		p.hash = hex.EncodeToString(digest[:])
		return p, nil
	}
	if len(checks) != 0 {
		return nil, errPrivatePath
	}
	raw, err := json.Marshal(profile)
	if err != nil {
		return nil, errPrivatePath
	}
	var owned routeCheckProfile
	if json.Unmarshal(raw, &owned) != nil {
		return nil, errPrivatePath
	}
	p.profile = &owned
	p.encoded, err = json.Marshal(&owned)
	if err != nil {
		return nil, errPrivatePath
	}
	digest := sha256.Sum256(append([]byte("syn443-route-check-plan-v2\n"), p.encoded...))
	p.hash = hex.EncodeToString(digest[:])
	return p, nil
}
func (p *routeCheckProgram) count() int {
	if p == nil {
		return 0
	}
	if p.profile != nil {
		return len(p.profile.Leaves)
	}
	return len(p.checks)
}
func (p *routeCheckProgram) allChecks() []routeCheck {
	if p.profile == nil {
		return append([]routeCheck(nil), p.checks...)
	}
	checks := make([]routeCheck, 0, len(p.profile.Leaves))
	for _, leaf := range p.profile.Leaves {
		checks = append(checks, leaf.Check)
	}
	return checks
}
func (p *routeCheckProgram) hasCountryGate(intent string) bool {
	if p.profile == nil {
		for _, check := range p.checks {
			if check.Method == "https_exit_country" && check.ExpectedExitClass == intent {
				return true
			}
		}
		return false
	}
	for _, id := range p.profile.Gates {
		for _, leaf := range p.profile.Leaves {
			if leaf.ID == id && leaf.Check.Method == "https_exit_country" && leaf.Check.ExpectedExitClass == intent {
				return true
			}
		}
	}
	return false
}
func (p *routeCheckProgram) equal(other *routeCheckProgram) bool {
	return p != nil && other != nil && (p.profile == nil) == (other.profile == nil) && bytes.Equal(p.encoded, other.encoded)
}
func (*routeCheckProgram) String() string     { return "RouteCheckProgram([redacted])" }
func (p *routeCheckProgram) GoString() string { return p.String() }

func (p *routePlan) UnmarshalJSON(raw []byte) error {
	object, err := checkProfileObject(raw, "id", "outbound", "checks", "profile")
	if err != nil || len(object) != 3 {
		return errPrivatePath
	}
	var result routePlan
	if json.Unmarshal(object["id"], &result.ID) != nil || json.Unmarshal(object["outbound"], &result.Outbound) != nil {
		return errPrivatePath
	}
	checks, hasChecks := object["checks"]
	profile, hasProfile := object["profile"]
	if hasChecks == hasProfile {
		return errPrivatePath
	}
	if hasChecks {
		if json.Unmarshal(checks, &result.Checks) != nil {
			return errPrivatePath
		}
	}
	if hasProfile {
		if json.Unmarshal(profile, &result.Profile) != nil || result.Profile == nil {
			return errPrivatePath
		}
	}
	if _, err = newRouteCheckProgram(result.Checks, result.Profile); err != nil {
		return err
	}
	*p = result
	return nil
}
func (p routePlan) MarshalJSON() ([]byte, error) {
	if p.Profile == nil {
		type legacy struct {
			ID       string       `json:"id"`
			Outbound string       `json:"outbound"`
			Checks   []routeCheck `json:"checks"`
		}
		return json.Marshal(legacy{p.ID, p.Outbound, p.Checks})
	}
	if len(p.Checks) != 0 {
		return nil, errPrivatePath
	}
	type current struct {
		ID       string             `json:"id"`
		Outbound string             `json:"outbound"`
		Profile  *routeCheckProfile `json:"profile"`
	}
	return json.Marshal(current{p.ID, p.Outbound, p.Profile})
}
