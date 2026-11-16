package bridge

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func privateAdaptiveWireFixture(t *testing.T, count int) ([]byte, []byte, map[string]string) {
	t.Helper()
	profiles := make(map[string]any, count)
	hops, ids := make([]any, 0, count), make([]string, 0, count)
	for i := 0; i < count; i++ {
		id := fmt.Sprintf("hop-%03d", i)
		ids = append(ids, id)
		profiles[id] = map[string]any{"type": "http", "tag": id, "server": "192.0.2.1", "server_port": 2000 + i}
		hops = append(hops, map[string]any{"id": id, "entryModes": []string{"WIFI"}, "exitClass": "INTERNAL", "features": []string{"TCP", "IPV4"}})
	}
	graph := map[string]any{
		"schemaVersion": 1, "hops": hops, "edges": []any{},
		"templates": []any{map[string]any{"id": "single", "slots": [][]string{ids}}},
		"groups":    []any{map[string]any{"id": "inside", "intent": "INTERNAL", "features": []string{"TCP", "IPV4"}, "templates": []string{"single"}}},
	}
	return privateAdaptiveMarshal(t, graph), privateAdaptiveMarshal(t, profiles), map[string]string{"inside": "managed-inside"}
}

func privateAdaptiveMarshal(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func privateAdaptiveObject(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var value map[string]any
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if err := d.Decode(&value); err != nil {
		t.Fatal(err)
	}
	return value
}

func privateAdaptiveEncode(t *testing.T, graph, catalogue []byte, groups map[string]string) []byte {
	t.Helper()
	return privateAdaptiveMarshal(t, map[string]any{
		"schemaVersion": 1, "graphB64": base64.RawURLEncoding.EncodeToString(graph),
		"catalogueB64": base64.RawURLEncoding.EncodeToString(catalogue), "groups": groups,
	})
}

func rejectPrivateAdaptive(t *testing.T, raw []byte) {
	t.Helper()
	if wire, err := decodePrivateAdaptiveWire(raw); wire != nil || err != errPrivatePath {
		t.Fatal("invalid adaptive wire returned authority, partial data or unredacted error")
	}
}

func TestPrivateAdaptiveWireStrictClosedShapeAndCanonicalOwnership(t *testing.T) {
	graph, catalogue, groups := privateAdaptiveWireFixture(t, 2)
	raw := privateAdaptiveEncode(t, graph, catalogue, groups)
	wire, err := decodePrivateAdaptiveWire(raw)
	if err != nil || wire == nil || len(wire.hash) != 64 || len(wire.catalogue) != 2 || wire.groups["inside"] != "managed-inside" ||
		!wire.graph.Allows("inside", "WIFI", []string{"hop-000"}) {
		t.Fatal("valid exact-bound wire rejected", err)
	}
	if want := fmt.Sprintf("%x", sha256.Sum256(raw)); wire.hash != want {
		t.Fatal("wire hash does not bind the canonical complete block")
	}
	beforeGraph := bytes.Clone(wire.graphRaw)
	beforeProfile := bytes.Clone(wire.catalogue["hop-000"])
	hash := wire.hash
	for i := range raw {
		raw[i] = '!'
	}
	for i := range graph {
		graph[i] = '!'
	}
	for i := range catalogue {
		catalogue[i] = '!'
	}
	groups["inside"] = "changed-after-decode"
	ids := wire.graph.GroupIDs()
	ids[0] = "changed-owned-view"
	if wire.hash != hash || !bytes.Equal(wire.graphRaw, beforeGraph) || !bytes.Equal(wire.catalogue["hop-000"], beforeProfile) ||
		wire.groups["inside"] != "managed-inside" || !reflect.DeepEqual(wire.graph.GroupIDs(), []string{"inside"}) {
		t.Fatal("caller buffers or returned metadata view changed owned wire")
	}
	for _, format := range []string{"%v", "%#v", "%s"} {
		text := fmt.Sprintf(format, wire)
		for _, private := range []string{"192.0.2.1", "hop-000", "inside", "managed-inside", wire.hash} {
			if strings.Contains(text, private) {
				t.Fatal("adaptive wire formatting disclosed a private field")
			}
		}
	}
	graph, catalogue, groups = privateAdaptiveWireFixture(t, 2)
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, graph, "", "  "); err != nil {
		t.Fatal(err)
	}
	formatted := privateAdaptiveEncode(t, pretty.Bytes(), catalogue, groups)
	formatted = append([]byte(" \n"), append(formatted, '\t', '\r', '\n')...)
	other, err := decodePrivateAdaptiveWire(formatted)
	if err != nil || other.hash != hash || !bytes.Equal(other.graphRaw, beforeGraph) {
		t.Fatal("harmless outer/graph formatting changed canonical dependency binding", err)
	}
	canonical := privateAdaptiveEncode(t, graph, catalogue, groups)
	for _, malformed := range [][]byte{nil, []byte("null"), []byte("[]"), []byte("{}"), append(bytes.Clone(canonical), []byte("null")...),
		bytes.Replace(canonical, []byte(`"schemaVersion":1`), []byte(`"schemaVersion":1,"schemaVersion":1`), 1),
		bytes.Replace(canonical, []byte(`"schemaVersion":1`), []byte(`"schemaVersion":1,"\u0073chemaVersion":1`), 1),
		bytes.Replace(canonical, []byte(`"graphB64"`), []byte(`"GraphB64"`), 1),
		bytes.Replace(canonical, []byte(`"inside":`), []byte("\"in\xffside\":"), 1),
	} {
		rejectPrivateAdaptive(t, malformed)
	}
	for _, key := range []string{"schemaVersion", "graphB64", "catalogueB64", "groups"} {
		for _, replacement := range []any{nil, true, "1", json.Number("1.0"), []any{}} {
			root := privateAdaptiveObject(t, canonical)
			root[key] = replacement
			rejectPrivateAdaptive(t, privateAdaptiveMarshal(t, root))
		}
		root := privateAdaptiveObject(t, canonical)
		delete(root, key)
		rejectPrivateAdaptive(t, privateAdaptiveMarshal(t, root))
	}
	for _, key := range []string{"graphB64", "catalogueB64"} {
		for _, text := range []string{"", "!", "Zg==", "Zg\n", "Zh", "Zg+", "Zg/"} {
			root := privateAdaptiveObject(t, canonical)
			root[key] = text
			rejectPrivateAdaptive(t, privateAdaptiveMarshal(t, root))
		}
	}
	root := privateAdaptiveObject(t, canonical)
	root["unexpected"] = "field"
	rejectPrivateAdaptive(t, privateAdaptiveMarshal(t, root))
	for _, invalid := range []any{nil, true, json.Number("1"), "", "Zg==", "Zg\n", "Zh", "Zg+", "Zg/"} {
		if _, ok := decodePrivateAdaptiveB64(invalid); ok {
			t.Fatal("noncanonical raw-url base64 accepted")
		}
	}
}

func TestPrivateAdaptiveWireRejectsUnboundGroupsAndUnsafeCatalogue(t *testing.T) {
	graph, catalogue, groups := privateAdaptiveWireFixture(t, 2)
	nullable := privateAdaptiveObject(t, graph)
	nullable["hops"].([]any)[0].(map[string]any)["exitClass"] = nil
	nullable["templates"].([]any)[0].(map[string]any)["slots"] = [][]string{{"hop-000"}, {"hop-001"}}
	nullable["edges"] = []any{map[string]any{"from": "hop-000", "to": "hop-001", "features": []string{"TCP", "IPV4"}}}
	if wire, err := decodePrivateAdaptiveWire(privateAdaptiveEncode(t, privateAdaptiveMarshal(t, nullable), catalogue, groups)); err != nil ||
		!wire.graph.Allows("inside", "WIFI", []string{"hop-000", "hop-001"}) {
		t.Fatal("legitimate transit null exit metadata was rejected", err)
	}
	for _, mutation := range []string{"missing", "extra", "unknown", "noncanonical", "duplicate", "escaped-duplicate", "null-profile"} {
		root := privateAdaptiveObject(t, catalogue)
		var raw []byte
		switch mutation {
		case "missing":
			delete(root, "hop-001")
		case "extra":
			node := privateAdaptiveObject(t, privateAdaptiveMarshal(t, root["hop-001"]))
			node["tag"], node["server_port"] = "hop-002", 2002
			root["hop-002"] = node
		case "unknown":
			root["other-hop"] = root["hop-001"]
			delete(root, "hop-001")
		case "noncanonical":
			raw = append([]byte{' '}, catalogue...)
		case "duplicate", "escaped-duplicate":
			node := privateAdaptiveMarshal(t, root["hop-000"])
			key := `"hop-000"`
			if mutation == "escaped-duplicate" {
				key = `"\u0068op-000"`
			}
			raw = []byte(`{"hop-000":` + string(node) + `,` + key + `:` + string(node) + `}`)
		case "null-profile":
			root["hop-000"] = nil
		}
		if raw == nil {
			raw = privateAdaptiveMarshal(t, root)
		}
		rejectPrivateAdaptive(t, privateAdaptiveEncode(t, graph, raw, groups))
	}
	for _, mutation := range []string{"tag", "type", "port-string", "port-zero", "port-high", "server-empty", "foreign-detour", "unknown-field", "field-case", "null", "tls-insecure", "tls-disabled", "tls-file", "tls-utls-file", "tls-reality-file", "ssh-no-pin", "ssh-file", "alias"} {
		t.Run(mutation, func(t *testing.T) {
			root := privateAdaptiveObject(t, catalogue)
			node := root["hop-000"].(map[string]any)
			switch mutation {
			case "tag":
				node["tag"] = "wrong-hop"
			case "type":
				node["type"] = "direct"
			case "port-string":
				node["server_port"] = "443"
			case "port-zero":
				node["server_port"] = 0
			case "port-high":
				node["server_port"] = 65536
			case "server-empty":
				node["server"] = ""
			case "foreign-detour":
				node["detour"] = "direct"
			case "unknown-field":
				node["unexpected"] = "value"
			case "field-case":
				node["Type"] = "http"
			case "null":
				node["password"] = nil
			case "tls-insecure":
				node["tls"] = map[string]any{"enabled": true, "insecure": true}
			case "tls-disabled":
				node["tls"] = map[string]any{"enabled": false}
			case "tls-file":
				node["tls"] = map[string]any{"enabled": true, "certificate_path": "/fixture/file"}
			case "tls-utls-file":
				node["tls"] = map[string]any{"enabled": true, "utls": map[string]any{"enabled": true, "fingerprint": "chrome", "path": "/fixture/file"}}
			case "tls-reality-file":
				node["tls"] = map[string]any{"enabled": true, "reality": map[string]any{"enabled": true, "private_key_path": "/fixture/file"}}
			case "ssh-no-pin":
				node["type"] = "ssh"
			case "ssh-file":
				node["type"], node["host_key"], node["private_key_path"] = "ssh", []string{"fixture-key"}, "/fixture/file"
			case "alias":
				root["hop-001"].(map[string]any)["server_port"] = node["server_port"]
			}
			rejectPrivateAdaptive(t, privateAdaptiveEncode(t, graph, privateAdaptiveMarshal(t, root), groups))
		})
	}
	for _, mapping := range []map[string]string{{}, {"other": "managed-inside"}, {"inside": "managed-inside", "extra": "managed-other"},
		{"inside": "direct"}, {"inside": ""}, {"inside": "-invalid"}, {"inside": "has space"},
		{"inside": "UPPER"}, {"inside": "bad.dot"}, {"inside": "_leading"}, {"inside": "syn443_reserved"},
		{"inside": strings.Repeat("x", 65)}} {
		rejectPrivateAdaptive(t, privateAdaptiveEncode(t, graph, catalogue, mapping))
	}
	for _, graphRaw := range [][]byte{
		bytes.Replace(graph, []byte(`"schemaVersion":1`), []byte(`"schemaVersion":1,"\u0073chemaVersion":1`), 1),
		bytes.Replace(graph, []byte(`"schemaVersion"`), []byte(`"SchemaVersion"`), 1),
		bytes.Replace(graph, []byte(`"id":"hop-001"`), []byte(`"id":"not-in-catalogue"`), 1),
	} {
		rejectPrivateAdaptive(t, privateAdaptiveEncode(t, graphRaw, catalogue, groups))
	}
	root := privateAdaptiveObject(t, graph)
	rows := []any{}
	mapping := map[string]string{}
	for i := 0; i < 16; i++ {
		id := fmt.Sprintf("group-%02d", i)
		rows = append(rows, map[string]any{"id": id, "intent": "INTERNAL", "features": []string{"TCP", "IPV4"}, "templates": []string{"single"}})
		mapping[id] = "managed-" + id
	}
	root["groups"] = rows
	if wire, err := decodePrivateAdaptiveWire(privateAdaptiveEncode(t, privateAdaptiveMarshal(t, root), catalogue, mapping)); err != nil || len(wire.groups) != 16 {
		t.Fatal("sixteen exact groups were truncated or refused", err)
	}
	mapping["group-01"] = mapping["group-00"]
	rejectPrivateAdaptive(t, privateAdaptiveEncode(t, privateAdaptiveMarshal(t, root), catalogue, mapping))
}

func TestPrivateAdaptiveWireParserAndByteBounds(t *testing.T) {
	graph, catalogue, groups := privateAdaptiveWireFixture(t, 1)
	raw := privateAdaptiveEncode(t, graph, catalogue, groups)
	maxWire := append(bytes.Clone(raw), bytes.Repeat([]byte{' '}, privateAdaptiveWireLimit-len(raw))...)
	if _, err := decodePrivateAdaptiveWire(maxWire); err != nil {
		t.Fatal("exact whole-wire byte limit rejected", err)
	}
	rejectPrivateAdaptive(t, append(maxWire, ' '))
	for _, extra := range []int{0, 1} {
		root := privateAdaptiveObject(t, catalogue)
		node := root["hop-000"].(map[string]any)
		node["username"] = ""
		node["username"] = strings.Repeat("p", 65536-len(privateAdaptiveMarshal(t, node))+extra)
		encoded := privateAdaptiveEncode(t, graph, privateAdaptiveMarshal(t, root), groups)
		if extra == 0 {
			if _, err := decodePrivateAdaptiveWire(encoded); err != nil {
				t.Fatal("exact per-profile byte limit rejected", err)
			}
		} else {
			rejectPrivateAdaptive(t, encoded)
		}
	}
	_, four, _ := privateAdaptiveWireFixture(t, 4)
	root := privateAdaptiveObject(t, four)
	for i := 0; i < 3; i++ {
		node := root[fmt.Sprintf("hop-%03d", i)].(map[string]any)
		node["username"] = ""
		node["username"] = strings.Repeat("p", 65536-len(privateAdaptiveMarshal(t, node)))
	}
	last := root["hop-003"].(map[string]any)
	last["username"] = ""
	last["username"] = strings.Repeat("p", privateAdaptiveDecodedLimit-len(privateAdaptiveMarshal(t, root)))
	exactCatalogue := privateAdaptiveMarshal(t, root)
	if len(exactCatalogue) != privateAdaptiveDecodedLimit {
		t.Fatal("fixture did not reach exact aggregate limit")
	}
	budget := privateAdaptiveTokenLimit
	if profiles, ids, ok := decodePrivateAdaptiveCatalogue(exactCatalogue, &budget); !ok || len(profiles) != 4 || len(ids) != 4 {
		t.Fatal("exact aggregate catalogue byte limit rejected")
	}
	last["username"] = last["username"].(string) + "p"
	budget = privateAdaptiveTokenLimit
	if _, _, ok := decodePrivateAdaptiveCatalogue(privateAdaptiveMarshal(t, root), &budget); ok {
		t.Fatal("oversized aggregate catalogue accepted")
	}
	for _, size := range []int{privateAdaptiveDecodedLimit, privateAdaptiveDecodedLimit + 1} {
		text := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{'a'}, size))
		if _, ok := decodePrivateAdaptiveB64(text); ok != (size == privateAdaptiveDecodedLimit) {
			t.Fatal("decoded base64 byte boundary changed")
		}
	}
	limits := privateAdaptiveJSONLimits{rootMembers: 500, arrayItems: 256}
	for _, tc := range []struct {
		raw string
		ok  bool
	}{
		{strings.Repeat("[", 16) + "0" + strings.Repeat("]", 16), true},
		{strings.Repeat("[", 17) + "0" + strings.Repeat("]", 17), false},
		{"[" + strings.Repeat("0,", 255) + "0]", true},
		{"[" + strings.Repeat("0,", 256) + "0]", false},
		{`{"a":{"key":1,"\u006bey":2}}`, false},
		{`{"a":null}`, false},
		{"{\"a\":\"\xff\"}", false},
	} {
		budget := privateAdaptiveTokenLimit
		if _, ok := readPrivateAdaptiveJSON([]byte(tc.raw), &budget, limits); ok != tc.ok {
			t.Fatal("bounded strict token-walker outcome changed")
		}
	}
	for _, count := range []int{128, 129} {
		child := map[string]any{}
		for i := 0; i < count; i++ {
			child[fmt.Sprintf("key-%03d", i)] = "value"
		}
		budget := privateAdaptiveTokenLimit
		if _, ok := readPrivateAdaptiveJSON(privateAdaptiveMarshal(t, map[string]any{"child": child}), &budget, limits); ok != (count == 128) {
			t.Fatal("nested map limit changed")
		}
	}
	for _, width := range []int{125, 126} {
		inner := "[" + strings.Repeat("0,", width-1) + "0]"
		wide := "[" + strings.Repeat(inner+",", 255) + inner + "]"
		budget := privateAdaptiveTokenLimit
		if _, ok := readPrivateAdaptiveJSON([]byte(wide), &budget, limits); ok != (width == 125) {
			t.Fatal("combined token budget did not bound otherwise legal arrays")
		}
	}
}

func TestPrivateAdaptiveWireFullFiveHundredCatalogueFitsWithoutTruncation(t *testing.T) {
	graph, catalogue, groups := privateAdaptiveWireFixture(t, 500)
	raw := privateAdaptiveEncode(t, graph, catalogue, groups)
	if len(raw) > privateAdaptiveWireLimit {
		t.Fatal("synthetic500 fixture does not fit the declared wire bound")
	}
	wire, err := decodePrivateAdaptiveWire(raw)
	if err != nil || wire == nil || len(wire.catalogue) != 500 {
		t.Fatal("allowed500 catalogue was truncated or refused", err)
	}
	if count, ok := wire.graph.UpperBound("inside"); !ok || count != 500 || !wire.graph.Allows("inside", "WIFI", []string{"hop-499"}) {
		t.Fatal("last of500 bound profiles was lost")
	}
	graph, catalogue, groups = privateAdaptiveWireFixture(t, 501)
	rejectPrivateAdaptive(t, privateAdaptiveEncode(t, graph, catalogue, groups))
}
