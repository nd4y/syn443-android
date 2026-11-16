package bridge

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"sort"
	"strings"
	"unicode/utf8"

	"io.syn443/routegraph"
)

const privateAdaptiveWireLimit = 196608
const privateAdaptiveDecodedLimit = 262144
const privateAdaptiveTokenLimit = 32768

func privateAdaptiveManagedTag(tag string) bool {
	return privateHopID.MatchString(tag) && !strings.Contains(tag, ".") && tag != "direct" && !strings.HasPrefix(tag, "syn443_")
}

// A bounded, owned representation, not permission to construct an adapter.
// Actual Runtime activation still needs independent source authorization,
// configured-tag collision checks, negotiated capability/lease and a complete
// newPrivatePathCatalogue typed validation against its own box context/router.
type privateAdaptiveWire struct {
	graph     *routegraph.Graph
	graphRaw  []byte
	catalogue map[string]json.RawMessage
	groups    map[string]string // graph group ID -> configured managed outbound tag
	hash      string
}

func (*privateAdaptiveWire) String() string     { return "PrivateAdaptiveWire([redacted])" }
func (w *privateAdaptiveWire) GoString() string { return w.String() }

type privateAdaptiveJSONLimits struct {
	rootMembers int
	arrayItems  int
	allowNull   bool
	maxBytes    int // zero keeps the closed decoded-document limit
}

// Token walking preserves duplicate and escaped-duplicate keys, case, null and
// JSON number lexemes before a typed/map decoder could erase their distinction.
// The shared remaining budget bounds all three decoded documents together.
func readPrivateAdaptiveJSON(raw []byte, remaining *int, limits privateAdaptiveJSONLimits) (any, bool) {
	limit := limits.maxBytes
	if limit == 0 {
		limit = privateAdaptiveDecodedLimit
	}
	if len(raw) == 0 || len(raw) > limit || !utf8.Valid(raw) || remaining == nil {
		return nil, false
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var read func(int) (any, bool)
	token := func() (json.Token, bool) {
		if *remaining <= 0 {
			return nil, false
		}
		*remaining -= 1
		v, err := d.Token()
		return v, err == nil
	}
	read = func(depth int) (any, bool) {
		if depth > 16 {
			return nil, false
		}
		value, ok := token()
		if !ok || value == nil && !limits.allowNull {
			return nil, false
		}
		delimiter, container := value.(json.Delim)
		if !container {
			return value, true
		}
		switch delimiter {
		case '{':
			max := 128
			if depth == 0 {
				max = limits.rootMembers
			}
			out := make(map[string]any)
			for d.More() {
				if len(out) >= max {
					return nil, false
				}
				keyToken, ok := token()
				key, stringKey := keyToken.(string)
				if !ok || !stringKey {
					return nil, false
				}
				if _, duplicate := out[key]; duplicate {
					return nil, false
				}
				child, ok := read(depth + 1)
				if !ok {
					return nil, false
				}
				out[key] = child
			}
			end, ok := token()
			return out, ok && end == json.Delim('}')
		case '[':
			out := make([]any, 0)
			for d.More() {
				if len(out) >= limits.arrayItems {
					return nil, false
				}
				child, ok := read(depth + 1)
				if !ok {
					return nil, false
				}
				out = append(out, child)
			}
			end, ok := token()
			return out, ok && end == json.Delim(']')
		default:
			return nil, false
		}
	}
	value, ok := read(0)
	if !ok {
		return nil, false
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, false
	}
	return value, true
}

func decodePrivateAdaptiveB64(value any) ([]byte, bool) {
	raw, ok := value.(string)
	if !ok || len(raw) == 0 || base64.RawURLEncoding.DecodedLen(len(raw)) > privateAdaptiveDecodedLimit {
		return nil, false
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(raw)
	return decoded, err == nil && len(decoded) > 0 && len(decoded) <= privateAdaptiveDecodedLimit && base64.RawURLEncoding.EncodeToString(decoded) == raw
}

func decodePrivateAdaptiveCatalogue(raw []byte, remaining *int) (map[string]json.RawMessage, []string, bool) {
	value, ok := readPrivateAdaptiveJSON(raw, remaining, privateAdaptiveJSONLimits{rootMembers: 500, arrayItems: 256})
	root, object := value.(map[string]any)
	if !ok || !object || len(root) < 1 || len(root) > 500 {
		return nil, nil, false
	}
	canonical, err := json.Marshal(root)
	if err != nil || !bytes.Equal(raw, canonical) {
		return nil, nil, false
	}
	owned := make(map[string]json.RawMessage, len(root))
	ids := make([]string, 0, len(root))
	seen := make(map[[32]byte]bool, len(root))
	size := 0
	for id, value := range root {
		node, object := value.(map[string]any)
		if !privateHopID.MatchString(id) || !object || !privateCatalogueNode(id, node) {
			return nil, nil, false
		}
		profile, err := json.Marshal(node)
		if err != nil || len(profile) < 1 || len(profile) > 65536 {
			return nil, nil, false
		}
		size += len(id) + len(profile)
		if size > privateAdaptiveDecodedLimit {
			return nil, nil, false
		}
		// Same alias guard as newPrivatePathCatalogue, without typed construction.
		// The graph must not count one normalized proxy under multiple hop IDs.
		delete(node, "tag")
		identity, err := json.Marshal(node)
		if err != nil {
			return nil, nil, false
		}
		fingerprint := sha256.Sum256(identity)
		if seen[fingerprint] {
			return nil, nil, false
		}
		seen[fingerprint] = true
		owned[id] = append(json.RawMessage(nil), profile...)
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return owned, ids, true
}

func decodePrivateAdaptiveWire(raw []byte) (*privateAdaptiveWire, error) {
	bad := func() (*privateAdaptiveWire, error) { return nil, errPrivatePath }
	if len(raw) < 1 || len(raw) > privateAdaptiveWireLimit {
		return bad()
	}
	remaining := privateAdaptiveTokenLimit
	value, ok := readPrivateAdaptiveJSON(raw, &remaining, privateAdaptiveJSONLimits{rootMembers: 4, arrayItems: 256})
	root, object := value.(map[string]any)
	if !ok || !object || len(root) != 4 || root["schemaVersion"] != json.Number("1") {
		return bad()
	}
	for _, key := range []string{"schemaVersion", "graphB64", "catalogueB64", "groups"} {
		if _, present := root[key]; !present {
			return bad()
		}
	}
	graphRaw, ok := decodePrivateAdaptiveB64(root["graphB64"])
	if !ok {
		return bad()
	}
	catalogueRaw, ok := decodePrivateAdaptiveB64(root["catalogueB64"])
	if !ok {
		return bad()
	}
	catalogue, ids, ok := decodePrivateAdaptiveCatalogue(catalogueRaw, &remaining)
	if !ok {
		return bad()
	}
	// Graph arrays legitimately include500 hops and up to4096 declared edges;
	// only graph exitClass may be null. The graph's own closed schema follows.
	graphValue, ok := readPrivateAdaptiveJSON(graphRaw, &remaining, privateAdaptiveJSONLimits{rootMembers: 128, arrayItems: 4096, allowNull: true})
	if !ok {
		return bad()
	}
	graph, err := routegraph.Decode(graphRaw, ids)
	if err != nil {
		return bad()
	}
	groupValues, object := root["groups"].(map[string]any)
	groupIDs := graph.GroupIDs()
	if !object || len(groupIDs) < 1 || len(groupIDs) > privateGroupLimit || len(groupValues) != len(groupIDs) {
		return bad()
	}
	groups, tags := make(map[string]string, len(groupIDs)), make(map[string]bool, len(groupIDs))
	for _, id := range groupIDs {
		tag, ok := groupValues[id].(string)
		if !ok || !privateAdaptiveManagedTag(tag) || tags[tag] {
			return bad()
		}
		groups[id], tags[tag] = tag, true
	}
	graphRaw, err = json.Marshal(graphValue)
	if err != nil {
		return bad()
	}
	canonicalCatalogue, err := json.Marshal(catalogue)
	if err != nil {
		return bad()
	}
	canonical, err := json.Marshal(map[string]any{
		"schemaVersion": 1, "graphB64": base64.RawURLEncoding.EncodeToString(graphRaw),
		"catalogueB64": base64.RawURLEncoding.EncodeToString(canonicalCatalogue), "groups": groups,
	})
	if err != nil || len(canonical) > privateAdaptiveWireLimit {
		return bad()
	}
	digest := sha256.Sum256(canonical)
	return &privateAdaptiveWire{graph: graph, graphRaw: append([]byte(nil), graphRaw...), catalogue: catalogue, groups: groups, hash: hex.EncodeToString(digest[:])}, nil
}
