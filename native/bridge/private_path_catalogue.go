package bridge

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"sort"
	"strings"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/service"
)

type privateCatalogueKey struct{}

// Construction handoff only, not an untrusted wire decoder or authorization
// source. Inputs must come from an independently authorized, normalized snapshot
// after the closed policy, TLS/SSH and graph capability checks. Local resource,
// ownership, filesystem and insecure-TLS fences are additionally enforced here.
// No Java API or accepted graph capability exposes this primitive.
type privatePathCatalogue struct {
	ctx      context.Context
	router   adapter.Router
	profiles map[string]json.RawMessage
	hash     string
}

func newPrivatePathCatalogue(parent context.Context, router adapter.Router, input map[string]json.RawMessage) (*privatePathCatalogue, error) {
	if parent == nil || parent.Err() != nil || router == nil || service.RegistryFromContext(parent) == nil || service.FromContext[adapter.OutboundRegistry](parent) == nil || len(input) < 1 || len(input) > 500 {
		return nil, errPrivatePath
	}
	ids := make([]string, 0, len(input))
	size := 0
	for id, raw := range input {
		if !privateHopID.MatchString(id) || len(raw) < 1 || len(raw) > 65536 {
			return nil, errPrivatePath
		}
		size += len(id) + len(raw)
		if size > 262144 {
			return nil, errPrivatePath
		}
		ids = append(ids, id)
	}
	sort.Strings(ids)
	owned := make(map[string]json.RawMessage, len(input))
	seen := map[[32]byte]bool{}
	for _, id := range ids {
		if parent.Err() != nil {
			return nil, errPrivatePath
		}
		raw := append([]byte(nil), input[id]...)
		d := json.NewDecoder(bytes.NewReader(raw))
		d.UseNumber()
		var node map[string]any
		if d.Decode(&node) != nil || node == nil || d.Decode(new(any)) != io.EOF {
			return nil, errPrivatePath
		}
		canonical, e := json.Marshal(node)
		// The normalized compiler emits this canonical form. Requiring exact
		// bytes also rejects duplicate keys/invalid UTF-8 before a typed parser
		// could silently collapse or substitute them.
		if e != nil || !bytes.Equal(raw, canonical) || !privateCatalogueNode(id, node) {
			return nil, errPrivatePath
		}
		delete(node, "tag")
		identity, e := json.Marshal(node)
		if e != nil {
			return nil, errPrivatePath
		}
		fingerprint := sha256.Sum256(identity)
		if seen[fingerprint] {
			return nil, errPrivatePath
		}
		seen[fingerprint] = true
		var parsed option.Outbound
		if parsed.UnmarshalJSONContext(parent, canonical) != nil {
			return nil, errPrivatePath
		}
		if _, ok := parsed.Options.(option.DialerOptionsWrapper); !ok {
			return nil, errPrivatePath
		}
		owned[id] = canonical
	}
	bound, e := json.Marshal(owned)
	if e != nil || len(bound) > 262144 {
		return nil, errPrivatePath
	}
	digest := sha256.Sum256(bound)
	c := &privatePathCatalogue{router: router, profiles: owned, hash: hex.EncodeToString(digest[:])}
	c.ctx = context.WithValue(parent, privateCatalogueKey{}, c)
	return c, nil
}

func privateCatalogueFields(node map[string]any, fields string) bool {
	allowed := map[string]bool{}
	for _, key := range strings.Fields(fields) {
		allowed[key] = true
	}
	for key := range node {
		if !allowed[key] {
			return false
		}
	}
	return true
}

func privateCatalogueNode(id string, node map[string]any) bool {
	kind, _ := node["type"].(string)
	fields := "type tag server server_port"
	switch kind {
	case "http":
		fields += " username password tls"
	case "socks":
		fields += " username password version"
	case "vless":
		fields += " uuid flow encryption packet_encoding network tls transport"
	case "ssh":
		fields += " user password private_key private_key_passphrase host_key host_key_algorithms client_version"
	default:
		return false
	}
	server, ok := node["server"].(string)
	port, isNumber := node["server_port"].(json.Number)
	number, e := port.Int64()
	if !privateCatalogueFields(node, fields) || node["tag"] != id || !ok || len(server) < 1 || len(server) > 253 || !isNumber || e != nil || number < 1 || number > 65535 {
		return false
	}
	if value, exists := node["tls"]; exists {
		tls, ok := value.(map[string]any)
		if !ok || !privateCatalogueFields(tls, "enabled server_name insecure alpn utls reality min_version max_version certificate") || tls["enabled"] != true {
			return false
		}
		if insecure, exists := tls["insecure"]; exists && insecure != false {
			return false
		}
		for key, fields := range map[string]string{"utls": "enabled fingerprint", "reality": "enabled public_key short_id"} {
			if value, exists := tls[key]; exists {
				child, ok := value.(map[string]any)
				if !ok || !privateCatalogueFields(child, fields) || child["enabled"] != true {
					return false
				}
			}
		}
	}
	if kind == "ssh" {
		keys, ok := node["host_key"].([]any)
		if !ok || len(keys) < 1 {
			return false
		}
	}
	return true
}

// Each construction decodes fresh typed options and uses only the registry
// cloned by buildPrivatePath. Neither a parent manager nor a replacement runtime
// can obtain a usable adapter through this callback. The typed detour is always
// replaced by the preceding private adapter, never an imported dependency.
func (c *privatePathCatalogue) create(child context.Context, id, tag, previous string) (adapter.Outbound, error) {
	if child == nil || child.Err() != nil || c.ctx.Err() != nil || child.Value(privateCatalogueKey{}) != c {
		return nil, errPrivatePath
	}
	manager, ok := service.FromContext[adapter.OutboundManager](child).(*privatePathRegistry)
	if !ok || manager == nil {
		return nil, errPrivatePath
	}
	if previous != "" {
		if _, ok = manager.Outbound(previous); !ok {
			return nil, errPrivatePath
		}
	}
	raw, ok := c.profiles[id]
	if !ok {
		return nil, errPrivatePath
	}
	var opts option.Outbound
	if opts.UnmarshalJSONContext(child, raw) != nil {
		return nil, errPrivatePath
	}
	wrapper, ok := opts.Options.(option.DialerOptionsWrapper)
	if !ok {
		return nil, errPrivatePath
	}
	dialer := wrapper.TakeDialerOptions()
	dialer.Detour = previous
	wrapper.ReplaceDialerOptions(dialer)
	registry := service.FromContext[adapter.OutboundRegistry](child)
	if registry == nil || child.Err() != nil || c.ctx.Err() != nil {
		return nil, errPrivatePath
	}
	return registry.CreateOutbound(child, c.router, log.NewNOPFactory().Logger(), tag, opts.Type, opts.Options)
}

func (*privatePathCatalogue) String() string     { return "PrivatePathCatalogue([redacted])" }
func (c *privatePathCatalogue) GoString() string { return c.String() }
