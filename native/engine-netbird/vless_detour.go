package netbird

import (
	"context"
	"errors"
	"net"

	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
)

// Inspect every selectable branch, not only the currently selected member.
// Revalidation on each dial prevents a changed group from introducing a direct path.
func validatedVLESSDetour(manager adapter.OutboundManager, tag string) (adapter.Outbound, error) {
	root, ok := manager.Outbound(tag)
	if !ok {
		return nil, errors.New("netbird VLESS detour is missing")
	}
	visiting, checked := make(map[string]bool), make(map[string]bool)
	var visit func(string, adapter.Outbound, int) error
	visit = func(name string, current adapter.Outbound, depth int) error {
		if current.Type() == "vless" {
			return nil
		}
		if current.Type() != "urltest" && current.Type() != "selector" {
			return errors.New("netbird detour must contain only VLESS outbounds")
		}
		group, ok := current.(interface{ All() []string })
		if !ok || depth > 64 || visiting[name] {
			return errors.New("invalid or cyclic netbird VLESS group")
		}
		if checked[name] {
			return nil
		}
		members := group.All()
		if len(members) == 0 {
			return errors.New("netbird VLESS group is empty")
		}
		visiting[name] = true
		defer delete(visiting, name)
		for _, member := range members {
			next, exists := manager.Outbound(member)
			if member == "" || !exists {
				return errors.New("netbird VLESS group member is missing")
			}
			if err := visit(member, next, depth+1); err != nil {
				return err
			}
		}
		checked[name] = true
		return nil
	}
	if err := visit(tag, root, 0); err != nil {
		return nil, err
	}
	return root, nil
}

type vlessGroupDialer struct {
	manager adapter.OutboundManager
	tag     string
}

func (d vlessGroupDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	detour, err := validatedVLESSDetour(d.manager, d.tag)
	if err != nil {
		return nil, err
	}
	return (singDialer{detour}).DialContext(ctx, network, address)
}

type singDialer struct{ outbound adapter.Outbound }

func (d singDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return d.outbound.DialContext(ctx, network, M.ParseSocksaddr(address))
}
