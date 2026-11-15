package bridge

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/service"
)

var errPrivatePath = errors.New("private path unavailable")
var privateHopID = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// A construction-only registry. It cannot consult a parent default/endpoint,
// mutate a live configured manager or independently retire owned adapters.
type privatePathRegistry struct {
	mu      sync.RWMutex
	nodes   map[string]adapter.Outbound
	ordered []adapter.Outbound
	closed  bool
}

var _ adapter.OutboundManager = (*privatePathRegistry)(nil)

func (m *privatePathRegistry) Start(adapter.StartStage) error { return errPrivatePath }
func (m *privatePathRegistry) Close() error                   { return errPrivatePath }
func (m *privatePathRegistry) Remove(string) error            { return errPrivatePath }
func (m *privatePathRegistry) Create(context.Context, adapter.Router, log.ContextLogger, string, string, any) error {
	return errPrivatePath
}
func (m *privatePathRegistry) Default() adapter.Outbound { return nil }
func (m *privatePathRegistry) Outbounds() []adapter.Outbound {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]adapter.Outbound(nil), m.ordered...)
}
func (m *privatePathRegistry) Outbound(tag string) (adapter.Outbound, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	value, ok := m.nodes[tag]
	return value, ok && !m.closed
}
func (m *privatePathRegistry) add(node adapter.Outbound) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || len(m.nodes) >= 4 || m.nodes[node.Tag()] != nil {
		return errPrivatePath
	}
	m.nodes[node.Tag()] = node
	m.ordered = append(m.ordered, node)
	return nil
}

type privatePath struct {
	ctx      context.Context
	cancel   context.CancelFunc
	registry *privatePathRegistry
	owned    []adapter.Outbound
	once     sync.Once
	closeErr error
}

func (p *privatePath) String() string { return "PrivatePath([redacted])" }

// This primitive grants no graph, probe, selection or resource admission. It is
// not exposed through the Java API or any accepted policy. Its resolver must
// bind separately authorized immutable profiles and override their typed detour.
// A future active/draining pool must own traffic handles before runtime use.
// A non-nil retained result has no usable-route authority: cleanup failed and
// its adapter reservation must remain held until confirmed owner recovery.
func buildPrivatePath(parent context.Context, hops []string, create func(context.Context, string, string, string) (adapter.Outbound, error)) (result *privatePath, retained *privatePath, err error) {
	if parent == nil || parent.Err() != nil || create == nil || len(hops) < 1 || len(hops) > 4 ||
		service.RegistryFromContext(parent) == nil || service.FromContext[adapter.OutboundManager](parent) == nil {
		return nil, nil, errPrivatePath
	}
	seen := map[string]bool{}
	for _, id := range hops {
		if !privateHopID.MatchString(id) || seen[id] {
			return nil, nil, errPrivatePath
		}
		seen[id] = true
	}
	var nonce [16]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return nil, nil, errPrivatePath
	}
	prefix := "candidate-" + hex.EncodeToString(nonce[:])
	child, cancel := context.WithCancel(service.ExtendContext(parent))
	manager := &privatePathRegistry{nodes: map[string]adapter.Outbound{}}
	child = service.ContextWith[adapter.OutboundManager](child, manager)
	owned := &privatePath{ctx: child, cancel: cancel, registry: manager}
	defer func() {
		if recover() != nil {
			result = nil
			err = errPrivatePath
		}
		if err != nil {
			if owned.Close() != nil {
				retained = owned
			}
			result = nil
			err = errPrivatePath
		}
	}()
	previous := ""
	for i, id := range hops {
		if child.Err() != nil {
			return nil, nil, errPrivatePath
		}
		tag := fmt.Sprintf("%s-%d", prefix, i)
		node, createErr := create(child, id, tag, previous)
		// Some constructors return a partially initialized object with an error.
		// Own it before inspecting errors, tags, dependencies or lifecycle.
		if node != nil {
			owned.owned = append(owned.owned, node)
		}
		if createErr != nil || node == nil || node.Tag() != tag {
			return nil, nil, errPrivatePath
		}
		switch node.Type() {
		case "http", "socks", "vless", "ssh":
		default:
			return nil, nil, errPrivatePath
		}
		dependencies := node.Dependencies()
		if previous == "" && len(dependencies) != 0 || previous != "" && (len(dependencies) != 1 || dependencies[0] != previous) {
			return nil, nil, errPrivatePath
		}
		if err = manager.add(node); err != nil {
			return nil, nil, errPrivatePath
		}
		for _, stage := range adapter.ListStartStages {
			if child.Err() != nil {
				return nil, nil, errPrivatePath
			}
			if err = adapter.LegacyStart(node, stage); err != nil {
				return nil, nil, errPrivatePath
			}
		}
		previous = tag
	}
	if child.Err() != nil {
		return nil, nil, errPrivatePath
	}
	return owned, nil, nil
}

func privateClose(node adapter.Outbound) (failed bool) {
	defer func() {
		if recover() != nil {
			failed = true
		}
	}()
	closer, ok := node.(io.Closer)
	return ok && closer.Close() != nil
}
func (p *privatePath) Close() error {
	p.once.Do(func() {
		p.cancel()
		p.registry.mu.Lock()
		p.registry.closed = true
		clear(p.registry.nodes)
		p.registry.ordered = nil
		p.registry.mu.Unlock()
		for i := len(p.owned) - 1; i >= 0; i-- {
			if privateClose(p.owned[i]) {
				p.closeErr = errPrivatePath
			}
		}
		if p.closeErr == nil {
			p.owned = nil
		}
	})
	return p.closeErr
}
