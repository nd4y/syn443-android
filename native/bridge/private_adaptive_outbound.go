package bridge

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"sync"
	"unicode/utf8"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/log"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

const privateAdaptiveOutboundType = "syn443-adaptive"

// Internal compiled option shape only. No public engine parser, policy
// capability or Java API currently admits this outbound.
type privateAdaptiveOutboundOptions struct {
	Group string `json:"group"`
}

func (o *privateAdaptiveOutboundOptions) UnmarshalJSON(raw []byte) error {
	*o = privateAdaptiveOutboundOptions{}
	if len(raw) < 1 || len(raw) > 2048 || !utf8.Valid(raw) {
		return errPrivatePath
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	if token, e := d.Token(); e != nil || token != json.Delim('{') || !d.More() {
		return errPrivatePath
	}
	key, e := d.Token()
	if e != nil || key != "group" {
		return errPrivatePath
	}
	value, e := d.Token()
	group, ok := value.(string)
	if e != nil || !ok || !privateGroupID.MatchString(group) || d.More() {
		return errPrivatePath
	}
	if token, e := d.Token(); e != nil || token != json.Delim('}') {
		return errPrivatePath
	}
	if _, e := d.Token(); e != io.EOF {
		return errPrivatePath
	}
	o.Group = group
	return nil
}

type privateAdaptiveReferenceKey struct{}

// One reference belongs to one actual box registry/router/manager. Create it
// before box.New, then initialize its hub against that box before Start. The
// marker alone is insufficient: inherited markers in cloned/foreign runtimes
// never authorize borrowing an existing reference or its catalogue.
type privateAdaptiveReference struct {
	mu         sync.Mutex
	ctx        context.Context
	cancel     context.CancelFunc
	stopParent func() bool
	registry   service.Registry
	bindings   map[string]string
	nodes      map[string]*privateAdaptiveOutbound
	router     adapter.Router
	manager    *outbound.Manager
	hub        *privateAdaptiveHub
	closed     bool
}

type privateAdaptiveOutbound struct {
	outbound.Adapter
	ctx   context.Context
	ref   *privateAdaptiveReference
	group string
}

var _ adapter.Outbound = (*privateAdaptiveOutbound)(nil)
var _ adapter.Lifecycle = (*privateAdaptiveOutbound)(nil)

func registerPrivateAdaptiveOutbound(registry *outbound.Registry) {
	outbound.Register[privateAdaptiveOutboundOptions](registry, privateAdaptiveOutboundType, newPrivateAdaptiveOutbound)
}

func newPrivateAdaptiveReference(parent context.Context, bindings map[string]string) (*privateAdaptiveReference, error) {
	if parent == nil || parent.Err() != nil || parent.Value(privateAdaptiveReferenceKey{}) != nil ||
		service.RegistryFromContext(parent) == nil || service.FromContext[adapter.OutboundRegistry](parent) == nil ||
		service.FromContext[adapter.Router](parent) != nil || service.FromContext[adapter.OutboundManager](parent) != nil ||
		len(bindings) < 1 || len(bindings) > privateGroupLimit {
		return nil, errPrivatePath
	}
	owned, groups := make(map[string]string, len(bindings)), map[string]bool{}
	for tag, group := range bindings {
		if !privateGroupID.MatchString(tag) || !privateGroupID.MatchString(group) || groups[group] {
			return nil, errPrivatePath
		}
		owned[tag], groups[group] = group, true
	}
	// A dedicated registry prevents box.New from mutating the caller's service
	// registry. Actual box construction and the catalogue share only this clone.
	ctx, cancel := context.WithCancel(service.ExtendContext(parent))
	r := &privateAdaptiveReference{cancel: cancel, registry: service.RegistryFromContext(ctx), bindings: owned, nodes: map[string]*privateAdaptiveOutbound{}}
	r.ctx = context.WithValue(ctx, privateAdaptiveReferenceKey{}, r)
	stop := context.AfterFunc(parent, r.Close)
	r.mu.Lock()
	if r.closed {
		stop()
	} else {
		r.stopParent = stop
	}
	r.mu.Unlock()
	return r, nil
}

func newPrivateAdaptiveOutbound(ctx context.Context, router adapter.Router, _ log.ContextLogger, tag string, options privateAdaptiveOutboundOptions) (adapter.Outbound, error) {
	if ctx == nil || ctx.Err() != nil || router == nil || !privateGroupID.MatchString(tag) || !privateGroupID.MatchString(options.Group) {
		return nil, errPrivatePath
	}
	r, ok := ctx.Value(privateAdaptiveReferenceKey{}).(*privateAdaptiveReference)
	manager, actual := service.FromContext[adapter.OutboundManager](ctx).(*outbound.Manager)
	if !ok || r == nil || !actual || manager == nil || service.RegistryFromContext(ctx) != r.registry || service.FromContext[adapter.Router](ctx) != router {
		return nil, errPrivatePath
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.ctx.Err() != nil || r.hub != nil || r.bindings[tag] != options.Group || r.nodes[tag] != nil ||
		r.router != nil && r.router != router || r.manager != nil && r.manager != manager {
		return nil, errPrivatePath
	}
	r.router, r.manager = router, manager
	o := &privateAdaptiveOutbound{Adapter: outbound.NewAdapter(privateAdaptiveOutboundType, tag, []string{N.NetworkTCP}, nil), ctx: ctx, ref: r, group: options.Group}
	r.nodes[tag] = o
	return o, nil
}

// The caller retains a rejected hub. Ownership transfers only after exact
// context/catalogue/group/manager membership checks succeed. A bad attempt
// cannot replace a previously attached owner or retire an unrelated runtime.
func (r *privateAdaptiveReference) initialize(h *privateAdaptiveHub) bool {
	if r == nil || h == nil {
		return false
	}
	r.mu.Lock()
	if r.closed || r.ctx.Err() != nil || r.hub != nil || r.manager == nil || r.router == nil || len(r.nodes) != len(r.bindings) {
		r.mu.Unlock()
		return false
	}
	manager, router := r.manager, r.router
	nodes := make(map[string]*privateAdaptiveOutbound, len(r.nodes))
	for tag, node := range r.nodes {
		nodes[tag] = node
	}
	r.mu.Unlock()
	// Manager.Remove may call an outbound's Close while holding its own lock.
	// Never acquire a manager lock while holding ref.mu, including validation.
	for tag, node := range nodes {
		if current, ok := manager.Outbound(tag); !ok || current != node {
			return false
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.ctx.Err() != nil || r.hub != nil || r.router != router || r.manager != manager ||
		service.RegistryFromContext(r.ctx) != r.registry || service.FromContext[adapter.Router](r.ctx) != router ||
		service.FromContext[adapter.OutboundManager](r.ctx) != manager {
		return false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	c := h.catalogue
	if h.closed || c == nil || h.pool == nil || c.ctx.Err() != nil || c.ctx.Value(privateAdaptiveReferenceKey{}) != r ||
		service.RegistryFromContext(c.ctx) != r.registry || c.router != router ||
		service.FromContext[adapter.Router](c.ctx) != router || service.FromContext[adapter.OutboundManager](c.ctx) != manager ||
		len(h.groups) != len(r.bindings) {
		return false
	}
	p := h.pool
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.ctx.Err() != nil || !privateManagedLease(p.lease) || p.scope != h.scope ||
		c.ctx.Value(privateCatalogueKey{}) != c || p.ctx.Value(privateCatalogueKey{}) != c ||
		p.ctx.Value(privateAdaptiveReferenceKey{}) != r || service.RegistryFromContext(p.ctx) != r.registry ||
		service.FromContext[adapter.Router](p.ctx) != router || service.FromContext[adapter.OutboundManager](p.ctx) != manager {
		return false
	}
	for tag, group := range r.bindings {
		node, selector := r.nodes[tag], h.groups[group]
		if node == nil || nodes[tag] != node || node.ref != r || node.group != group || selector == nil || selector.pool != p || selector.group != group || !selector.validLocked() {
			return false
		}
	}
	r.hub = h
	return true
}

func (o *privateAdaptiveOutbound) currentHub() (*privateAdaptiveHub, error) {
	r := o.ref
	if r == nil || o.ctx == nil || o.ctx.Err() != nil || o.ctx.Value(privateAdaptiveReferenceKey{}) != r ||
		service.RegistryFromContext(o.ctx) != r.registry {
		return nil, errPrivatePath
	}
	r.mu.Lock()
	h, manager, router := r.hub, r.manager, r.router
	valid := !r.closed && r.ctx.Err() == nil && h != nil && manager != nil && router != nil && r.nodes[o.Tag()] == o && r.bindings[o.Tag()] == o.group
	r.mu.Unlock()
	if !valid || service.FromContext[adapter.Router](o.ctx) != router || service.FromContext[adapter.OutboundManager](o.ctx) != manager {
		return nil, errPrivatePath
	}
	current, ok := manager.Outbound(o.Tag())
	if !ok || current != o {
		return nil, errPrivatePath
	}
	// Close synchronously cancels r.ctx before releasing ref.mu, which also
	// revokes the hub/pool contexts before asynchronous cleanup can begin.
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.ctx.Err() != nil || r.hub != h || r.nodes[o.Tag()] != o {
		return nil, errPrivatePath
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed || h.pool == nil || h.catalogue == nil {
		return nil, errPrivatePath
	}
	p := h.pool
	p.mu.Lock()
	defer p.mu.Unlock()
	selector := h.groups[o.group]
	if p.closed || p.ctx.Err() != nil || !privateManagedLease(p.lease) || p.scope != h.scope ||
		p.ctx.Value(privateCatalogueKey{}) != h.catalogue || p.ctx.Value(privateAdaptiveReferenceKey{}) != r ||
		selector == nil || selector.pool != p || selector.group != o.group || !selector.validLocked() {
		return nil, errPrivatePath
	}
	return h, nil
}

func (o *privateAdaptiveOutbound) Start(adapter.StartStage) error {
	_, err := o.currentHub()
	return err
}

func (*privateAdaptiveOutbound) Network() []string { return []string{N.NetworkTCP} }

func (o *privateAdaptiveOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if ctx == nil || ctx.Err() != nil || network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, errPrivatePath
	}
	h, err := o.currentHub()
	if err != nil {
		return nil, errPrivatePath
	}
	return h.dialTCP(o.group, ctx, network, destination)
}

func (*privateAdaptiveOutbound) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errPrivatePath
}

func (o *privateAdaptiveOutbound) Close() error {
	if o.ref != nil {
		o.ref.Close()
	}
	return nil // Cleanup request only; the owner must separately require stopped().
}

func (r *privateAdaptiveReference) Close() {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return
	}
	r.closed = true
	r.cancel() // Revoke every group's authority before releasing the reference lock.
	if r.stopParent != nil {
		r.stopParent()
		r.stopParent = nil
	}
	h := r.hub
	r.mu.Unlock()
	if h != nil {
		h.Close()
	}
}

func (r *privateAdaptiveReference) stopped() bool {
	r.mu.Lock()
	closed, h := r.closed, r.hub
	r.mu.Unlock()
	return closed && (h == nil || h.stopped())
}

func (*privateAdaptiveReference) String() string     { return "PrivateAdaptiveReference([redacted])" }
func (r *privateAdaptiveReference) GoString() string { return r.String() }
func (*privateAdaptiveOutbound) String() string      { return "PrivateAdaptiveOutbound([redacted])" }
func (o *privateAdaptiveOutbound) GoString() string  { return o.String() }
