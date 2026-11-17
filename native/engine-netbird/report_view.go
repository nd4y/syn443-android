package netbird

import (
	"encoding/json"
	"io"
	"net/netip"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/netbirdio/netbird/client/embed"
)

const (
	ReportPageSize             = 16
	ReportRetainedLimit        = 1024
	ReportMaximumBytes         = 65536
	reportSectionBytes         = 24576
	reportMaximumTotal         = 2147483647
	reportMaximumInteger int64 = 9007199254740991
)

type reportSelection struct {
	Page    int
	Request string
}
type reportSelections struct{ Peers, Diagnostics reportSelection }
type reportView struct {
	Page     int    `json:"page"`
	PageSize int    `json:"page_size"`
	Total    int    `json:"total"`
	Retained int    `json:"retained"`
	Shown    int    `json:"shown"`
	Omitted  int    `json:"omitted"`
	Pages    int    `json:"pages"`
	Request  string `json:"request"`
}
type reportCoverage struct {
	Total    int `json:"total"`
	Planned  int `json:"planned"`
	Checked  int `json:"checked"`
	Unprobed int `json:"unprobed"`
	Omitted  int `json:"omitted"`
}
type connectionHeader struct {
	Active              bool      `json:"active"`
	Mode                string    `json:"mode"`
	Tag                 string    `json:"tag"`
	ProxyGroup          string    `json:"proxy_group"`
	SelectedProxy       string    `json:"selected_proxy"`
	Sampled             time.Time `json:"sampled_at"`
	ManagementConnected bool      `json:"management_connected"`
	SignalConnected     bool      `json:"signal_connected"`
	IP                  string    `json:"ip"`
	IPValid             bool      `json:"ip_valid"`
	FQDN                string    `json:"fqdn"`
	FQDNTruncated       bool      `json:"fqdn_truncated"`
	ConnectionUnknown   bool      `json:"connection_unknown"`
}
type reportPeer struct {
	IP            string    `json:"ip"`
	IPValid       bool      `json:"ip_valid"`
	FQDN          string    `json:"fqdn"`
	FQDNTruncated bool      `json:"fqdn_truncated"`
	State         string    `json:"state"`
	Relayed       bool      `json:"relayed"`
	LastHandshake time.Time `json:"last_handshake"`
	BytesTx       int64     `json:"bytes_tx"`
	BytesRx       int64     `json:"bytes_rx"`
}
type connectionReport struct {
	connectionHeader
	Peers           []reportPeer `json:"peers"`
	View            reportView   `json:"view"`
	MetadataUnknown bool         `json:"metadata_unknown"`
}
type diagnosticReport struct {
	Stale           bool           `json:"stale"`
	State           string         `json:"state"`
	Started         time.Time      `json:"started"`
	Finished        time.Time      `json:"finished"`
	Results         []ProbeResult  `json:"results"`
	View            reportView     `json:"view"`
	Coverage        reportCoverage `json:"coverage"`
	MetadataUnknown bool           `json:"metadata_unknown"`
}

func reportRequestID(raw string) bool {
	if len(raw) < 1 || len(raw) > 64 {
		return false
	}
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

// A page request changes only this captured outbound's local display selection.
// It never checks a lease, calls the SDK, probes, reconnects or creates a worker.
func RequestView(raw string) bool {
	if len(raw) == 0 || len(raw) > 1024 || !utf8.ValidString(raw) {
		return false
	}
	d := json.NewDecoder(strings.NewReader(raw))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return false
	}
	values := map[string]json.RawMessage{}
	for d.More() {
		token, err = d.Token()
		key, ok := token.(string)
		if err != nil || !ok || (key != "kind" && key != "section" && key != "page" && key != "request") {
			return false
		}
		if _, duplicate := values[key]; duplicate {
			return false
		}
		var value json.RawMessage
		if d.Decode(&value) != nil {
			return false
		}
		values[key] = value
	}
	if token, err = d.Token(); err != nil || token != json.Delim('}') || len(values) != 4 || d.Decode(new(any)) != io.EOF {
		return false
	}
	var kind, section, request string
	if json.Unmarshal(values["kind"], &kind) != nil || kind != "overlay-view" || json.Unmarshal(values["section"], &section) != nil ||
		(section != "peers" && section != "diagnostics") || json.Unmarshal(values["request"], &request) != nil || !reportRequestID(request) {
		return false
	}
	pageRaw := string(values["page"])
	if len(pageRaw) < 1 || len(pageRaw) > 2 || (len(pageRaw) > 1 && pageRaw[0] == '0') {
		return false
	}
	page := 0
	for i := 0; i < len(pageRaw); i++ {
		if pageRaw[i] < '0' || pageRaw[i] > '9' {
			return false
		}
		page = page*10 + int(pageRaw[i]-'0')
	}
	if page > 63 {
		return false
	}
	o := activeOutbound()
	if o == nil {
		return false
	}
	// Match Close's owner lock order. The view lock is never held across SDK I/O.
	o.mu.RLock()
	defer o.mu.RUnlock()
	if o.closed {
		return false
	}
	runtimePeer.RLock()
	defer runtimePeer.RUnlock()
	if runtimePeer.outbound != o {
		return false
	}
	o.viewMu.Lock()
	defer o.viewMu.Unlock()
	selection := reportSelection{page, strings.Clone(request)}
	if section == "peers" {
		o.views.Peers = selection
	} else {
		o.views.Diagnostics = selection
	}
	return true
}

func (o *Outbound) reportViews() reportSelections {
	o.viewMu.Lock()
	defer o.viewMu.Unlock()
	return o.views
}
func makeReportView(total int, selection reportSelection) (reportView, bool) {
	if total < 0 || total > reportMaximumTotal || selection.Page < 0 || selection.Page > 63 || (selection.Request != "" && !reportRequestID(selection.Request)) {
		return reportView{}, false
	}
	retained := min(total, ReportRetainedLimit)
	pages := (retained + ReportPageSize - 1) / ReportPageSize
	page := 0
	if pages > 0 {
		page = min(selection.Page, pages-1)
	}
	shown := min(ReportPageSize, retained-page*ReportPageSize)
	return reportView{page, ReportPageSize, total, retained, shown, total - retained, pages, strings.Clone(selection.Request)}, true
}
func (v reportView) valid(rows int) bool {
	want, ok := makeReportView(v.Total, reportSelection{v.Page, v.Request})
	return ok && v == want && rows == v.Shown
}

// Inspect at most96 input bytes/runes worth of output, and clone only that
// prefix. A small DTO must not retain a backing string from the full SDK roster.
func reportFQDN(raw string) (string, bool) { return reportText(raw, 96) }

func reportText(raw string, maximum int) (string, bool) {
	maximum = max(0, min(maximum, 512))
	var out strings.Builder
	out.Grow(maximum)
	at := 0
	changed := false
	for at < len(raw) && out.Len() < maximum {
		r, n := utf8.DecodeRuneInString(raw[at:])
		if r == utf8.RuneError && n == 1 {
			changed = true
		}
		if r < 32 || r >= 127 && r <= 159 {
			r = utf8.RuneError
			changed = true
		}
		if out.Len()+utf8.RuneLen(r) > maximum {
			break
		}
		out.WriteRune(r)
		at += n
	}
	return out.String(), changed || at < len(raw)
}
func reportIP(raw string) (string, bool) {
	if len(raw) < 1 || len(raw) > 64 {
		return "", false
	}
	ip, err := netip.ParseAddr(raw)
	if err != nil || ip.Zone() != "" {
		return "", false
	}
	return strings.Clone(raw), true // Display and target stay byte-exact, including mapped IPv6.
}
func reportNumber(value int64) int64 {
	if value < 0 {
		return 0
	}
	return min(value, reportMaximumInteger)
}
func reportTime(value time.Time) time.Time {
	if value.IsZero() || value.Year() < 1970 || value.Year() > 9999 || value.UnixMilli() < 0 || value.UnixMilli() > reportMaximumInteger {
		return time.Time{}
	}
	return value.UTC()
}
func reportCode(raw string) string {
	if len(raw) > 64 {
		return ""
	}
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.' || c == ':') {
			return ""
		}
	}
	return strings.Clone(raw)
}
func reportMode(raw string) string {
	if raw == "direct" || raw == "vless" {
		return strings.Clone(raw)
	}
	return "unknown"
}
func reportPeerState(raw string) string {
	switch raw {
	case "connected", "connecting", "disconnected":
		return strings.Clone(raw)
	}
	return "unknown"
}
func reportResultState(raw string) string {
	switch raw {
	case "queued", "checking", "reply", "no_reply", "cancelled", "invalid_target":
		return strings.Clone(raw)
	}
	return "unknown"
}
func reportJobState(raw string) string {
	switch raw {
	case "preparing", "running", "completed", "partial", "cancelled", "unavailable", "no_peers", "stale":
		return strings.Clone(raw)
	}
	return "unavailable"
}
func reportLabel(raw string) (string, bool) {
	v, changed := reportFQDN(raw)
	if changed {
		return "", false
	}
	return v, true
}

func projectConnection(o *Outbound, snapshot embed.ConnectionSnapshot, selection reportSelection) connectionReport {
	view, ok := makeReportView(len(snapshot.Peers), selection)
	header := connectionHeader{Active: true, Mode: reportMode(o.options.ConnectionMode), Sampled: reportTime(time.Now()), ManagementConnected: snapshot.ManagementConnected, SignalConnected: snapshot.SignalConnected}
	header.IP, header.IPValid = reportIP(snapshot.IP)
	header.FQDN, header.FQDNTruncated = reportFQDN(snapshot.FQDN)
	unknown := !ok
	var good bool
	header.Tag, good = reportLabel(o.Tag())
	unknown = unknown || !good
	header.ProxyGroup, good = reportLabel(o.options.Detour)
	unknown = unknown || !good
	selected := o.options.Detour
	selected, good = reportLabel(selected)
	unknown = unknown || !good
	if header.Mode == "direct" {
		selected = ""
	} else if o.manager != nil {
		seen := map[string]bool{}
		for selected != "" && !seen[selected] && len(seen) < 64 {
			seen[selected] = true
			out, found := o.manager.Outbound(selected)
			if !found {
				break
			}
			group, isGroup := out.(interface{ Now() string })
			if !isGroup {
				break
			}
			selected, good = reportLabel(group.Now())
			if !good {
				unknown = true
				break
			}
		}
	}
	header.SelectedProxy, good = reportLabel(selected)
	unknown = unknown || !good
	if !ok {
		view, _ = makeReportView(0, selection)
	}
	result := connectionReport{connectionHeader: header, Peers: make([]reportPeer, 0, view.Shown), View: view, MetadataUnknown: unknown}
	if !ok {
		return result
	}
	for i := view.Page * ReportPageSize; i < view.Page*ReportPageSize+view.Shown; i++ {
		p := snapshot.Peers[i]
		ip, valid := reportIP(p.IP)
		fqdn, truncated := reportFQDN(p.FQDN)
		result.Peers = append(result.Peers, reportPeer{ip, valid, fqdn, truncated, reportPeerState(p.State), p.Relayed, reportTime(p.LastHandshake), reportNumber(p.BytesTx), reportNumber(p.BytesRx)})
	}
	return result
}

func (o *Outbound) diagnosticReportLocked() diagnosticReport {
	selection := o.reportViews().Diagnostics
	if o.job.unknown {
		r := unknownDiagnostics(selection, o.job.Stale)
		r.State = reportJobState(o.job.State)
		if r.State == "completed" {
			r.State = "unavailable"
		}
		r.Started = reportTime(o.job.Started)
		r.Finished = reportTime(o.job.Finished)
		return r
	}
	view, ok := makeReportView(o.job.total, selection)
	if len(o.job.Results) > ReportRetainedLimit || !ok || len(o.job.Results) != view.Retained || o.job.planned < 0 || o.job.planned > view.Retained {
		return unknownDiagnostics(selection, o.job.Stale)
	}
	checked := 0
	for _, r := range o.job.Results {
		_, valid := reportIP(r.IP)
		if valid != r.IPValid || (!valid && r.State != "invalid_target" && r.State != "unknown") || r.State != reportResultState(r.State) {
			return unknownDiagnostics(selection, o.job.Stale)
		}
		if r.State == "reply" || r.State == "no_reply" {
			checked++
		}
	}
	if checked > o.job.planned {
		return unknownDiagnostics(selection, o.job.Stale)
	}
	coverage := reportCoverage{view.Total, o.job.planned, checked, view.Total - checked, view.Omitted}
	state := reportJobState(o.job.State)
	if state == "completed" && (coverage.Total == 0 || coverage.Checked != coverage.Total || coverage.Planned != coverage.Total || coverage.Omitted != 0) {
		state = "partial"
	}
	result := diagnosticReport{Stale: o.job.Stale, State: state, Started: reportTime(o.job.Started), Finished: reportTime(o.job.Finished), Results: make([]ProbeResult, 0, view.Shown), View: view, Coverage: coverage}
	for i := view.Page * ReportPageSize; i < view.Page*ReportPageSize+view.Shown; i++ {
		r := o.job.Results[i]
		r.IP, r.IPValid = reportIP(r.IP)
		fqdn, truncated := reportFQDN(r.FQDN)
		r.FQDN = fqdn
		r.FQDNTruncated = r.FQDNTruncated || truncated
		r.State = reportResultState(r.State)
		r.RTTMillis = min(reportNumber(r.RTTMillis), 12000)
		result.Results = append(result.Results, r)
	}
	return result
}
func unknownConnection(header connectionHeader, selection reportSelection) connectionReport {
	view, _ := makeReportView(0, selection)
	return connectionReport{connectionHeader: header, Peers: []reportPeer{}, View: view, MetadataUnknown: true}
}
func unknownDiagnostics(selection reportSelection, stale bool) diagnosticReport {
	view, _ := makeReportView(0, selection)
	return diagnosticReport{Stale: stale, State: "unavailable", Results: []ProbeResult{}, View: view, MetadataUnknown: true}
}
func unavailableDiagnosticReport(o *Outbound, state string) string {
	selection := reportSelection{}
	if o != nil {
		selection = o.reportViews().Diagnostics
	}
	r := unknownDiagnostics(selection, false)
	r.State = reportJobState(state)
	return marshal(r)
}

// Caches are produced locally, but validate bounds before decoding so a broken
// producer never turns the heartbeat into a whole-roster marshal or raw splice.
func decodeReport(raw string, value any) bool {
	if len(raw) == 0 || len(raw) > reportSectionBytes || !utf8.ValidString(raw) {
		return false
	}
	d := json.NewDecoder(strings.NewReader(raw))
	d.UseNumber()
	tokens := 0
	peer := false
	switch value.(type) {
	case *connectionReport:
		peer = true
	case *diagnosticReport:
	default:
		return false
	}
	var walk func(int, string) bool
	walk = func(depth int, path string) bool {
		if depth > 8 {
			return false
		}
		tokens++
		if tokens > 1024 {
			return false
		}
		t, err := d.Token()
		if err != nil || t == nil {
			return false
		}
		if delim, ok := t.(json.Delim); ok {
			switch delim {
			case '{':
				seen := map[string]bool{}
				for d.More() {
					k, e := d.Token()
					key, yes := k.(string)
					if e != nil || !yes || seen[key] || len(seen) >= 32 {
						return false
					}
					seen[key] = true
					child := key
					if path != "" {
						child = path + "." + key
					}
					if !walk(depth+1, child) {
						return false
					}
				}
				end, e := d.Token()
				return e == nil && end == json.Delim('}') && reportObjectKeys(path, peer, seen)
			case '[':
				n := 0
				for d.More() {
					n++
					if n > ReportPageSize || !walk(depth+1, path+"[]") {
						return false
					}
				}
				end, e := d.Token()
				return e == nil && end == json.Delim(']')
			default:
				return false
			}
		}
		return true
	}
	if !walk(0, "") || d.Decode(new(any)) != io.EOF {
		return false
	}
	d = json.NewDecoder(strings.NewReader(raw))
	d.DisallowUnknownFields()
	return d.Decode(value) == nil && d.Decode(new(any)) == io.EOF
}

func reportObjectKeys(path string, peer bool, seen map[string]bool) bool {
	var required, optional []string
	switch path {
	case "":
		if peer {
			required = []string{"active", "mode", "tag", "proxy_group", "selected_proxy", "sampled_at", "management_connected", "signal_connected", "ip", "ip_valid", "fqdn", "fqdn_truncated", "connection_unknown", "peers", "view", "metadata_unknown"}
		} else {
			required = []string{"stale", "state", "started", "finished", "results", "view", "coverage", "metadata_unknown"}
		}
	case "view":
		required = []string{"page", "page_size", "total", "retained", "shown", "omitted", "pages", "request"}
	case "coverage":
		required = []string{"total", "planned", "checked", "unprobed", "omitted"}
	case "peers[]":
		required = []string{"ip", "ip_valid", "fqdn", "fqdn_truncated", "state", "relayed", "last_handshake", "bytes_tx", "bytes_rx"}
	case "results[]":
		required = []string{"ip", "fqdn", "state", "ip_valid", "fqdn_truncated"}
		optional = []string{"rtt_ms"}
	default:
		return false
	}
	for _, name := range required {
		if !seen[name] {
			return false
		}
	}
	if len(seen) < len(required) || len(seen) > len(required)+len(optional) {
		return false
	}
	for name := range seen {
		known := false
		for _, key := range required {
			known = known || key == name
		}
		for _, key := range optional {
			known = known || key == name
		}
		if !known {
			return false
		}
	}
	return true
}
func validConnectionReport(r connectionReport) bool {
	if !r.View.valid(len(r.Peers)) || r.Peers == nil || r.Mode != reportMode(r.Mode) || len(r.FQDN) > 96 || !utf8.ValidString(r.FQDN) || len(r.Tag) > 96 || len(r.ProxyGroup) > 96 || len(r.SelectedProxy) > 96 || !r.Sampled.Equal(reportTime(r.Sampled)) {
		return false
	}
	if ip, valid := reportIP(r.IP); ip != r.IP || valid != r.IPValid {
		return false
	}
	for _, p := range r.Peers {
		if len(p.FQDN) > 96 || !utf8.ValidString(p.FQDN) || p.State != reportPeerState(p.State) || p.BytesTx != reportNumber(p.BytesTx) || p.BytesRx != reportNumber(p.BytesRx) || !p.LastHandshake.Equal(reportTime(p.LastHandshake)) {
			return false
		}
		if ip, valid := reportIP(p.IP); ip != p.IP || valid != p.IPValid {
			return false
		}
	}
	return true
}
func validDiagnosticReport(r diagnosticReport) bool {
	if !r.View.valid(len(r.Results)) || r.Results == nil || r.State != reportJobState(r.State) || !r.Started.Equal(reportTime(r.Started)) || !r.Finished.Equal(reportTime(r.Finished)) {
		return false
	}
	c := r.Coverage
	if c.Total != r.View.Total || c.Omitted != r.View.Omitted || c.Planned < 0 || c.Planned > r.View.Retained || c.Checked < 0 || c.Checked > c.Planned || c.Unprobed != c.Total-c.Checked {
		return false
	}
	if r.State == "completed" && (c.Total == 0 || c.Checked != c.Total || c.Planned != c.Total || c.Unprobed != 0 || c.Omitted != 0) {
		return false
	}
	for _, p := range r.Results {
		if len(p.FQDN) > 96 || !utf8.ValidString(p.FQDN) || p.State != reportResultState(p.State) || p.RTTMillis < 0 || p.RTTMillis > 12000 {
			return false
		}
		if ip, valid := reportIP(p.IP); ip != p.IP || valid != p.IPValid {
			return false
		}
		if !p.IPValid && p.State != "invalid_target" && p.State != "unknown" {
			return false
		}
	}
	return true
}

func boundedHeader(h connectionHeader) connectionHeader {
	h.Mode = reportMode(h.Mode)
	h.Sampled = reportTime(h.Sampled)
	h.IP, h.IPValid = reportIP(h.IP)
	fqdn, truncated := reportFQDN(h.FQDN)
	h.FQDN = fqdn
	h.FQDNTruncated = h.FQDNTruncated || truncated
	var ok bool
	h.Tag, ok = reportLabel(h.Tag)
	h.ConnectionUnknown = h.ConnectionUnknown || !ok
	h.ProxyGroup, ok = reportLabel(h.ProxyGroup)
	h.ConnectionUnknown = h.ConnectionUnknown || !ok
	h.SelectedProxy, ok = reportLabel(h.SelectedProxy)
	h.ConnectionUnknown = h.ConnectionUnknown || !ok
	return h
}
func (d *Deferred) boundedHeader() connectionHeader {
	if h, ok := d.header.Load().(connectionHeader); ok {
		return boundedHeader(h)
	}
	return connectionHeader{Mode: reportMode(d.options.ConnectionMode), ConnectionUnknown: true}
}
func boundedModule(s moduleState) moduleState {
	switch s.Phase {
	case "Configured", "Starting", "Recovering", "Started", "NeedsAction", "Stopping", "Off", "Unknown":
	default:
		s.Phase = "Unknown"
	}
	s.Mode = reportMode(s.Mode)
	s.Reason = reportCode(s.Reason)
	// The startup path already redacts this authorized local error text. Keep
	// useful words and punctuation; treating it as an enum erased real errors.
	var changed bool
	s.Failure, changed = reportText(s.Failure, 512)
	s.FailureTruncated = s.FailureTruncated || changed
	s.Retry.Attempt = max(0, min(s.Retry.Attempt, 30))
	s.Retry.Next = reportNumber(s.Retry.Next)
	s.Sampled = reportNumber(s.Sampled)
	return s
}
func boundedStartupCodes(raw []string) []string {
	result := make([]string, 0, min(len(raw), 16))
	for i := 0; i < min(len(raw), 16); i++ {
		if code := reportCode(raw[i]); code != "" {
			result = append(result, code)
		}
	}
	return result
}

// These samplers belong to one captured Outbound. A replacement must not inherit
// its page requests, cached diagnostics or a late SDK result.
func (d *Deferred) reportOwnerCurrent(owner *Outbound) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.current == owner
}
func (d *Deferred) resetReportViewsLocked() {
	header := d.boundedHeader()
	header.ConnectionUnknown = true
	d.header.Store(header)
	d.report.Store(marshal(unknownConnection(header, reportSelection{})))
	d.diagnostics.Store(marshal(unknownDiagnostics(reportSelection{}, true)))
}
func (d *Deferred) publishConnectionReport(owner *Outbound, raw string) bool {
	var owned connectionReport
	valid := decodeReport(raw, &owned) && validConnectionReport(owned)
	if !valid {
		raw = marshal(unknownConnection(d.boundedHeader(), owner.reportViews().Peers))
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.current != owner || d.ctx.Err() != nil {
		return false
	}
	owner.mu.RLock()
	defer owner.mu.RUnlock()
	if owner.closed {
		return false
	}
	if valid && !owned.ConnectionUnknown {
		d.header.Store(owned.connectionHeader)
	}
	d.report.Store(raw)
	return true
}
