package main

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/gopacket/layers"
	"github.com/mattn/go-runewidth"
)

type view int

const (
	viewFlows view = iota
	viewHosts
	viewPackets
	viewStats
	viewNotices
	viewMap
	viewCount
)

func (v view) String() string {
	return [...]string{"Flows", "Hosts", "Packets", "Stats", "Notices", "Map"}[v]
}

type sortKey int

const (
	sortLast sortKey = iota
	sortBytes
	sortPkts
	sortAddr
	sortCount
)

func (s sortKey) String() string {
	return [...]string{"last seen", "bytes", "packets", "address"}[s]
}

type dirFilter int

const (
	dirAll dirFilter = iota
	dirOnlyIn
	dirOnlyOut
	dirOnlyOther
	dirFilterCount
)

func (d dirFilter) String() string {
	return [...]string{"all", "inbound", "outbound", "other (bcast/mcast/LAN)"}[d]
}

func (d dirFilter) match(dir Direction) bool {
	switch d {
	case dirOnlyIn:
		return dir == DirIn
	case dirOnlyOut:
		return dir == DirOut || dir == DirLocal
	case dirOnlyOther:
		return dir == DirOther
	}
	return true
}

type tickMsg time.Time
type captureErrMsg struct{ err error }

var (
	stTitle    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("15")).Background(lipgloss.Color("25")).Padding(0, 1)
	stHeader   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("0")).Background(lipgloss.Color("250"))
	stTabOn    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("15")).Background(lipgloss.Color("33")).Padding(0, 1)
	stTabOff   = lipgloss.NewStyle().Foreground(lipgloss.Color("250")).Padding(0, 1)
	stSelected = lipgloss.NewStyle().Reverse(true)
	stDim      = lipgloss.NewStyle().Foreground(lipgloss.Color("245"))
	stKey      = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("214"))
	stErr      = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("196"))
	stWarn     = lipgloss.NewStyle().Foreground(lipgloss.Color("208"))
	stIn       = lipgloss.NewStyle().Foreground(lipgloss.Color("82"))
	stOut      = lipgloss.NewStyle().Foreground(lipgloss.Color("75"))
	stOther    = lipgloss.NewStyle().Foreground(lipgloss.Color("220"))
	stPaused   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("0")).Background(lipgloss.Color("214")).Padding(0, 1)
	stBar      = lipgloss.NewStyle().Foreground(lipgloss.Color("39"))
	stBarOut   = lipgloss.NewStyle().Foreground(lipgloss.Color("75"))
	stSection  = lipgloss.NewStyle().Bold(true).Underline(true)
)

// overlay is a full-screen scrollable text page (decode tree, timeline, help,
// or a streamed Claude explanation).
type overlay struct {
	title string
	lines []string
	off   int

	ai       bool
	aiID     int
	aiCh     <-chan aiMsg
	aiCancel context.CancelFunc
	aiText   strings.Builder
	aiPrompt string
	aiDone   bool
	aiErr    error
	aiLabel  string
	showSent bool
}

type model struct {
	agg      *Agg
	res      *Resolver
	cap      *Capture
	errs     <-chan error
	iface    string
	filter   string
	pcapOut  string
	linkType layers.LinkType
	explain  Asker
	aiSeq    int

	topo      *Topo
	tv        TopoView
	mapOff    int
	phase     int
	animOn    bool
	autoTrace bool // start a route trace the first time the map opens
	traced    bool

	w, h      int
	view      view
	cursor    int
	offset    int
	sort      sortKey
	dir       dirFilter
	search    string
	searching bool
	paused    bool
	detail    bool
	err       error
	overlay   *overlay

	snap    Snapshot
	flows   []Flow
	hosts   []Host
	pkts    []Packet
	notices []Notice

	seenCountries map[string]bool
	prevStats     Stats
	prevT         time.Time
	pps, bps      float64
}

func newModel(agg *Agg, res *Resolver, cap *Capture, errs <-chan error, iface, filter string) model {
	m := model{agg: agg, res: res, cap: cap, errs: errs, iface: iface, filter: filter, w: 80, h: 24,
		pcapOut: cap.WriteTo, linkType: cap.LinkType(), seenCountries: map[string]bool{}, topo: NewTopo("1.1.1.1")}
	return m
}

func tick() tea.Cmd {
	return tea.Tick(500*time.Millisecond, func(t time.Time) tea.Msg { return tickMsg(t) })
}

func (m model) waitErr() tea.Cmd {
	return func() tea.Msg {
		err, ok := <-m.errs
		if !ok || err == nil {
			return nil
		}
		return captureErrMsg{err}
	}
}

func (m model) Init() tea.Cmd {
	return tea.Batch(tick(), m.waitErr())
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.w, m.h = msg.Width, msg.Height
		m.rebuild()
		m.refreshAI()
	case tickMsg:
		if !m.paused {
			m.agg.SetDropped(m.cap.Dropped())
			m.snap = m.agg.Snapshot()
			m.updateRates(time.Time(msg))
			m.noticeCountries()
			if m.view == viewMap {
				m.tv = m.topo.View(m.iface)
			}
			m.rebuild()
		}
		return m, tick()
	case animMsg:
		if m.view != viewMap {
			m.animOn = false
			return m, nil
		}
		m.phase++
		return m, animTick()
	case captureErrMsg:
		m.err = msg.err
	case aiMsg:
		o := m.overlay
		if o == nil || !o.ai || o.aiID != msg.id {
			return m, nil // stale chunk from a closed panel
		}
		o.aiText.WriteString(msg.text)
		if msg.done {
			o.aiDone, o.aiErr = true, msg.err
		}
		m.refreshAI()
		if msg.done {
			return m, nil
		}
		return m, waitAI(o.aiCh)
	case tea.KeyMsg:
		return m.handleKey(msg)
	}
	return m, nil
}

func (m *model) updateRates(now time.Time) {
	s := m.snap.Stats
	dt := now.Sub(m.prevT).Seconds()
	if m.prevT.IsZero() || s.Packets < m.prevStats.Packets { // first sample, or counters were reset
		m.prevStats = s
		m.prevT = now
		return
	}
	if dt > 0 {
		pps := float64(s.Packets-m.prevStats.Packets) / dt
		bps := float64(s.Bytes-m.prevStats.Bytes) * 8 / dt
		m.pps = 0.6*m.pps + 0.4*pps
		m.bps = 0.6*m.bps + 0.4*bps
	}
	m.prevStats = s
	m.prevT = now
}

// noticeCountries raises a notice the first time traffic involves a new country.
func (m *model) noticeCountries() {
	for _, h := range m.snap.Hosts {
		hi := m.res.Get(h.IP)
		if hi.Country == "" || m.seenCountries[hi.Country] {
			continue
		}
		m.seenCountries[hi.Country] = true
		m.agg.AddNotice("country", fmt.Sprintf("first traffic involving %s: %s (%s)", hi.Country, h.IP, firstNonEmpty(hi.Org, hi.ASN, "unknown org")))
	}
}

func (m model) handleKey(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	if k.Type == tea.KeyCtrlC {
		return m, tea.Quit
	}
	if m.overlay != nil {
		return m.handleOverlayKey(k)
	}
	if m.searching {
		switch k.Type {
		case tea.KeyEsc:
			m.searching, m.search = false, ""
		case tea.KeyEnter:
			m.searching = false
		case tea.KeyBackspace:
			if r := []rune(m.search); len(r) > 0 {
				m.search = string(r[:len(r)-1])
			}
		case tea.KeyRunes, tea.KeySpace:
			m.search += string(k.Runes)
		}
		m.cursor, m.offset = 0, 0
		m.rebuild()
		return m, nil
	}
	if m.view == viewMap {
		switch k.String() {
		case "j", "down":
			m.mapOff++
			return m, nil
		case "k", "up":
			m.mapOff = max(0, m.mapOff-1)
			return m, nil
		case "pgdown", "ctrl+d":
			m.mapOff += m.rowsAvail()
			return m, nil
		case "pgup", "ctrl+u":
			m.mapOff = max(0, m.mapOff-m.rowsAvail())
			return m, nil
		case "g", "home":
			m.mapOff = 0
			return m, nil
		case "G", "end":
			m.mapOff = len(m.mapLines())
			return m, nil
		}
	}
	switch k.String() {
	case "q":
		return m, tea.Quit
	case "tab", "right", "l":
		m.setView((m.view + 1) % viewCount)
	case "shift+tab", "left", "h":
		m.setView((m.view + viewCount - 1) % viewCount)
	case "1", "2", "3", "4", "5", "6":
		m.setView(view(k.String()[0] - '1'))
	case "u":
		if m.view == viewMap {
			m.startTrace()
		}
	case "j", "down":
		m.cursor++
	case "k", "up":
		m.cursor--
	case "pgdown", "ctrl+d":
		m.cursor += m.rowsAvail()
	case "pgup", "ctrl+u":
		m.cursor -= m.rowsAvail()
	case "g", "home":
		m.cursor = 0
	case "G", "end":
		m.cursor = 1 << 30
	case "s":
		m.sort = (m.sort + 1) % sortCount
	case "d":
		m.dir = (m.dir + 1) % dirFilterCount
		m.cursor, m.offset = 0, 0
	case "i":
		if m.dir == dirOnlyIn {
			m.dir = dirAll
		} else {
			m.dir = dirOnlyIn
		}
		m.cursor, m.offset = 0, 0
	case "/":
		m.searching = true
	case "esc":
		if m.search != "" {
			m.search = ""
		} else {
			m.detail = false
		}
	case "enter":
		if m.view == viewPackets {
			m.openDecode()
		} else {
			m.detail = !m.detail
		}
	case "t":
		if m.view == viewFlows {
			m.openTimeline()
		}
	case "?":
		m.overlay = &overlay{title: "Help", lines: helpLines()}
	case "a":
		return m.askClaude()
	case "p", " ":
		m.paused = !m.paused
	case "r":
		m.agg.Reset()
		m.snap = m.agg.Snapshot()
		m.seenCountries = map[string]bool{}
		m.cursor, m.offset = 0, 0
	}
	m.rebuild()
	if m.view == viewMap && !m.animOn {
		m.animOn = true
		return m, animTick()
	}
	return m, nil
}

func (m *model) setView(v view) {
	m.view = v
	m.cursor, m.offset = 0, 0
	if v == viewMap {
		m.tv = m.topo.View(m.iface)
		if m.autoTrace && !m.traced {
			m.startTrace()
		}
	}
}

func (m *model) startTrace() {
	m.traced = true
	res := m.res
	m.topo.Trace(func(ip netip.Addr) { res.Enqueue(ip) })
	m.tv = m.topo.View(m.iface)
}

func (m model) handleOverlayKey(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	o := m.overlay
	page := m.h - 3
	if page < 1 {
		page = 1
	}
	switch k.String() {
	case "q", "esc", "enter", "?", "t":
		if o.aiCancel != nil {
			o.aiCancel()
		}
		m.overlay = nil
	case "v":
		if o.ai && o.aiPrompt != "" {
			o.showSent = !o.showSent
			o.off = 0
			m.refreshAI()
		}
	case "j", "down":
		o.off++
	case "k", "up":
		o.off--
	case "pgdown", "ctrl+d", " ":
		o.off += page
	case "pgup", "ctrl+u":
		o.off -= page
	case "g", "home":
		o.off = 0
	case "G", "end":
		o.off = len(o.lines)
	}
	if m.overlay != nil {
		if o.off > len(o.lines)-page {
			o.off = len(o.lines) - page
		}
		if o.off < 0 {
			o.off = 0
		}
	}
	return m, nil
}

func (m *model) openDecode() {
	if m.cursor >= len(m.pkts) {
		return
	}
	p := m.pkts[m.cursor]
	title := fmt.Sprintf("Packet %s  %s %s → %s  %d bytes", p.Time.Format("15:04:05.000"), p.Proto, addrPort(p.Src, p.SPort), addrPort(p.Dst, p.DPort), p.Len)
	m.overlay = &overlay{title: title, lines: decodeTree(p.Raw, m.linkType)}
}

func (m *model) openTimeline() {
	if m.cursor >= len(m.flows) {
		return
	}
	f := m.flows[m.cursor]
	m.overlay = &overlay{title: "Timeline " + flowTitle(f), lines: timelineLines(f, m.res.Get(f.Key.Remote))}
}

// rebuild applies direction filter, search and sort to the snapshot.
func (m *model) rebuild() {
	q := strings.ToLower(strings.TrimSpace(m.search))

	m.flows = m.flows[:0]
	for _, f := range m.snap.Flows {
		if !m.dir.match(f.Dir) {
			continue
		}
		if q != "" && !m.flowMatches(f, q) {
			continue
		}
		m.flows = append(m.flows, f)
	}
	sort.SliceStable(m.flows, func(i, j int) bool { return m.lessFlow(&m.flows[i], &m.flows[j]) })

	m.hosts = m.hosts[:0]
	for _, h := range m.snap.Hosts {
		switch m.dir {
		case dirOnlyIn:
			if h.PktsIn == 0 {
				continue
			}
		case dirOnlyOut:
			if h.PktsOut == 0 {
				continue
			}
		}
		if q != "" && !m.hostMatches(h, q) {
			continue
		}
		m.hosts = append(m.hosts, h)
	}
	sort.SliceStable(m.hosts, func(i, j int) bool { return m.lessHost(&m.hosts[i], &m.hosts[j]) })

	m.pkts = m.pkts[:0]
	for _, p := range m.snap.Packets {
		if !m.dir.match(p.Dir) {
			continue
		}
		if q != "" && !m.pktMatches(p, q) {
			continue
		}
		m.pkts = append(m.pkts, p)
	}

	m.notices = m.notices[:0]
	for _, n := range m.snap.Notices {
		if q != "" && !strings.Contains(strings.ToLower(n.Kind+" "+n.Text), q) {
			continue
		}
		m.notices = append(m.notices, n)
	}

	n := m.rowCount()
	if m.cursor >= n {
		m.cursor = n - 1
	}
	if m.cursor < 0 {
		m.cursor = 0
	}
	avail := m.rowsAvail()
	if m.cursor < m.offset {
		m.offset = m.cursor
	}
	if m.cursor >= m.offset+avail {
		m.offset = m.cursor - avail + 1
	}
	if m.offset < 0 {
		m.offset = 0
	}
}

func (m *model) rowCount() int {
	switch m.view {
	case viewFlows:
		return len(m.flows)
	case viewHosts:
		return len(m.hosts)
	case viewPackets:
		return len(m.pkts)
	case viewNotices:
		return len(m.notices)
	}
	return 0
}

func (m *model) lessFlow(a, b *Flow) bool {
	switch m.sort {
	case sortBytes:
		if a.Bytes() != b.Bytes() {
			return a.Bytes() > b.Bytes()
		}
	case sortPkts:
		if a.Pkts() != b.Pkts() {
			return a.Pkts() > b.Pkts()
		}
	case sortAddr:
		if c := a.Key.Remote.Compare(b.Key.Remote); c != 0 {
			return c < 0
		}
		return a.Key.RemotePort < b.Key.RemotePort
	}
	if !a.Last.Equal(b.Last) {
		return a.Last.After(b.Last)
	}
	return a.Bytes() > b.Bytes()
}

func (m *model) lessHost(a, b *Host) bool {
	switch m.sort {
	case sortBytes:
		if a.Bytes() != b.Bytes() {
			return a.Bytes() > b.Bytes()
		}
	case sortPkts:
		if a.Pkts() != b.Pkts() {
			return a.Pkts() > b.Pkts()
		}
	case sortAddr:
		return a.IP.Compare(b.IP) < 0
	}
	if !a.Last.Equal(b.Last) {
		return a.Last.After(b.Last)
	}
	return a.Bytes() > b.Bytes()
}

func (m *model) hostText(ip netip.Addr) string {
	hi := m.res.Get(ip)
	return strings.ToLower(ip.String() + " " + hi.Name + " " + hi.Origin() + " " + hi.Kind)
}

func (m *model) flowMatches(f Flow, q string) bool {
	s := m.hostText(f.Key.Remote) + " " + strings.ToLower(f.Key.Proto+" "+f.Name+" "+f.Proc) + fmt.Sprintf(" %d %d %s", f.Key.RemotePort, f.Key.LocalPort, f.Dir)
	return strings.Contains(s, q)
}

func (m *model) hostMatches(h Host, q string) bool {
	s := m.hostText(h.IP)
	for p := range h.Ports {
		s += fmt.Sprintf(" %d", p)
	}
	for p := range h.Protos {
		s += " " + strings.ToLower(p)
	}
	for n := range h.Names {
		s += " " + strings.ToLower(n)
	}
	for n := range h.Procs {
		s += " " + strings.ToLower(n)
	}
	return strings.Contains(s, q)
}

func (m *model) pktMatches(p Packet, q string) bool {
	s := strings.ToLower(fmt.Sprintf("%s %s %d %d %s %s %s %s", p.Src, p.Dst, p.SPort, p.DPort, p.Proto, p.Info, p.Dir, p.Name))
	return strings.Contains(s, q)
}

// ---- rendering ----

const (
	headerLines = 3
	footerLines = 1
	detailLines = 8
)

// showDetail is true when the detail panel is on, applies to this view, and fits.
func (m *model) showDetail() bool {
	if m.view != viewFlows && m.view != viewHosts {
		return false
	}
	return m.detail && m.h >= headerLines+1+footerLines+detailLines+2
}

func (m *model) rowsAvail() int {
	n := m.h - headerLines - 1 - footerLines
	if m.showDetail() {
		n -= detailLines
	}
	if n < 1 {
		n = 1
	}
	return n
}

// col describes a table column. prio 0 columns are always shown; the others
// are dropped highest-prio first when the terminal is too narrow.
type col struct {
	name  string
	w     int
	right bool
	prio  int
}

func (m model) View() string {
	if m.overlay != nil {
		return m.renderOverlay()
	}
	var b strings.Builder
	b.WriteString(m.renderHeader())
	b.WriteByte('\n')
	switch m.view {
	case viewFlows:
		m.renderFlows(&b)
	case viewHosts:
		m.renderHosts(&b)
	case viewPackets:
		m.renderPackets(&b)
	case viewStats:
		m.renderStats(&b)
	case viewNotices:
		m.renderNotices(&b)
	case viewMap:
		m.renderMap(&b)
	}
	if m.showDetail() {
		b.WriteString(m.renderDetail())
	}
	b.WriteString(m.renderFooter())
	return b.String()
}

func (m model) renderHeader() string {
	s := m.snap.Stats
	up := time.Since(s.Start).Truncate(time.Second)
	line1 := fmt.Sprintf("%s  iface %s", stTitle.Render("ears"), stKey.Render(m.iface))
	if m.filter != "" {
		line1 += "  filter " + stKey.Render(m.filter)
	}
	if m.pcapOut != "" {
		line1 += "  writing " + stKey.Render(m.pcapOut)
	}
	line1 += fmt.Sprintf("  up %s", up)
	if m.paused {
		line1 += "  " + stPaused.Render("PAUSED")
	}
	if m.err != nil {
		line1 += "  " + stErr.Render("capture error: "+m.err.Error())
	}

	line2 := fmt.Sprintf("  %s pps  %s   total %s / %s   in %s   out %s   other %s   flows %d   hosts %d",
		stKey.Render(fmt.Sprintf("%.0f", m.pps)), stKey.Render(humanBits(m.bps)),
		humanCount(s.Packets), humanBytes(s.Bytes),
		stIn.Render(humanBytes(s.BytesIn)), stOut.Render(humanBytes(s.BytesOut)), stOther.Render(humanBytes(s.BytesOther)),
		len(m.snap.Flows), len(m.snap.Hosts))
	if s.Dropped > 0 {
		line2 += "  " + stErr.Render(fmt.Sprintf("dropped %d", s.Dropped))
	}

	var tabs []string
	for v := view(0); v < viewCount; v++ {
		label := fmt.Sprintf("%d %s", int(v)+1, v)
		if v == viewNotices && len(m.snap.Notices) > 0 {
			label += fmt.Sprintf(" (%d)", len(m.snap.Notices))
		}
		if v == m.view {
			tabs = append(tabs, stTabOn.Render(label))
		} else {
			tabs = append(tabs, stTabOff.Render(label))
		}
	}
	line3 := strings.Join(tabs, "")
	if m.view != viewMap && m.view != viewStats {
		line3 += stDim.Render(fmt.Sprintf("  sort: %s  dir: %s", m.sort, m.dir))
	}
	if m.searching {
		line3 += "  search: " + stKey.Render(m.search+"▏")
	} else if m.search != "" {
		line3 += "  search: " + stKey.Render(m.search)
	}
	if len(m.snap.Notices) > 0 && m.view != viewNotices {
		if n := m.snap.Notices[0]; time.Since(n.T) < time.Minute {
			line3 += "  " + stWarn.Render("⚠ "+n.Text)
		}
	}
	return truncLine(line1, m.w) + "\n" + truncLine(line2, m.w) + "\n" + truncLine(line3, m.w)
}

func (m model) renderFooter() string {
	keys := []string{"q quit", "tab view", "j/k move", "s sort", "d dir", "i inbound", "/ search"}
	switch m.view {
	case viewFlows:
		keys = append(keys, "enter detail", "t timeline", "a ask")
	case viewHosts:
		keys = append(keys, "enter detail", "a ask")
	case viewPackets:
		keys = append(keys, "enter decode", "a ask")
	case viewNotices:
		keys = append(keys, "a ask")
	case viewMap:
		keys = []string{"q quit", "tab view", "j/k scroll", "u retrace", "a ask", "p pause", "? help"}
	}
	keys = append(keys, "p pause", "r reset", "? help")
	var parts []string
	for _, k := range keys {
		f := strings.SplitN(k, " ", 2)
		parts = append(parts, stKey.Render(f[0])+" "+stDim.Render(f[1]))
	}
	return truncLine(" "+strings.Join(parts, "  "), m.w)
}

// ipWidth picks an address column width: full IPv6 only on wide terminals.
func (m model) ipWidth(hasV6 bool) int {
	switch {
	case !hasV6:
		return 15
	case m.w >= 150:
		return 39
	default:
		return 25
	}
}

// layoutCols drops optional columns until the table fits, keeping at least
// minFlex for the last (flexible) column. It returns the kept columns and
// their indexes into the original slice.
func layoutCols(cols []col, width int) ([]col, []int) {
	const minFlex = 14
	keep := make([]bool, len(cols))
	for i := range keep {
		keep[i] = true
	}
	last := len(cols) - 1
	for {
		used := 0
		for i := 0; i < last; i++ {
			if keep[i] {
				used += cols[i].w + 1
			}
		}
		if used+minFlex <= width {
			break
		}
		drop := -1
		for i := 0; i < last; i++ {
			if keep[i] && cols[i].prio > 0 && (drop < 0 || cols[i].prio > cols[drop].prio) {
				drop = i
			}
		}
		if drop < 0 {
			break
		}
		keep[drop] = false
	}
	var kept []col
	var idx []int
	for i, c := range cols {
		if keep[i] {
			kept = append(kept, c)
			idx = append(idx, i)
		}
	}
	return kept, idx
}

// renderTable draws a header plus the visible window of rows.
// rows[i] is the row at index m.offset+i and holds one cell per column in cols
// (before layout); idx selects the kept columns.
func (m model) renderTable(b *strings.Builder, cols []col, rows [][]string, styles []lipgloss.Style, total int) {
	kept, idx := layoutCols(cols, m.w)
	used := 0
	for i := 0; i < len(kept)-1; i++ {
		used += kept[i].w + 1
	}
	if last := m.w - used; last > 4 {
		kept[len(kept)-1].w = last
	} else {
		kept[len(kept)-1].w = 4
	}
	var hdr []string
	for _, c := range kept {
		hdr = append(hdr, fit(c.name, c.w, c.right))
	}
	b.WriteString(stHeader.Render(truncLine(strings.Join(hdr, " "), m.w)))
	b.WriteByte('\n')

	avail := m.rowsAvail()
	for i := 0; i < avail; i++ {
		if i >= len(rows) || m.offset+i >= total {
			b.WriteByte('\n')
			continue
		}
		var cells []string
		for j, c := range kept {
			v := ""
			if idx[j] < len(rows[i]) {
				v = rows[i][idx[j]]
			}
			cells = append(cells, fit(v, c.w, c.right))
		}
		line := truncLine(strings.Join(cells, " "), m.w)
		switch {
		case m.offset+i == m.cursor:
			line = stSelected.Render(line)
		case styles != nil && i < len(styles):
			line = styles[i].Render(line)
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
}

func dirStyle(d Direction) lipgloss.Style {
	switch d {
	case DirIn:
		return stIn
	case DirOut, DirLocal:
		return stOut
	}
	return stOther
}

func (m model) window(n int) (int, int) {
	end := min(n, m.offset+m.rowsAvail())
	return m.offset, end
}

func (m model) renderFlows(b *strings.Builder) {
	start, end := m.window(len(m.flows))
	hasV6 := false
	for i := start; i < end; i++ {
		if m.flows[i].Key.Remote.Is6() {
			hasV6 = true
		}
	}
	cols := []col{
		{"DIR", 5, false, 0}, {"PROTO", 6, false, 0}, {"REMOTE", m.ipWidth(hasV6), false, 0}, {"RPORT", 6, true, 2}, {"LPORT", 6, true, 5},
		{"PKTS↓", 7, true, 6}, {"PKTS↑", 7, true, 7}, {"BYTES↓", 8, true, 0}, {"BYTES↑", 8, true, 3},
		{"RTT", 7, true, 8}, {"TTL", 4, true, 9}, {"LAST", 5, true, 4}, {"PROCESS", 14, false, 1},
		{"NAME / ORIGIN", 20, false, 0},
	}
	var rows [][]string
	var styles []lipgloss.Style
	for i := start; i < end; i++ {
		f := m.flows[i]
		hi := m.res.Get(f.Key.Remote)
		rows = append(rows, []string{
			f.Dir.String(), f.Key.Proto, f.Key.Remote.String(), portStr(f.Key.RemotePort), portStr(f.Key.LocalPort),
			humanCount(f.PktsIn), humanCount(f.PktsOut), humanBytes(f.BytesIn), humanBytes(f.BytesOut),
			rttStr(f.RTT), ttlStr(f.TTL), age(f.Last), orDash(f.Proc), nameOrigin(f.Name, hi),
		})
		styles = append(styles, dirStyle(f.Dir))
	}
	m.renderTable(b, cols, rows, styles, len(m.flows))
}

func (m model) renderHosts(b *strings.Builder) {
	start, end := m.window(len(m.hosts))
	hasV6 := false
	for i := start; i < end; i++ {
		if m.hosts[i].IP.Is6() {
			hasV6 = true
		}
	}
	cols := []col{
		{"REMOTE", m.ipWidth(hasV6), false, 0}, {"PKTS↓", 7, true, 6}, {"PKTS↑", 7, true, 7}, {"BYTES↓", 8, true, 0}, {"BYTES↑", 8, true, 3},
		{"FLOWS", 6, true, 4}, {"PORTS", 16, false, 5}, {"PROCESS", 14, false, 2}, {"LAST", 5, true, 1},
		{"NAME", 26, false, 0}, {"ORIGIN", 20, false, 0},
	}
	var rows [][]string
	var styles []lipgloss.Style
	for i := start; i < end; i++ {
		h := m.hosts[i]
		hi := m.res.Get(h.IP)
		name := h.BestName()
		if name == "" {
			name = hi.Name
		}
		procs := topKeys(h.Procs, 1)
		proc := "-"
		if len(procs) > 0 {
			proc = procs[0]
			if len(h.Procs) > 1 {
				proc += fmt.Sprintf(" +%d", len(h.Procs)-1)
			}
		}
		rows = append(rows, []string{
			h.IP.String(), humanCount(h.PktsIn), humanCount(h.PktsOut), humanBytes(h.BytesIn), humanBytes(h.BytesOut),
			fmt.Sprint(h.Flows), portList(h.Ports, 3), proc, age(h.Last), name, hi.Origin(),
		})
		d := DirOut
		if h.PktsIn > 0 {
			d = DirIn
		}
		if hi.Kind == "multicast" || hi.Kind == "broadcast" {
			d = DirOther
		}
		styles = append(styles, dirStyle(d))
	}
	m.renderTable(b, cols, rows, styles, len(m.hosts))
}

func (m model) renderPackets(b *strings.Builder) {
	start, end := m.window(len(m.pkts))
	hasV6 := false
	for i := start; i < end; i++ {
		if m.pkts[i].Src.Is6() || m.pkts[i].Dst.Is6() {
			hasV6 = true
		}
	}
	ipw := m.ipWidth(hasV6) + 6
	cols := []col{
		{"TIME", 12, false, 0}, {"DIR", 5, false, 2}, {"PROTO", 6, false, 0}, {"SOURCE", ipw, false, 0}, {"DEST", ipw, false, 0},
		{"LEN", 5, true, 1}, {"TTL", 4, true, 3}, {"INFO", 20, false, 0},
	}
	var rows [][]string
	var styles []lipgloss.Style
	for i := start; i < end; i++ {
		p := m.pkts[i]
		rows = append(rows, []string{
			p.Time.Format("15:04:05.000"), p.Dir.String(), p.Proto, addrPort(p.Src, p.SPort), addrPort(p.Dst, p.DPort),
			fmt.Sprint(p.Len), ttlStr(p.TTL), p.Info,
		})
		styles = append(styles, dirStyle(p.Dir))
	}
	m.renderTable(b, cols, rows, styles, len(m.pkts))
}

func (m model) renderNotices(b *strings.Builder) {
	start, end := m.window(len(m.notices))
	cols := []col{{"TIME", 8, false, 0}, {"KIND", 8, false, 0}, {"NOTICE", 20, false, 0}}
	var rows [][]string
	var styles []lipgloss.Style
	for i := start; i < end; i++ {
		n := m.notices[i]
		rows = append(rows, []string{n.T.Format("15:04:05"), n.Kind, n.Text})
		switch n.Kind {
		case "arp", "scan":
			styles = append(styles, stErr)
		case "inbound":
			styles = append(styles, stWarn)
		default:
			styles = append(styles, stDim)
		}
	}
	m.renderTable(b, cols, rows, styles, len(m.notices))
}

func (m model) renderDetail() string {
	var ip netip.Addr
	var h *Host
	switch m.view {
	case viewFlows:
		if m.cursor < len(m.flows) {
			ip = m.flows[m.cursor].Key.Remote
		}
	case viewHosts:
		if m.cursor < len(m.hosts) {
			ip = m.hosts[m.cursor].IP
		}
	}
	for i := range m.snap.Hosts {
		if m.snap.Hosts[i].IP == ip {
			h = &m.snap.Hosts[i]
			break
		}
	}
	lines := make([]string, 0, detailLines)
	rule := stDim.Render(strings.Repeat("─", max(0, m.w-len(ip.String())-4)))
	lines = append(lines, fmt.Sprintf("─ %s %s", stKey.Render(ip.String()), rule))
	if h == nil {
		lines = append(lines, stDim.Render("  no data for this address"))
	} else {
		hi := m.res.Get(ip)
		rdns := hi.Name
		if rdns == "" {
			if hi.NameOK {
				rdns = stDim.Render("(no reverse DNS)")
			} else {
				rdns = stDim.Render("(resolving…)")
			}
		}
		names := topKeys(h.Names, 3)
		nameStr := stDim.Render("(no name seen in TLS/DNS yet)")
		if len(names) > 0 {
			nameStr = strings.Join(names, ", ")
			if len(h.Names) > 3 {
				nameStr += fmt.Sprintf(" +%d", len(h.Names)-3)
			}
		}
		asn := ""
		if hi.ASN != "" {
			asn = " " + hi.ASN
		}
		extra := ""
		if h.MAC != "" {
			extra += "    mac " + h.MAC
		}
		if h.TTL != 0 {
			extra += "    " + ttlExplain(h.TTL)
		}
		procs := topKeys(h.Procs, 4)
		procStr := stDim.Render("(unknown: not a socket of this user, or too short-lived)")
		if len(procs) > 0 {
			procStr = strings.Join(procs, ", ")
		}
		lines = append(lines,
			fmt.Sprintf("  name   %s    rdns  %s", nameStr, rdns),
			fmt.Sprintf("  kind   %s    origin  %s%s%s", hi.Kind, hi.Origin(), asn, extra),
			fmt.Sprintf("  first  %s    last  %s (%s ago)    flows %d    protos %s",
				h.First.Format("15:04:05"), h.Last.Format("15:04:05"), age(h.Last), h.Flows, protoList(h.Protos)),
			fmt.Sprintf("  in     %s pkts / %s    out  %s pkts / %s",
				humanCount(h.PktsIn), humanBytes(h.BytesIn), humanCount(h.PktsOut), humanBytes(h.BytesOut)),
			fmt.Sprintf("  process       %s", procStr),
			fmt.Sprintf("  remote ports  %s", portList(h.Ports, 8)),
			fmt.Sprintf("  local ports   %s", portList(h.LocalPorts, 8)),
		)
	}
	for len(lines) < detailLines {
		lines = append(lines, "")
	}
	var b strings.Builder
	for _, l := range lines[:detailLines] {
		b.WriteString(truncLine(l, m.w))
		b.WriteByte('\n')
	}
	return b.String()
}

func (m model) renderOverlay() string {
	o := m.overlay
	var b strings.Builder
	b.WriteString(truncLine(stTitle.Render("ears")+"  "+stKey.Render(o.title), m.w))
	b.WriteByte('\n')
	body := m.h - 2
	if body < 1 {
		body = 1
	}
	for i := 0; i < body; i++ {
		idx := o.off + i
		if idx < len(o.lines) {
			b.WriteString(truncLine(o.lines[idx], m.w))
		}
		b.WriteByte('\n')
	}
	pos := ""
	if len(o.lines) > body {
		pos = fmt.Sprintf("  line %d-%d of %d", o.off+1, min(o.off+body, len(o.lines)), len(o.lines))
	}
	keys := " " + stKey.Render("esc") + stDim.Render(" close  ") + stKey.Render("j/k") + stDim.Render(" scroll  ") + stKey.Render("space") + stDim.Render(" page")
	if o.ai && o.aiPrompt != "" {
		label := " show what was sent"
		if o.showSent {
			label = " show the answer"
		}
		keys += "  " + stKey.Render("v") + stDim.Render(label)
	}
	b.WriteString(truncLine(keys+stDim.Render(pos), m.w))
	return b.String()
}

// ---- formatting helpers ----

func fit(s string, w int, right bool) string {
	if runewidth.StringWidth(s) > w {
		s = runewidth.Truncate(s, w, "…")
	}
	if right {
		return runewidth.FillLeft(s, w)
	}
	return runewidth.FillRight(s, w)
}

func truncLine(s string, w int) string {
	if w <= 0 || lipgloss.Width(s) <= w {
		return s
	}
	return runewidth.Truncate(s, w, "")
}

// nameOrigin picks the best label for a flow: SNI/DNS name, then reverse DNS, then origin.
func nameOrigin(name string, hi HostInfo) string {
	if name == "" {
		name = hi.Name
	}
	if name != "" {
		return name + "  " + stDim.Render(hi.Origin())
	}
	return hi.Origin()
}

func flowTitle(f Flow) string {
	return fmt.Sprintf("%s %s ⇄ %s", f.Key.Proto, addrPort(f.Key.Local, f.Key.LocalPort), addrPort(f.Key.Remote, f.Key.RemotePort))
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func portStr(p uint16) string {
	if p == 0 {
		return "-"
	}
	return fmt.Sprint(p)
}

func rttStr(d time.Duration) string {
	switch {
	case d == 0:
		return "-"
	case d < time.Millisecond:
		return fmt.Sprintf("%dµs", d.Microseconds())
	case d < time.Second:
		return fmt.Sprintf("%.1fms", float64(d.Microseconds())/1000)
	default:
		return fmt.Sprintf("%.1fs", d.Seconds())
	}
}

func ttlStr(t uint8) string {
	if t == 0 {
		return "-"
	}
	return fmt.Sprint(t)
}

// ttlExplain estimates hop count from the TTL, assuming the usual 64/128/255 start values.
func ttlExplain(t uint8) string {
	start := 255
	switch {
	case t <= 64:
		start = 64
	case t <= 128:
		start = 128
	}
	return fmt.Sprintf("ttl %d ≈ %d hops away (if it started at %d)", t, start-int(t), start)
}

func addrPort(ip netip.Addr, port uint16) string {
	if !ip.IsValid() {
		return "-"
	}
	if port == 0 {
		return ip.String()
	}
	return netip.AddrPortFrom(ip, port).String()
}

func portList(m map[uint16]uint64, n int) string {
	ps := topPorts(m, n)
	var parts []string
	for _, p := range ps {
		parts = append(parts, fmt.Sprint(p))
	}
	if len(m) > n {
		parts = append(parts, fmt.Sprintf("+%d", len(m)-n))
	}
	return strings.Join(parts, " ")
}

func protoList(m map[string]uint64) string {
	var parts []string
	for _, k := range topKeys(m, 6) {
		parts = append(parts, fmt.Sprintf("%s %s", k, humanCount(m[k])))
	}
	return strings.Join(parts, ", ")
}

func age(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	d := time.Since(t)
	switch {
	case d < time.Second:
		return "now"
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	default:
		return fmt.Sprintf("%dh", int(d.Hours()))
	}
}

func humanBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	f, i := float64(n)/unit, 0
	for ; f >= unit && i < 4; i++ {
		f /= unit
	}
	return fmt.Sprintf("%.1f %cB", f, "KMGTP"[i])
}

func humanBits(bps float64) string {
	units := []string{"b/s", "Kb/s", "Mb/s", "Gb/s"}
	i := 0
	for bps >= 1000 && i < len(units)-1 {
		bps /= 1000
		i++
	}
	return fmt.Sprintf("%.1f %s", bps, units[i])
}

func humanCount(n uint64) string {
	switch {
	case n < 10000:
		return fmt.Sprint(n)
	case n < 1000000:
		return fmt.Sprintf("%.1fk", float64(n)/1000)
	default:
		return fmt.Sprintf("%.2fM", float64(n)/1e6)
	}
}

// askClaude opens a panel and streams Claude's explanation of the selected row.
func (m model) askClaude() (tea.Model, tea.Cmd) {
	var title, prompt string
	switch {
	case m.view == viewFlows && m.cursor < len(m.flows):
		title, prompt = m.aiFlow(m.flows[m.cursor])
	case m.view == viewHosts && m.cursor < len(m.hosts):
		title, prompt = m.aiHost(m.hosts[m.cursor])
	case m.view == viewPackets && m.cursor < len(m.pkts):
		title, prompt = m.aiPacket(m.pkts[m.cursor])
	case m.view == viewNotices && m.cursor < len(m.notices):
		title, prompt = m.aiNotice(m.notices[m.cursor])
	case m.view == viewMap:
		title, prompt = m.aiMap()
	default:
		return m, nil
	}
	if m.explain == nil {
		m.overlay = &overlay{title: "Ask Claude", lines: aiDisabledLines()}
		return m, nil
	}
	m.aiSeq++
	ctx, cancel := context.WithCancel(context.Background())
	o := &overlay{title: title, ai: true, aiID: m.aiSeq, aiCancel: cancel, aiPrompt: prompt, aiLabel: m.explain.Label()}
	o.aiCh = m.explain.Start(ctx, o.aiID, prompt)
	m.overlay = o
	m.refreshAI()
	return m, waitAI(o.aiCh)
}

// refreshAI re-wraps the explanation panel for the current width and state.
func (m *model) refreshAI() {
	o := m.overlay
	if o == nil || !o.ai {
		return
	}
	width := m.w - 4
	if o.showSent {
		o.lines = []string{stDim.Render("  This is the exact text sent to the API with the request, besides the fixed instructions:"), ""}
		for _, l := range wrapText(o.aiPrompt, width) {
			o.lines = append(o.lines, "  "+l)
		}
		return
	}
	text := strings.ReplaceAll(o.aiText.String(), "**", "")
	var lines []string
	if text == "" && !o.aiDone {
		lines = append(lines, stDim.Render("  Thinking… ("+o.aiLabel+")"))
	}
	for _, l := range wrapText(text, width) {
		lines = append(lines, "  "+l)
	}
	if o.aiDone {
		lines = append(lines, "")
		if o.aiErr != nil {
			lines = append(lines, stErr.Render("  "+o.aiErr.Error()))
		} else {
			lines = append(lines, stDim.Render("  Answer by "+o.aiLabel+". It can be wrong; check claims against the data with v."))
		}
	}
	o.lines = lines
}

func aiDisabledLines() []string {
	return []string{
		"  Explanations are off. Start ears with -ai to turn them on:",
		"",
		"    ./ears -ai      # uses Claude Code and your Claude plan, or the API if ANTHROPIC_API_KEY is set",
		"",
		"  Pressing a then sends a text description of the selected row to Claude:",
		"  addresses, ports, server and process names, counters, and for a single packet its",
		"  decoded headers and first 128 bytes. Nothing is sent until you press a, and only that row.",
		"  The panel's v key shows the exact text before you rely on the answer.",
	}
}
