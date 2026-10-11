package main

import (
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// mapDevice is one box on the map: a hardware address and what is known about it.
type mapDevice struct {
	MAC       string
	IPs       []netip.Addr
	Name      string
	Vendor    string
	Private   bool
	Hint      string
	BytesFrom uint64
	BytesTo   uint64
	Last      time.Time
	Self      bool
	Router    bool
	ARPOnly   bool
}

var (
	stMapSelf    = lipgloss.NewStyle().Foreground(lipgloss.Color("39"))
	stMapRouter  = lipgloss.NewStyle().Foreground(lipgloss.Color("220"))
	stMapNet     = lipgloss.NewStyle().Foreground(lipgloss.Color("141"))
	stMapDev     = lipgloss.NewStyle().Foreground(lipgloss.Color("250"))
	stMapPrivate = lipgloss.NewStyle().Foreground(lipgloss.Color("244"))
	stMapActive  = lipgloss.NewStyle().Foreground(lipgloss.Color("82"))
	stMapSpine   = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	stMapUp      = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("75"))
	stMapDown    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("82"))
	stBold       = lipgloss.NewStyle().Bold(true)
	stSelBorder  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("231"))
	hopPalette   = []lipgloss.Style{
		lipgloss.NewStyle().Foreground(lipgloss.Color("214")),
		lipgloss.NewStyle().Foreground(lipgloss.Color("141")),
		lipgloss.NewStyle().Foreground(lipgloss.Color("44")),
		lipgloss.NewStyle().Foreground(lipgloss.Color("205")),
	}
)

type animMsg struct{}

func animTick() tea.Cmd {
	return tea.Tick(180*time.Millisecond, func(time.Time) tea.Msg { return animMsg{} })
}

// buildDevices merges the ARP table, the capture's MAC records and this
// machine's own interface into one list, keyed by hardware address.
func (m model) buildDevices(tv TopoView) (router *mapDevice, devs []mapDevice) {
	byMAC := map[string]*mapDevice{}
	get := func(mac string) *mapDevice {
		d := byMAC[mac]
		if d == nil {
			d = &mapDevice{MAC: mac}
			d.Vendor, d.Private = m.topo.Vendor(mac)
			byMAC[mac] = d
		}
		return d
	}
	addIP := func(d *mapDevice, ip netip.Addr) {
		for _, x := range d.IPs {
			if x == ip {
				return
			}
		}
		d.IPs = append(d.IPs, ip)
	}
	onLAN := func(ip netip.Addr) bool {
		if ip.Is4() {
			return tv.Subnet.IsValid() && tv.Subnet.Contains(ip)
		}
		return ip.IsLinkLocalUnicast() || ip.IsPrivate()
	}
	owner := map[netip.Addr]string{} // IPv4 address -> MAC the system vouches for
	if tv.LocalIP.IsValid() && tv.LocalMAC != "" {
		owner[tv.LocalIP] = tv.LocalMAC
	}
	for _, e := range tv.ARP {
		if e.Iface != tv.Iface {
			continue
		}
		owner[e.IP] = e.MAC
		d := get(e.MAC)
		d.ARPOnly = true
		addIP(d, e.IP)
	}
	for _, mi := range m.snap.Macs {
		var ips []netip.Addr
		for ip := range mi.IPs {
			if o, ok := owner[ip]; onLAN(ip) && (!ok || o == mi.MAC) {
				ips = append(ips, ip)
			}
		}
		if len(ips) == 0 && byMAC[mi.MAC] == nil {
			continue // a MAC with no LAN address is not a device we can place
		}
		d := get(mi.MAC)
		d.ARPOnly = false
		for _, ip := range ips {
			addIP(d, ip)
		}
		d.BytesFrom, d.BytesTo, d.Last = mi.BytesFrom, mi.BytesTo, mi.Last
		if mi.Hostname != "" {
			d.Name = mi.Hostname
		}
		d.Hint = osHint(mi.Vendor)
	}
	if tv.LocalMAC != "" {
		d := get(tv.LocalMAC)
		d.Self, d.ARPOnly = true, false
		if tv.LocalIP.IsValid() {
			addIP(d, tv.LocalIP)
		}
		d.Name = tv.Hostname
	}
	for _, d := range byMAC {
		sort.Slice(d.IPs, func(i, j int) bool {
			if d.IPs[i].Is4() != d.IPs[j].Is4() {
				return d.IPs[i].Is4()
			}
			return d.IPs[i].Less(d.IPs[j])
		})
		for _, ip := range d.IPs {
			if ip == tv.Gateway {
				d.Router = true
			}
			if d.Name == "" {
				if n := m.snap.LANNames[ip]; n != "" {
					d.Name = strings.TrimSuffix(n, ".local")
				}
			}
		}
		if d.Name == "" && len(d.IPs) > 0 {
			m.res.Enqueue(d.IPs[0])
			d.Name = m.res.Get(d.IPs[0]).Name
		}
	}
	for _, d := range byMAC {
		if d.Router {
			r := *d
			router = &r
			continue
		}
		devs = append(devs, *d)
	}
	sort.Slice(devs, func(i, j int) bool {
		if devs[i].Self != devs[j].Self {
			return devs[i].Self
		}
		a, b := devs[i], devs[j]
		if len(a.IPs) == 0 || len(b.IPs) == 0 {
			return len(a.IPs) > len(b.IPs)
		}
		return a.IPs[0].Less(b.IPs[0])
	})
	return router, devs
}

func osHint(vendorClass string) string {
	v := strings.ToLower(vendorClass)
	switch {
	case v == "":
		return ""
	case strings.Contains(v, "android"):
		return "Android"
	case strings.HasPrefix(v, "msft"):
		return "Windows"
	case strings.Contains(v, "dhcpcd"):
		return "Linux (dhcpcd)"
	case strings.Contains(v, "udhcp"):
		return "embedded Linux"
	}
	return vendorClass
}

// ---- drawing primitives ----

// drawBox returns a rounded box of display width w. join columns (relative to
// the box, -1 for none) put ┴ in the top border and ┬ in the bottom one.
func drawBox(body []string, w int, border lipgloss.Style, topJoin, botJoin int) []string {
	return drawBoxSel(body, w, border, topJoin, botJoin, false)
}

// drawBoxSel draws a heavy, bright border when sel is set.
func drawBoxSel(body []string, w int, border lipgloss.Style, topJoin, botJoin int, sel bool) []string {
	if w < 6 {
		w = 6
	}
	tl, tr, bl, br, h, v, jt, jb := "╭", "╮", "╰", "╯", "─", "│", "┴", "┬"
	if sel {
		tl, tr, bl, br, h, v, jt, jb = "┏", "┓", "┗", "┛", "━", "┃", "┻", "┳"
		border = stSelBorder
	}
	edge := func(l, r string, join int, jc string) string {
		runes := []string{l}
		for i := 1; i < w-1; i++ {
			if i == join {
				runes = append(runes, jc)
			} else {
				runes = append(runes, h)
			}
		}
		runes = append(runes, r)
		return border.Render(strings.Join(runes, ""))
	}
	out := []string{edge(tl, tr, topJoin, jt)}
	for _, l := range body {
		out = append(out, border.Render(v)+" "+fitStyled(l, w-4)+" "+border.Render(v))
	}
	return append(out, edge(bl, br, botJoin, jb))
}

// fitStyled pads or truncates a possibly styled string to exactly w cells.
func fitStyled(s string, w int) string { return fit(s, w, false) }

func indent(n int) string {
	if n <= 0 {
		return ""
	}
	return strings.Repeat(" ", n)
}

// spineRow is one line on the vertical path between the LAN and the internet.
type spineRow struct {
	node  string // "" for a plain segment, else the node glyph
	style lipgloss.Style
	text  string
	key   string // selectable object key, for hop rows
}

// mapObj is a selectable thing on the map and where it was drawn.
type mapObj struct {
	key    string
	line   int
	height int
}

func devKey(d mapDevice) string { return "dev:" + d.MAC }

// ---- the map ----

func (m model) mapLines() []string {
	lines, _ := m.mapLayout()
	return lines
}

// mapLayout draws the map and records each selectable object's position.
func (m model) mapLayout() ([]string, []mapObj) {
	W := max(m.w, 40)
	tv := m.tv
	router, devs := m.buildDevices(tv)
	var lines []string
	var objs []mapObj
	add := func(ls ...string) {
		for _, l := range ls {
			lines = append(lines, truncLine(l, W))
		}
	}
	mark := func(key string, height int) { objs = append(objs, mapObj{key: key, line: len(lines), height: height}) }

	boxW := min(54, W-2)
	// Wide terminals: boxes centred on the spine, pulled left so hop labels
	// fit. Narrow ones: everything against the left edge, spine near it.
	sc := max(boxW/2+1, min(W/2, W-84))
	boxLeft := sc - boxW/2
	if W < 120 {
		boxLeft, sc = 1, 5
	}
	join := sc - boxLeft
	narrow := W < 120

	// Hops beyond the router, furthest first.
	var hops []Hop
	for _, h := range tv.Hops {
		if h.N == 1 && (h.IP == tv.Gateway || h.NoReply) {
			continue
		}
		if n := len(hops); n > 0 && !h.NoReply && hops[n-1].IP == h.IP {
			continue // the same router answered for two TTLs
		}
		hops = append(hops, h)
	}
	firstOrg, lastHop := "", Hop{}
	for _, h := range hops {
		if !h.NoReply {
			lastHop = h
			if firstOrg == "" {
				if hi := m.res.Get(h.IP); hi.Kind == "public" && hi.Org != "" {
					firstOrg = hi.Org
				}
			}
		}
	}

	// Internet box.
	inet := []string{stBold.Render(stMapNet.Render("☁  Internet"))}
	if firstOrg != "" {
		inet = append(inet, "ISP "+firstOrg)
	}
	switch {
	case tv.TraceState == "running":
		inet = append(inet, stDim.Render("tracing "+tv.Target+"…"))
	case tv.TraceState == "done" && lastHop.IP.IsValid():
		inet = append(inet, fmt.Sprintf("%d hops to %s · %s", lastHop.N, tv.Target, rttStr(lastHop.RTT)))
	case tv.TraceState == "done":
		inet = append(inet, stDim.Render("no hops answered"))
	case tv.TraceState == "":
		inet = append(inet, stDim.Render("u: trace route"))
	default:
		inet = append(inet, stErr.Render(tv.TraceState))
	}
	inetBox := drawBoxSel(inet, boxW, stMapNet, -1, join, m.mapSel == "inet")
	mark("inet", len(inetBox))
	for _, l := range inetBox {
		add(indent(boxLeft) + l)
	}

	// Spine: hops, then the router box, then the link to this machine.
	var spine []spineRow
	spine = append(spine, spineRow{})
	group, prevOrg := -1, "\x00"
	var maxRTT time.Duration
	for _, h := range hops {
		maxRTT = max(maxRTT, h.RTT)
	}
	for i := len(hops) - 1; i >= 0; i-- {
		h := hops[i]
		if h.NoReply {
			spine = append(spine, spineRow{node: "○", style: stDim, text: stDim.Render(fmt.Sprintf("%2d  no reply", h.N))})
			continue
		}
		hi := m.res.Get(h.IP)
		org := firstNonEmpty(hi.Org, hi.ASN, hi.Kind)
		if org != prevOrg {
			group++
			prevOrg = org
		}
		st := hopPalette[group%len(hopPalette)]
		where := org
		if hi.City != "" {
			where += " · " + hi.City
		}
		label := hi.Name
		if label == "" {
			label = where
		} else {
			label += "  " + stDim.Render(where)
		}
		bar := ""
		if maxRTT > 0 && !narrow {
			n := int(int64(h.RTT) * 8 / int64(maxRTT))
			bar = stBar.Render(strings.Repeat("▮", max(1, n))) + strings.Repeat(" ", 8-max(1, n))
		}
		text := fmt.Sprintf("%s  %-15s %s %7s  %s", st.Render(fmt.Sprintf("%2d", h.N)), h.IP, bar, rttStr(h.RTT), label)
		if narrow {
			text = fmt.Sprintf("%s  %-15s %7s  %s", st.Render(fmt.Sprintf("%2d", h.N)), h.IP, rttStr(h.RTT), label)
		}
		spine = append(spine, spineRow{node: "●", style: st, text: text, key: fmt.Sprintf("hop:%d", h.N)})
	}
	spine = append(spine, spineRow{})
	spineTop := spine

	// Router box body.
	var rbody []string
	rtitle := stBold.Render(stMapRouter.Render("⌂  Router"))
	rbody = append(rbody, rtitle)
	if tv.Gateway.IsValid() {
		gl := tv.Gateway.String()
		if router != nil && router.Name != "" {
			gl += "  " + router.Name
		}
		rbody = append(rbody, gl)
	} else {
		rbody = append(rbody, stDim.Render("no default route"))
	}
	if router != nil {
		rbody = append(rbody, firstNonEmpty(router.Vendor, "unknown")+stDim.Render("  "+router.MAC))
	}
	for _, h := range tv.Hops {
		if h.N == 1 && h.IP == tv.Gateway && h.RTT > 0 {
			rbody = append(rbody, "latency "+rttStr(h.RTT))
		}
	}
	if tv.WiFi != nil && tv.WiFi.BSSID != "" && router != nil {
		if sameDevice(router.MAC, tv.WiFi.BSSID) {
			rbody = append(rbody, "Wi-Fi built in")
		} else {
			v, _ := m.topo.Vendor(tv.WiFi.BSSID)
			rbody = append(rbody, "Wi-Fi via "+firstNonEmpty(v, tv.WiFi.BSSID))
		}
	}
	if router != nil && router.BytesFrom+router.BytesTo > 0 {
		rbody = append(rbody, fmt.Sprintf("↓%s ↑%s", humanBytes(router.BytesFrom), humanBytes(router.BytesTo)))
	}

	// Link between the router and the LAN.
	var link []spineRow
	if tv.Wireless {
		w := tv.WiFi
		if w != nil && w.SSID != "" {
			band := ""
			switch {
			case w.FreqMHz >= 5925:
				band = "6 GHz"
			case w.FreqMHz >= 4900:
				band = "5 GHz"
			case w.FreqMHz > 0:
				band = "2.4 GHz"
			}
			parts := []string{"Wi-Fi “" + w.SSID + "”"}
			if band != "" {
				parts = append(parts, fmt.Sprintf("%s ch %d", band, w.Channel))
			}
			if w.Security != "" {
				parts = append(parts, w.Security)
			}
			link = append(link, spineRow{text: stKey.Render(strings.Join(parts, " · "))})
		} else {
			link = append(link, spineRow{text: stKey.Render("Wi-Fi")})
		}
		if w != nil && w.RSSI != 0 {
			parts := []string{fmt.Sprintf("%d dBm %s", w.RSSI, signalWord(w.RSSI))}
			if w.Mode != "" {
				parts = append(parts, w.Mode)
			}
			if w.Bitrate != "" {
				parts = append(parts, w.Bitrate)
			}
			link = append(link, spineRow{text: stDim.Render(strings.Join(parts, " · "))})
		}
	} else {
		link = append(link, spineRow{text: stKey.Render("wired, " + tv.Iface)})
	}
	if bk := m.lastBucket(); bk.In+bk.Out > 0 {
		link = append(link, spineRow{text: stMapUp.Render("▲ "+humanBits(float64(bk.Out)*8)) + "  " + stMapDown.Render("▼ "+humanBits(float64(bk.In)*8))})
	}

	// Animated packets: one dot climbing the spine while uploading, one
	// falling while downloading.
	allSpine := len(spineTop) + len(link)
	bk := m.lastBucket()
	up, down := -1, -1
	if allSpine > 0 {
		if bk.Out > 0 {
			up = allSpine - 1 - m.phase%allSpine
		}
		if bk.In > 0 {
			down = (m.phase + allSpine/2) % allSpine
		}
	}
	renderSpine := func(rows []spineRow, base int) {
		for i, r := range rows {
			idx := base + i
			glyph := stMapSpine.Render("│")
			if r.node != "" {
				glyph = r.style.Render(r.node)
			}
			switch {
			case idx == up && r.node == "":
				glyph = stMapUp.Render("▲")
			case idx == down && r.node == "":
				glyph = stMapDown.Render("▼")
			}
			text := r.text
			if r.key != "" {
				mark(r.key, 1)
				if r.key == m.mapSel {
					text = stSelected.Render(" " + stripANSI(text) + " ")
				}
			}
			add(indent(sc) + glyph + "  " + text)
		}
	}
	renderSpine(spineTop, 0)
	rbox := drawBoxSel(rbody, boxW, stMapRouter, join, join, m.mapSel == "router")
	mark("router", len(rbox))
	for _, l := range rbox {
		add(indent(boxLeft) + l)
	}
	renderSpine(link, len(spineTop))

	// LAN bus and device boxes.
	gridLines, gridObjs := m.lanGrid(devs, tv, sc, W)
	for _, o := range gridObjs {
		o.line += len(lines)
		objs = append(objs, o)
	}
	lines = append(lines, gridLines...)

	// Tailscale overlay network.
	if len(tv.Tailscale) > 0 {
		add("", stBold.Render(stMapNet.Render("Tailscale"))+stDim.Render("  "+tv.TSIP.String()))
		for _, p := range tv.Tailscale {
			dot := stDim.Render("○")
			if p.Online {
				dot = stMapActive.Render("●")
			}
			ip := ""
			for _, a := range p.IPs {
				if a.Is4() {
					ip = a.String()
				}
			}
			path := p.Path()
			switch {
			case p.Self:
				path = stMapSelf.Render(path)
			case !p.Online || !p.Active:
				path = stDim.Render(path)
			}
			row := fmt.Sprintf("%s %-24s %-15s %-8s %s", dot, fitStyled(p.Name, 24), ip, p.OS, path)
			key := "ts:" + p.Name
			if key == m.mapSel {
				row = stSelected.Render(" " + stripANSI(row) + " ")
			}
			mark(key, 1)
			add("  " + row)
		}
	}

	add("", stDim.Render("● active  ○ quiet  ")+stMapUp.Render("▲")+stDim.Render(" out  ")+stMapDown.Render("▼")+stDim.Render(" in"))
	return lines, objs
}

// lanGrid draws the LAN bus joined to the spine at column sc, and the device boxes under it.
func (m model) lanGrid(devs []mapDevice, tv TopoView, sc, W int) ([]string, []mapObj) {
	const x0 = 3
	bw := 28
	if W < 120 {
		bw = 24
	}
	if W-x0 < bw+1 {
		bw = W - x0 - 1
	}
	cols := max(1, (W-x0)/(bw+1))
	rows := (len(devs) + cols - 1) / cols
	center := func(i int) int { return x0 + i*(bw+1) + bw/2 }
	var out []string
	var objs []mapObj
	label := "LAN"
	if tv.Subnet.IsValid() {
		label = fmt.Sprintf("LAN %s · %d devices", tv.Subnet, len(devs)+1)
	}
	if len(devs) == 0 {
		out = append(out, indent(sc)+stMapSpine.Render("│"), indent(max(0, sc-len(label)/2))+stDim.Render(label+" · no other devices"))
		return out, nil
	}
	for r := 0; r < rows; r++ {
		n := min(cols, len(devs)-r*cols)
		end := center(n - 1)
		if r == 0 {
			end = max(end, sc)
		}
		bus := make([]string, max(end+1, W))
		for i := range bus {
			bus[i] = " "
		}
		start := center(0)
		if rows > 1 {
			start = 1
		}
		for i := start; i <= end; i++ {
			bus[i] = "─"
		}
		if rows > 1 {
			switch {
			case r == 0:
				bus[1] = "┌"
			case r == rows-1:
				bus[1] = "└"
			default:
				bus[1] = "├"
			}
		}
		for i := 0; i < n; i++ {
			bus[center(i)] = "┬"
		}
		if r == 0 {
			if bus[sc] == "┬" {
				bus[sc] = "┼"
			} else {
				bus[sc] = "┴"
			}
			if start == center(0) && sc < start {
				bus[sc] = "└"
			}
			if sc == end && bus[sc] == "┴" {
				bus[sc] = "┘"
			}
		}
		line := stMapSpine.Render(strings.TrimRight(strings.Join(bus, ""), " "))
		if r == 0 && W-lipgloss.Width(line) > len(label)+3 {
			line += "  " + stDim.Render(label)
		}
		out = append(out, truncLine(line, W))

		boxes := make([][]string, n)
		for i := 0; i < n; i++ {
			d := devs[r*cols+i]
			boxes[i] = m.deviceBox(d, bw, devKey(d) == m.mapSel)
			objs = append(objs, mapObj{key: devKey(d), line: len(out), height: len(boxes[i])})
		}
		for li := range boxes[0] {
			trunk := "   "
			if rows > 1 && r < rows-1 {
				trunk = " " + stMapSpine.Render("│") + " "
			}
			var parts []string
			for i := 0; i < n; i++ {
				parts = append(parts, boxes[i][li])
			}
			out = append(out, truncLine(trunk+strings.Join(parts, " "), W))
		}
	}
	return out, objs
}

func (m model) deviceBox(d mapDevice, bw int, sel bool) []string {
	border := stMapDev
	switch {
	case d.Self:
		border = stMapSelf
	case d.Private:
		border = stMapPrivate
	}
	dot := stDim.Render("○")
	if d.Self || (!d.Last.IsZero() && time.Since(d.Last) < 30*time.Second) {
		dot = stMapActive.Render("●")
	}
	name := d.Name
	switch {
	case d.Self:
		name = firstNonEmpty(name, "this machine") + stMapSelf.Render(" ★")
	case name == "" && d.Vendor != "":
		name = d.Vendor
	case name == "":
		name = "unknown"
	}
	ip := "-"
	if len(d.IPs) > 0 {
		ip = d.IPs[0].String()
		if len(d.IPs) > 1 {
			ip += stDim.Render(fmt.Sprintf(" +%d", len(d.IPs)-1))
		}
	}
	maker := d.Vendor
	switch {
	case d.Private:
		maker = stDim.Render("random MAC")
	case maker == "":
		maker = stDim.Render(d.MAC)
	}
	if d.Hint != "" {
		maker += stDim.Render(" · " + d.Hint)
	}
	traffic := stDim.Render("quiet")
	if !d.ARPOnly && d.BytesFrom+d.BytesTo > 0 {
		traffic = fmt.Sprintf("↓%s ↑%s", shortBytes(d.BytesTo), shortBytes(d.BytesFrom))
		if !d.Last.IsZero() {
			traffic += stDim.Render(" · " + age(d.Last))
		}
	}
	if d.Self {
		traffic = stDim.Render(d.MAC)
	}
	return drawBoxSel([]string{dot + " " + stBold.Render(name), ip, maker, traffic}, bw, border, bw/2, -1, sel)
}

// sameDevice guesses whether two MACs belong to one box: routers number their
// radios and ports consecutively, so the first five bytes match.
func sameDevice(a, b string) bool {
	ha, err1 := net.ParseMAC(a)
	hb, err2 := net.ParseMAC(b)
	if err1 != nil || err2 != nil || len(ha) != 6 || len(hb) != 6 {
		return false
	}
	return string(ha[:5]) == string(hb[:5])
}

func signalWord(dbm int) string {
	switch {
	case dbm >= -50:
		return "excellent"
	case dbm >= -60:
		return "good"
	case dbm >= -70:
		return "fair"
	}
	return "weak"
}

// lastBucket is the most recent complete second of traffic.
func (m model) lastBucket() Bucket {
	if n := len(m.snap.Buckets); n >= 2 {
		return m.snap.Buckets[n-2]
	}
	return Bucket{}
}

func (m model) renderMap(b *strings.Builder) {
	lines, _ := m.mapLayout()
	avail := m.rowsAvail() + 1
	off := min(m.mapOff, max(0, len(lines)-avail))
	for i := 0; i < avail; i++ {
		if off+i < len(lines) {
			b.WriteString(lines[off+i])
		}
		b.WriteByte('\n')
	}
}

// aiMap describes the topology for Claude.
func (m model) aiMap() (title, prompt string) {
	tv := m.tv
	router, devs := m.buildDevices(tv)
	var b strings.Builder
	b.WriteString(m.aiPreamble())
	b.WriteString("Selected item: the map of the local network and the path to the internet.\n")
	fmt.Fprintf(&b, "Interface %s, subnet %s, this machine %s (%s).\n", tv.Iface, tv.Subnet, tv.LocalIP, tv.LocalMAC)
	if w := tv.WiFi; w != nil {
		fmt.Fprintf(&b, "Wi-Fi network %q, access point %s, %d MHz channel %d, %s, signal %d dBm, %s, %s.\n", w.SSID, w.BSSID, w.FreqMHz, w.Channel, w.Security, w.RSSI, w.Mode, w.Bitrate)
	}
	if router != nil {
		fmt.Fprintf(&b, "Default gateway %s, MAC %s, maker %s, name %q.\n", tv.Gateway, router.MAC, firstNonEmpty(router.Vendor, "unknown"), router.Name)
	}
	b.WriteString("Other devices on the LAN (from the ARP table and captured traffic):\n")
	for _, d := range devs {
		var ips []string
		for _, ip := range d.IPs {
			ips = append(ips, ip.String())
		}
		fmt.Fprintf(&b, "  - name %q, addresses %s, maker %q, private MAC %v, OS hint %q, bytes to it %d, from it %d, this machine %v\n",
			d.Name, strings.Join(ips, " "), d.Vendor, d.Private, d.Hint, d.BytesTo, d.BytesFrom, d.Self)
	}
	fmt.Fprintf(&b, "Trace to %s (state %s), hop by hop:\n", tv.Target, tv.TraceState)
	for _, h := range tv.Hops {
		if h.NoReply {
			fmt.Fprintf(&b, "  %d: no reply\n", h.N)
			continue
		}
		hi := m.res.Get(h.IP)
		fmt.Fprintf(&b, "  %d: %s rtt %s, reverse DNS %q, %s %s %s\n", h.N, h.IP, rttStr(h.RTT), hi.Name, hi.Origin(), hi.ASN, hi.Kind)
	}
	for _, p := range tv.Tailscale {
		fmt.Fprintf(&b, "Tailscale peer %q (%s), online %v, self %v, direct %q, relay %q.\n", p.Name, p.OS, p.Online, p.Self, p.Direct, p.Relay)
	}
	b.WriteString("\nExplain this network: how my traffic gets from this computer to the internet, what each device on the LAN probably is, and anything worth checking.")
	return "Ask Claude · network map", b.String()
}

// shortBytes is humanBytes without the space, for tight boxes: "960.0KB".
func shortBytes(n uint64) string { return strings.Replace(humanBytes(n), " ", "", 1) }
