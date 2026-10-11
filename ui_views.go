package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
)

// ---- Stats view ----

type kv struct {
	k string
	v uint64
}

func (m model) renderStats(b *strings.Builder) {
	avail := m.rowsAvail() + 1 // no table header in this view
	var lines []string

	// Bandwidth sparklines.
	in := make([]uint64, len(m.snap.Buckets))
	out := make([]uint64, len(m.snap.Buckets))
	pk := make([]uint64, len(m.snap.Buckets))
	var peakIn, peakOut uint64
	for i, bk := range m.snap.Buckets {
		in[i], out[i], pk[i] = bk.In, bk.Out, bk.Pkts
		peakIn, peakOut = max(peakIn, bk.In), max(peakOut, bk.Out)
	}
	sw := min(60, max(10, m.w-36))
	lines = append(lines,
		stSection.Render("Bandwidth, last 60 seconds")+stDim.Render("  one column per second, newest on the right"),
		fmt.Sprintf("  in    %s  peak %s", stBar.Render(spark(in, sw)), humanBits(float64(peakIn)*8)),
		fmt.Sprintf("  out   %s  peak %s", stBarOut.Render(spark(out, sw)), humanBits(float64(peakOut)*8)),
		fmt.Sprintf("  pkts  %s", stDim.Render(spark(pk, sw))),
		"",
	)

	// Breakdowns.
	byProto, byPort, byProc := map[string]uint64{}, map[string]uint64{}, map[string]uint64{}
	for _, f := range m.snap.Flows {
		byProto[f.Key.Proto] += f.Bytes()
		if f.Key.RemotePort != 0 {
			byPort[fmt.Sprintf("%d %s", f.Key.RemotePort, portName(f.Key.RemotePort))] += f.Bytes()
		}
		byProc[firstNonEmpty(f.Proc, "(unknown)")] += f.Bytes()
	}
	byCountry, byOrg, byKind := map[string]uint64{}, map[string]uint64{}, map[string]uint64{}
	for _, h := range m.snap.Hosts {
		hi := m.res.Get(h.IP)
		byKind[hi.Kind] += h.Bytes()
		if hi.Kind != "public" {
			continue
		}
		byCountry[firstNonEmpty(hi.Country, "?")] += h.Bytes()
		byOrg[firstNonEmpty(hi.Org, hi.ASN, "?")] += h.Bytes()
	}
	s := m.snap.Stats
	byDir := map[string]uint64{"in": s.BytesIn, "out": s.BytesOut, "other": s.BytesOther}

	colW := (m.w - 3) / 2
	if colW < 30 {
		colW = m.w
	}
	left := barList("Protocols", byProto, colW, 5)
	left = append(left, barList("Remote ports", byPort, colW, 6)...)
	left = append(left, barList("Processes", byProc, colW, 6)...)
	right := barList("Countries", byCountry, colW, 5)
	right = append(right, barList("Organisations", byOrg, colW, 6)...)
	right = append(right, barList("Direction", byDir, colW, 3)...)
	right = append(right, barList("Address kinds", byKind, colW, 4)...)
	if colW == m.w {
		lines = append(lines, left...)
		lines = append(lines, right...)
	} else {
		for i := 0; i < max(len(left), len(right)); i++ {
			l, r := "", ""
			if i < len(left) {
				l = left[i]
			}
			if i < len(right) {
				r = right[i]
			}
			lines = append(lines, fit(l, colW, false)+" │ "+r)
		}
	}

	for i := 0; i < avail; i++ {
		if i < len(lines) {
			b.WriteString(truncLine(lines[i], m.w))
		}
		b.WriteByte('\n')
	}
}

var sparkChars = []rune("▁▂▃▄▅▆▇█")

// spark renders values as a block-character sparkline of the given width,
// scaled to the maximum. Only the newest `width` values are drawn.
func spark(vals []uint64, width int) string {
	if len(vals) > width {
		vals = vals[len(vals)-width:]
	}
	var mx uint64
	for _, v := range vals {
		mx = max(mx, v)
	}
	var b strings.Builder
	for i := 0; i < width-len(vals); i++ {
		b.WriteRune(' ')
	}
	for _, v := range vals {
		if mx == 0 || v == 0 {
			b.WriteRune(sparkChars[0])
			continue
		}
		lvl := int(v * uint64(len(sparkChars)-1) / mx)
		if lvl == 0 {
			lvl = 1
		}
		b.WriteRune(sparkChars[lvl])
	}
	return b.String()
}

// barList renders a titled horizontal bar chart of the top n entries.
func barList(title string, m map[string]uint64, width, n int) []string {
	lines := []string{stSection.Render(title)}
	keys := topKeys(m, n)
	if len(keys) == 0 {
		return append(lines, stDim.Render("  (nothing yet)"), "")
	}
	var total, mx uint64
	for _, v := range m {
		total += v
	}
	for _, k := range keys {
		mx = max(mx, m[k])
	}
	labelW := 0
	for _, k := range keys {
		labelW = max(labelW, lipgloss.Width(k))
	}
	labelW = min(labelW, max(8, width/3))
	barW := width - labelW - 20
	if barW < 4 {
		barW = 4
	}
	for _, k := range keys {
		v := m[k]
		n := 0
		if mx > 0 {
			n = int(v * uint64(barW) / mx)
		}
		if n == 0 && v > 0 {
			n = 1
		}
		pct := 0.0
		if total > 0 {
			pct = float64(v) * 100 / float64(total)
		}
		lines = append(lines, fmt.Sprintf("  %s %s %8s %4.0f%%", fit(k, labelW, false), stBar.Render(strings.Repeat("█", n)+strings.Repeat("░", barW-n)), humanBytes(v), pct))
	}
	return append(lines, "")
}

var portNames = map[uint16]string{
	20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 67: "dhcp", 68: "dhcp", 80: "http", 110: "pop3",
	123: "ntp", 137: "netbios", 138: "netbios", 139: "netbios", 143: "imap", 161: "snmp", 443: "https", 445: "smb", 465: "smtps",
	500: "ipsec", 514: "syslog", 587: "submission", 631: "ipp", 853: "dns-tls", 993: "imaps", 995: "pop3s", 1194: "openvpn",
	1900: "ssdp", 3389: "rdp", 3478: "stun", 4500: "ipsec-nat", 5222: "xmpp", 5353: "mdns", 5355: "llmnr", 5228: "google-push",
	5900: "vnc", 8080: "http-alt", 8443: "https-alt", 41641: "tailscale", 51820: "wireguard", 57621: "spotify",
}

func portName(p uint16) string {
	if n, ok := portNames[p]; ok {
		return n
	}
	return ""
}

// ---- Timeline overlay ----

func timelineLines(f Flow, hi HostInfo) []string {
	var lines []string
	meta := []string{}
	if f.Name != "" {
		meta = append(meta, "name "+f.Name)
	} else if hi.Name != "" {
		meta = append(meta, "rdns "+hi.Name)
	}
	if f.Proc != "" {
		meta = append(meta, "process "+f.Proc)
	}
	if f.RTT != 0 {
		meta = append(meta, "rtt "+rttStr(f.RTT))
	}
	if f.TTL != 0 {
		meta = append(meta, ttlExplain(f.TTL))
	}
	meta = append(meta, "origin "+hi.Origin())
	lines = append(lines, "  "+strings.Join(meta, "    "))
	lines = append(lines, fmt.Sprintf("  first %s    last %s    in %s pkts / %s    out %s pkts / %s",
		f.First.Format("15:04:05.000"), f.Last.Format("15:04:05.000"),
		humanCount(f.PktsIn), humanBytes(f.BytesIn), humanCount(f.PktsOut), humanBytes(f.BytesOut)))
	lines = append(lines, "")
	lines = append(lines, stHeader.Render(fmt.Sprintf("  %-11s %-4s %-14s %8s %12s  %s", "TIME", "DIR", "FLAGS", "BYTES", "SEQ", "NOTE")))
	if len(f.Events) == 0 {
		lines = append(lines, stDim.Render("  no events recorded"))
	}
	var prev time.Time
	for i, e := range f.Events {
		arrow := "→"
		side := 0
		switch e.Dir {
		case DirIn:
			arrow, side = "←", 1
		case DirOther:
			arrow, side = "⇢", 1
		}
		seq := ""
		if f.Key.Proto == "TCP" && f.ISNSet[side] {
			seq = fmt.Sprintf("%d", e.Seq-f.ISN[side])
		}
		note := e.Note
		if f.Key.Proto == "TCP" {
			switch {
			case i == 0 && e.Flags == "SYN":
				note = firstNonEmpty(note, "open: sender proposes a connection")
			case e.Flags == "SYN,ACK":
				note = firstNonEmpty(note, "open: accepted")
				if f.RTT != 0 && f.Dir == DirOut {
					note += "  (round trip " + rttStr(f.RTT) + ")"
				}
			case i > 0 && e.Flags == "ACK" && f.Events[i-1].Flags == "SYN,ACK":
				note = firstNonEmpty(note, "open: handshake complete")
			case strings.Contains(e.Flags, "FIN"):
				note = firstNonEmpty(note, "close: no more data this way")
			case strings.Contains(e.Flags, "RST"):
				note = firstNonEmpty(note, "abort: connection reset")
			}
		}
		gap := ""
		if !prev.IsZero() {
			if d := e.T.Sub(prev); d > 500*time.Millisecond {
				gap = stDim.Render(fmt.Sprintf("  (+%s idle)", d.Truncate(time.Millisecond)))
			}
		}
		prev = e.T
		rel := e.T.Sub(f.First)
		style := dirStyle(e.Dir)
		lines = append(lines, style.Render(fmt.Sprintf("  +%-10s %-4s %-14s %8d %12s  %s", fmtRel(rel), arrow, orDash(e.Flags), e.Len, seq, note))+gap)
	}
	if len(f.Events) >= eventCap {
		lines = append(lines, stDim.Render(fmt.Sprintf("  … only the first %d packets of a flow are recorded", eventCap)))
	}
	lines = append(lines, "",
		stDim.Render("  → sent by this machine   ← received   ⇢ overheard.  BYTES is payload after headers; SEQ is relative to the first byte each side sent."),
		stDim.Render("  A TCP connection opens with SYN, SYN,ACK, ACK. The time between the first two is one round trip to the other end."))
	return lines
}

func fmtRel(d time.Duration) string {
	switch {
	case d < time.Second:
		return fmt.Sprintf("%.3fs", d.Seconds())
	case d < time.Minute:
		return fmt.Sprintf("%.2fs", d.Seconds())
	default:
		return d.Truncate(time.Millisecond * 10).String()
	}
}

// ---- Help overlay ----

func helpLines() []string {
	h := func(s string) string { return stSection.Render(s) }
	return []string{
		h("Keys"),
		"  tab / shift+tab / 1-6    switch view         j k / pgup pgdn / g G   move",
		"  s   cycle sort           d   cycle direction filter      i   inbound only",
		"  /   search (esc clears)  enter   detail panel (Flows, Hosts) or decode tree (Packets)",
		"  t   timeline of the selected flow (Flows)    p   pause display    r   reset counters    q   quit",
		"  a   ask Claude to explain the selected row (start with -ai); in the answer, v shows exactly what was sent",
		"",
		h("Views"),
		"  Flows     one conversation: remote address and port to a local port, one protocol",
		"  Hosts     one remote address with all its flows summed",
		"  Packets   every captured frame, newest first; enter shows it field by field",
		"  Stats     bandwidth over the last minute and bytes by protocol, port, process, country, organisation",
		"  Notices   things worth a look: new countries, inbound connections from the internet, port scans, ARP changes",
		"  Map       this machine, the LAN devices, the router, and each router on the path to the internet; u re-runs the trace",
		"",
		h("Columns"),
		"  DIR       in = sent to this machine, out = sent by it, other = overheard (broadcast, multicast, mirrored)",
		"  REMOTE    the other end; for 'other' traffic, the sender",
		"  RPORT     port on the remote; a well-known number (443 https, 53 dns) says what service",
		"  LPORT     port on this machine; a high random number means this machine opened the connection",
		"  PKTS/BYTES ↓ received, ↑ sent",
		"  RTT       time from this machine's SYN to the remote's SYN,ACK: one round trip across the network",
		"  TTL       hop limit left on packets from the remote; starts at 64, 128 or 255, minus one per router",
		"  PROCESS   the local program owning the socket; only visible for processes of your user",
		"  NAME      what the program asked for: the TLS server name, HTTP Host, or the DNS name that resolved here",
		"  ORIGIN    where the address block is registered, from a local database; city precision at best",
		"",
		h("Reading it"),
		"  Reverse DNS names the network owner (googleusercontent.com), NAME names the service (api.spotify.com).",
		"  Cloud and CDN addresses place the datacenter, never the company renting it or the person behind it.",
		"  Inbound SYN from a public address with no prior outbound traffic is someone on the internet knocking.",
		"  Lots of ARP from the router is normal cache refresh. Two MACs claiming one IP is not.",
	}
}
