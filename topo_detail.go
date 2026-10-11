package main

import (
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

func stripANSI(s string) string { return ansiRE.ReplaceAllString(s, "") }

// servicePorts explains what a device offering or using a port probably is.
var servicePorts = map[uint16]string{
	22:    "SSH",
	53:    "DNS server",
	80:    "web page",
	443:   "HTTPS",
	445:   "Windows file sharing",
	548:   "Apple file sharing",
	554:   "RTSP video (camera?)",
	631:   "IPP printer",
	1900:  "UPnP (TV, speaker, router)",
	3389:  "Remote Desktop",
	5353:  "mDNS",
	5355:  "LLMNR (Windows)",
	7000:  "AirPlay",
	8008:  "Google Cast",
	8009:  "Google Cast",
	9100:  "printer or node_exporter",
	32400: "Plex",
	41641: "Tailscale",
	57621: "Spotify Connect",
	62078: "iPhone/iPad sync",
}

type kv2 struct{ k, v string }

func detailRows(rows []kv2, width int) []string {
	var out []string
	for _, r := range rows {
		if r.v == "" {
			continue
		}
		if r.k == "" {
			out = append(out, "")
			if r.v != "-" {
				out = append(out, "  "+stSection.Render(r.v))
			}
			continue
		}
		wrapped := wrapText(r.v, max(20, width-20))
		for i, l := range wrapped {
			label := ""
			if i == 0 {
				label = r.k
			}
			out = append(out, fmt.Sprintf("  %s %s", stDim.Render(fmt.Sprintf("%-15s", label)), l))
		}
	}
	return out
}

// mapDetail builds the panel for one selected map object.
func (m model) mapDetail(key string) (string, []string) {
	tv := m.tv
	router, devs := m.buildDevices(tv)
	width := m.w - 2
	switch {
	case key == "inet":
		return "Internet", detailRows(m.inetRows(), width)
	case key == "router" && router != nil:
		return "Router " + tv.Gateway.String(), detailRows(m.routerRows(*router), width)
	case strings.HasPrefix(key, "hop:"):
		n, _ := strconv.Atoi(strings.TrimPrefix(key, "hop:"))
		for _, h := range tv.Hops {
			if h.N == n && !h.NoReply {
				return fmt.Sprintf("Hop %d  %s", n, h.IP), detailRows(m.hopRows(h), width)
			}
		}
	case strings.HasPrefix(key, "dev:"):
		for _, d := range devs {
			if devKey(d) == key {
				return "Device " + firstNonEmpty(d.Name, d.MAC), detailRows(m.deviceRows(d), width)
			}
		}
	case strings.HasPrefix(key, "ts:"):
		for _, p := range tv.Tailscale {
			if "ts:"+p.Name == key {
				return "Tailscale peer " + p.Name, detailRows(m.tsRows(p), width)
			}
		}
	}
	return "Map", []string{"  This item is no longer on the map."}
}

func ipList(ips []netip.Addr) string {
	var s []string
	for _, ip := range ips {
		s = append(s, ip.String())
	}
	return strings.Join(s, ", ")
}

// flowsWith summarises captured conversations involving any of the addresses.
func (m model) flowsWith(ips []netip.Addr) (talk []string, ports map[uint16]bool) {
	set := map[netip.Addr]bool{}
	for _, ip := range ips {
		set[ip] = true
	}
	ports = map[uint16]bool{}
	var fl []Flow
	for _, f := range m.snap.Flows {
		if set[f.Key.Remote] {
			fl = append(fl, f)
			if f.Key.RemotePort != 0 {
				ports[f.Key.RemotePort] = true
			}
		}
	}
	sort.Slice(fl, func(i, j int) bool { return fl[i].Bytes() > fl[j].Bytes() })
	for i, f := range fl {
		if i == 8 {
			talk = append(talk, fmt.Sprintf("… and %d more", len(fl)-8))
			break
		}
		line := fmt.Sprintf("%s %s ⇄ %s · %s · %s", f.Key.Proto, portLabel(f.Key.RemotePort), portLabel(f.Key.LocalPort), humanBytes(f.Bytes()), age(f.Last))
		if f.Dir == DirOther {
			line += " · broadcast"
		}
		if f.Proc != "" {
			line += " · " + f.Proc
		}
		talk = append(talk, line)
	}
	return talk, ports
}

func portHints(ports map[uint16]bool) string {
	var ps []int
	for p := range ports {
		if _, ok := servicePorts[p]; ok {
			ps = append(ps, int(p))
		}
	}
	sort.Ints(ps)
	var out []string
	for _, p := range ps {
		out = append(out, fmt.Sprintf("%d %s", p, servicePorts[uint16(p)]))
	}
	return strings.Join(out, ", ")
}

func (m model) deviceRows(d mapDevice) []kv2 {
	tv := m.tv
	var names []string
	if d.Name != "" {
		names = append(names, d.Name)
	}
	for _, ip := range d.IPs {
		if n := m.snap.LANNames[ip]; n != "" && strings.TrimSuffix(n, ".local") != d.Name {
			names = append(names, n+" (mDNS)")
		}
		if n := m.res.Get(ip).Name; n != "" && n != d.Name {
			names = append(names, n+" (reverse DNS)")
		}
	}
	nameVal := firstNonEmpty(strings.Join(names, ", "), "none seen")
	maker := firstNonEmpty(d.Vendor, "unknown")
	if d.Private {
		maker = "hidden (random MAC)"
	}
	rows := []kv2{
		{"name", nameVal},
		{"addresses", ipList(d.IPs)},
		{"MAC", d.MAC},
		{"maker", maker},
		{"OS hint", d.Hint},
	}
	if m.book != nil {
		if k, ok := m.book.Get(d.MAC); ok {
			rows = append(rows, kv2{"first seen", k.First.Format("2006-01-02 15:04")})
		}
	}
	if d.Self {
		if tv.Replay {
			rows = append(rows, kv2{"role", "recorded " + tv.Iface})
		} else {
			rows = append(rows, kv2{"role", "this machine, " + tv.Iface})
		}
		if len(tv.DNS) > 0 {
			rows = append(rows, kv2{"DNS servers", m.dnsText()})
		}
		var procs []string
		byProc := map[string]uint64{}
		for _, f := range m.snap.Flows {
			if f.Proc != "" {
				byProc[f.Proc] += f.Bytes()
			}
		}
		for _, p := range topN(byProc, 5) {
			procs = append(procs, fmt.Sprintf("%s %s", p, humanBytes(byProc[p])))
		}
		rows = append(rows, kv2{"programs", strings.Join(procs, ", ")})
		s := m.snap.Stats
		rows = append(rows, kv2{"traffic", fmt.Sprintf("↓%s ↑%s, %s overheard", humanBytes(s.BytesIn), humanBytes(s.BytesOut), humanBytes(s.BytesOther))})
		return rows
	}
	if d.ARPOnly {
		rows = append(rows, kv2{"traffic", "none captured (ARP table only)"})
	} else {
		rows = append(rows, kv2{"traffic", fmt.Sprintf("↓%s ↑%s, last %s", humanBytes(d.BytesTo), humanBytes(d.BytesFrom), age(d.Last))})
	}
	talk, ports := m.flowsWith(d.IPs)
	if len(talk) > 0 {
		rows = append(rows, kv2{"", "Conversations"})
		for _, t := range talk {
			rows = append(rows, kv2{" ", t})
		}
	}
	if h := portHints(ports); h != "" {
		rows = append(rows, kv2{"ports", h})
	}
	return rows
}

func (m model) dnsText() string {
	var parts []string
	for _, ip := range m.tv.DNS {
		m.res.Enqueue(ip)
		hi := m.res.Get(ip)
		s := ip.String()
		switch {
		case ip == m.tv.Gateway:
			s += " (router)"
		case hi.Kind == "public" && hi.Org != "":
			s += " (" + hi.Org + ")"
		}
		parts = append(parts, s)
	}
	return strings.Join(parts, ", ")
}

func (m model) routerRows(r mapDevice) []kv2 {
	tv := m.tv
	rows := []kv2{
		{"role", "default gateway"},
		{"address", ipList(r.IPs)},
		{"name", r.Name},
		{"MAC", r.MAC},
		{"maker", firstNonEmpty(r.Vendor, "unknown")},
	}
	for _, h := range tv.Hops {
		if h.N == 1 && h.IP == tv.Gateway && h.RTT > 0 {
			rows = append(rows, kv2{"latency", rttStr(h.RTT)})
		}
	}
	if w := tv.WiFi; w != nil && w.BSSID != "" {
		ap := "“" + w.SSID + "” via access point " + w.BSSID
		if sameDevice(r.MAC, w.BSSID) {
			ap = "“" + w.SSID + "”, built-in radio " + w.BSSID
		}
		rows = append(rows, kv2{"Wi-Fi", ap})
	}
	dns := "no"
	for _, ip := range tv.DNS {
		if ip == tv.Gateway {
			dns = "yes"
		}
	}
	if dns == "no" && len(tv.DNS) > 0 {
		dns = "no, you use " + m.dnsText()
	}
	rows = append(rows, kv2{"DNS server", dns})
	rows = append(rows, kv2{"traffic", fmt.Sprintf("↓%s ↑%s", humanBytes(r.BytesFrom), humanBytes(r.BytesTo))})
	rows = append(rows, kv2{"admin page", "http://" + tv.Gateway.String()})
	return rows
}

func (m model) hopRows(h Hop) []kv2 {
	hi := m.res.Get(h.IP)
	return []kv2{
		{"hop", fmt.Sprintf("%d (to %s)", h.N, m.tv.Target)},
		{"address", h.IP.String()},
		{"reverse DNS", hi.Name},
		{"operator", strings.TrimSpace(hi.Org + " " + hi.ASN)},
		{"location", strings.Trim(hi.City+", "+hi.Country, ", ")},
		{"round trip", rttStr(h.RTT)},
	}
}

func (m model) inetRows() []kv2 {
	tv := m.tv
	var rows []kv2
	for _, p := range tv.Tailscale {
		if p.Self && p.Public.IsValid() {
			m.res.Enqueue(p.Public)
			rows = append(rows, kv2{"public IP", p.Public.String()})
		}
	}
	isp := ""
	last := Hop{}
	for _, h := range tv.Hops {
		if h.NoReply {
			continue
		}
		last = h
		if hi := m.res.Get(h.IP); isp == "" && hi.Kind == "public" && hi.Org != "" {
			isp = hi.Org
		}
	}
	rows = append(rows, kv2{"ISP", firstNonEmpty(isp, "unknown")})
	if last.IP.IsValid() {
		rows = append(rows, kv2{"route", fmt.Sprintf("%d hops to %s, %s", last.N, tv.Target, rttStr(last.RTT))})
	}
	if len(tv.DNS) > 0 {
		rows = append(rows, kv2{"DNS servers", m.dnsText()})
	}
	var in, out uint64
	byOrg, byCountry := map[string]uint64{}, map[string]uint64{}
	for _, h := range m.snap.Hosts {
		hi := m.res.Get(h.IP)
		if hi.Kind != "public" {
			continue
		}
		in += h.BytesIn
		out += h.BytesOut
		byOrg[firstNonEmpty(hi.Org, hi.ASN, "unknown")] += h.Bytes()
		byCountry[firstNonEmpty(hi.Country, "?")] += h.Bytes()
	}
	rows = append(rows, kv2{"traffic", fmt.Sprintf("↓%s ↑%s", humanBytes(in), humanBytes(out))})
	var orgs, countries []string
	for _, k := range topN(byOrg, 6) {
		orgs = append(orgs, fmt.Sprintf("%s %s", k, humanBytes(byOrg[k])))
	}
	for _, k := range topN(byCountry, 6) {
		countries = append(countries, fmt.Sprintf("%s %s", k, humanBytes(byCountry[k])))
	}
	rows = append(rows, kv2{"networks", strings.Join(orgs, ", ")}, kv2{"countries", strings.Join(countries, ", ")})
	return rows
}

func (m model) tsRows(p TSPeer) []kv2 {
	rows := []kv2{
		{"name", p.Name},
		{"system", p.OS},
		{"addresses", ipList(p.IPs)},
		{"status", p.Path()},
		{"home relay", p.Relay},
		{"public IP", func() string {
			if p.Public.IsValid() {
				return p.Public.String()
			}
			return ""
		}()},
	}
	var tsIPs []netip.Addr
	tsIPs = append(tsIPs, p.IPs...)
	if talk, _ := m.flowsWith(tsIPs); len(talk) > 0 {
		rows = append(rows, kv2{"", "Conversations"})
		for _, t := range talk {
			rows = append(rows, kv2{" ", t})
		}
	}
	return rows
}

// aiMapObject asks about the selected object, sending the same facts the panel shows.
func (m model) aiMapObject(key string) (string, string) {
	title, lines := m.mapDetail(key)
	var b strings.Builder
	b.WriteString(m.aiPreamble())
	fmt.Fprintf(&b, "Selected item on the network map: %s.\n", title)
	for _, l := range lines {
		if s := strings.TrimSpace(stripANSI(l)); s != "" {
			b.WriteString(s + "\n")
		}
	}
	if w := m.tv.WiFi; w != nil {
		fmt.Fprintf(&b, "This machine is on Wi-Fi %q, gateway %s.\n", w.SSID, m.tv.Gateway)
	}
	b.WriteString("\nWhat is this, and what is it doing on my network?")
	return "Ask Claude · " + title, b.String()
}
