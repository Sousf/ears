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
	22:    "SSH remote login (a computer or server)",
	53:    "DNS (it answers name lookups)",
	80:    "a web page, often an admin interface",
	443:   "HTTPS",
	445:   "Windows file sharing (SMB)",
	548:   "Apple file sharing",
	554:   "RTSP video streaming (cameras, media boxes)",
	631:   "IPP printing",
	1900:  "UPnP discovery (TVs, speakers, consoles, routers)",
	3389:  "Windows Remote Desktop",
	5353:  "mDNS/Bonjour (Apple, Google, printers and smart devices announce themselves)",
	5355:  "LLMNR name lookups (usually Windows)",
	7000:  "AirPlay",
	8008:  "Google Cast",
	8009:  "Google Cast (Chromecast, Nest, Android TV)",
	9100:  "raw printing, or Prometheus node_exporter on a server",
	32400: "Plex media server",
	41641: "Tailscale",
	57621: "Spotify Connect",
	62078: "iPhone or iPad sync service",
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
		dir := "with this machine"
		if f.Dir == DirOther {
			dir = "broadcast, overheard"
		}
		line := fmt.Sprintf("%s their port %s, our port %s · %s · %s, last %s", f.Key.Proto, portLabel(f.Key.RemotePort), portLabel(f.Key.LocalPort),
			humanBytes(f.Bytes()), dir, age(f.Last))
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
		out = append(out, fmt.Sprintf("%d: %s", p, servicePorts[uint16(p)]))
	}
	return strings.Join(out, ". ")
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
	nameVal := strings.Join(names, ", ")
	if nameVal == "" {
		nameVal = "none seen yet. Devices name themselves over mDNS or DHCP; this one has not while ears was running."
	}
	maker := firstNonEmpty(d.Vendor, "not in the vendor list")
	if d.Private {
		maker = "hidden: the MAC is randomised (locally administered), which phones, tablets and laptops do for privacy"
	} else if len(d.MAC) >= 8 {
		maker += " (from the prefix " + d.MAC[:8] + ")"
	}
	rows := []kv2{
		{"name", nameVal},
		{"addresses", ipList(d.IPs)},
		{"MAC", d.MAC},
		{"maker", maker},
		{"OS hint", d.Hint},
	}
	if d.Self {
		rows = append(rows, kv2{"role", "this machine, on " + tv.Iface})
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
		for _, p := range topKeys(byProc, 5) {
			procs = append(procs, fmt.Sprintf("%s %s", p, humanBytes(byProc[p])))
		}
		rows = append(rows, kv2{"top programs", strings.Join(procs, ", ")})
		s := m.snap.Stats
		rows = append(rows, kv2{"traffic", fmt.Sprintf("%s in, %s out, %s overheard this session", humanBytes(s.BytesIn), humanBytes(s.BytesOut), humanBytes(s.BytesOther))})
		return rows
	}
	if d.ARPOnly {
		rows = append(rows, kv2{"seen", "only in the kernel's ARP table: this machine exchanged packets with it at some point, but ears has not captured any of its traffic yet"})
	} else {
		rows = append(rows, kv2{"traffic", fmt.Sprintf("%s sent to it, %s sent by it, last %s ago", humanBytes(d.BytesTo), humanBytes(d.BytesFrom), age(d.Last))})
	}
	talk, ports := m.flowsWith(d.IPs)
	if len(talk) > 0 {
		rows = append(rows, kv2{"", "Conversations"})
		for _, t := range talk {
			rows = append(rows, kv2{" ", t})
		}
	}
	if h := portHints(ports); h != "" {
		rows = append(rows, kv2{"", "What its ports suggest"}, kv2{" ", h})
	}
	rows = append(rows, kv2{"", "-"}, kv2{" ", stDim.Render("Press a to ask Claude what this device probably is.")})
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
			s += " (your router)"
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
		{"role", "default gateway: every packet for an address outside " + tv.Subnet.String() + " goes here first, and it forwards it to your ISP"},
		{"address", ipList(r.IPs)},
		{"MAC", r.MAC},
		{"maker", firstNonEmpty(r.Vendor, "not in the vendor list")},
	}
	if r.Name != "" {
		rows = append(rows, kv2{"name", r.Name})
	}
	for _, h := range tv.Hops {
		if h.N == 1 && h.IP == tv.Gateway && h.RTT > 0 {
			rows = append(rows, kv2{"latency", rttStr(h.RTT) + " round trip from this machine. Over Wi-Fi a few milliseconds is normal; wired is usually under 1 ms."})
		}
	}
	if w := tv.WiFi; w != nil && w.BSSID != "" {
		ap := "a separate access point " + w.BSSID
		if sameDevice(r.MAC, w.BSSID) {
			ap = "its own radio, BSSID " + w.BSSID + " (the router numbers its interfaces consecutively)"
		}
		rows = append(rows, kv2{"Wi-Fi", fmt.Sprintf("“%s” through %s", w.SSID, ap)})
	}
	isDNS := false
	for _, ip := range tv.DNS {
		if ip == tv.Gateway {
			isDNS = true
		}
	}
	if isDNS {
		rows = append(rows, kv2{"DNS", "this machine asks the router to look up names"})
	} else if len(tv.DNS) > 0 {
		rows = append(rows, kv2{"DNS", "not used for name lookups: this machine asks " + m.dnsText() + " directly"})
	}
	rows = append(rows, kv2{"traffic", fmt.Sprintf("%s arrived through it and %s left through it this session. Internet traffic has the router's MAC on it, so this is nearly all of it.", humanBytes(r.BytesFrom), humanBytes(r.BytesTo))})
	rows = append(rows, kv2{"admin page", "most routers serve one at http://" + tv.Gateway.String()})
	return rows
}

func (m model) hopRows(h Hop) []kv2 {
	hi := m.res.Get(h.IP)
	where := ""
	if hi.City != "" || hi.Country != "" {
		where = strings.Trim(hi.City+", "+hi.Country, ", ")
	}
	rows := []kv2{
		{"hop", fmt.Sprintf("%d of the path to %s", h.N, m.tv.Target)},
		{"address", h.IP.String()},
		{"reverse DNS", firstNonEmpty(hi.Name, "none")},
		{"operator", strings.TrimSpace(hi.Org + " " + hi.ASN)},
		{"location", where},
		{"round trip", rttStr(h.RTT) + " from this machine to this router and back"},
		{"", "How this was found"},
		{" ", fmt.Sprintf("tracepath sent a probe with a time-to-live of %d. Each router subtracts one, and the router that takes it to zero drops the probe and replies with an ICMP \"time exceeded\" message. This router sent that reply, which reveals its address.", h.N)},
	}
	if hi.Name != "" {
		rows = append(rows, kv2{" ", "Network operators often put the router's location and role in its name, like a city code or \"edge\" and \"core\"."})
	}
	return rows
}

func (m model) inetRows() []kv2 {
	tv := m.tv
	var rows []kv2
	for _, p := range tv.Tailscale {
		if p.Self && p.Public.IsValid() {
			m.res.Enqueue(p.Public)
			rows = append(rows, kv2{"public address", p.Public.String() + " (as Tailscale sees it). The whole LAN shares it: the router rewrites addresses on the way out (NAT)."})
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
	rows = append(rows, kv2{"ISP", firstNonEmpty(isp, "unknown until the trace finishes and the GeoIP database names the first public hop")})
	if last.IP.IsValid() {
		rows = append(rows, kv2{"trace", fmt.Sprintf("%d hops to %s, %s round trip at the last router that answered", last.N, tv.Target, rttStr(last.RTT))})
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
	rows = append(rows, kv2{"traffic", fmt.Sprintf("%s down and %s up with internet addresses this session", humanBytes(in), humanBytes(out))})
	var orgs, countries []string
	for _, k := range topKeys(byOrg, 6) {
		orgs = append(orgs, fmt.Sprintf("%s %s", k, humanBytes(byOrg[k])))
	}
	for _, k := range topKeys(byCountry, 6) {
		countries = append(countries, fmt.Sprintf("%s %s", k, humanBytes(byCountry[k])))
	}
	rows = append(rows, kv2{"top networks", strings.Join(orgs, ", ")}, kv2{"top countries", strings.Join(countries, ", ")})
	return rows
}

func (m model) tsRows(p TSPeer) []kv2 {
	rows := []kv2{
		{"name", p.Name},
		{"system", p.OS},
		{"addresses", ipList(p.IPs)},
		{"status", p.Path()},
		{"home relay", p.Relay},
	}
	switch {
	case p.Self:
		rows = append(rows, kv2{"about", "this machine's own entry. Tailscale gives every device a 100.x address that works from anywhere, carried inside encrypted WireGuard tunnels."})
	case p.Active && p.Direct != "":
		rows = append(rows, kv2{"about", "packets go straight to the peer's address over an encrypted WireGuard tunnel"})
	case p.Active:
		rows = append(rows, kv2{"about", "no direct path was found, so packets bounce off Tailscale's relay server in " + p.Relay + ". That works but adds latency."})
	case p.Online:
		rows = append(rows, kv2{"about", "online but nothing is being sent now. Tailscale opens a tunnel, direct if it can, when traffic starts."})
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
		if s := strings.TrimSpace(stripANSI(l)); s != "" && !strings.HasPrefix(s, "Press a") {
			b.WriteString(s + "\n")
		}
	}
	if w := m.tv.WiFi; w != nil {
		fmt.Fprintf(&b, "This machine is on Wi-Fi %q, gateway %s.\n", w.SSID, m.tv.Gateway)
	}
	b.WriteString("\nWhat is this, and what is it doing on my network?")
	return "Ask Claude · " + title, b.String()
}
