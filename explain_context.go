package main

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// The functions below describe the selected item for Claude. They include
// headers, names and counters; packet payload bytes only for a selected packet.

func (m model) aiPreamble() string {
	var locals []string
	for ip := range m.agg.local {
		if !ip.IsLoopback() && !ip.IsLinkLocalUnicast() {
			locals = append(locals, ip.String())
		}
	}
	sort.Strings(locals)
	return fmt.Sprintf("Capture interface: %s. This computer's addresses: %s.\n\n", m.iface, strings.Join(locals, ", "))
}

func (m model) hostFacts(ip netip.Addr) string {
	hi := m.res.Get(ip)
	var b strings.Builder
	fmt.Fprintf(&b, "Address %s: kind %s", ip, hi.Kind)
	if hi.Kind == "public" {
		fmt.Fprintf(&b, ", origin %s", hi.Origin())
		if hi.ASN != "" {
			fmt.Fprintf(&b, " (%s)", hi.ASN)
		}
	}
	if hi.Name != "" {
		fmt.Fprintf(&b, ", reverse DNS %s", hi.Name)
	} else if hi.NameOK {
		b.WriteString(", no reverse DNS record")
	}
	b.WriteString(".\n")
	return b.String()
}

func portLabel(p uint16) string {
	if n := portName(p); n != "" {
		return fmt.Sprintf("%d (%s)", p, n)
	}
	return fmt.Sprint(p)
}

func (m model) aiFlow(f Flow) (title, prompt string) {
	var b strings.Builder
	b.WriteString(m.aiPreamble())
	fmt.Fprintf(&b, "Selected item: one %s flow (conversation).\n", f.Key.Proto)
	fmt.Fprintf(&b, "Direction of the first packet: %s (in = sent to this computer, out = sent by it, other = overheard broadcast or multicast).\n", f.Dir)
	fmt.Fprintf(&b, "Local end %s port %s. Remote end %s port %s.\n", f.Key.Local, portLabel(f.Key.LocalPort), f.Key.Remote, portLabel(f.Key.RemotePort))
	b.WriteString(m.hostFacts(f.Key.Remote))
	if f.Name != "" {
		fmt.Fprintf(&b, "Server name seen (TLS SNI, HTTP Host or DNS): %s.\n", f.Name)
	}
	if f.Proc != "" {
		fmt.Fprintf(&b, "Local process owning the socket: %s.\n", f.Proc)
	} else {
		b.WriteString("Local process: unknown (another user's process, or too short-lived).\n")
	}
	fmt.Fprintf(&b, "Received %d packets / %d bytes. Sent %d packets / %d bytes.\n", f.PktsIn, f.BytesIn, f.PktsOut, f.BytesOut)
	fmt.Fprintf(&b, "First seen %s, last seen %s (duration %s).\n", f.First.Format("15:04:05.000"), f.Last.Format("15:04:05.000"), f.Last.Sub(f.First).Round(1e6))
	if f.RTT != 0 {
		fmt.Fprintf(&b, "TCP handshake round-trip time: %s.\n", rttStr(f.RTT))
	}
	if f.TTL != 0 {
		fmt.Fprintf(&b, "TTL on packets from the remote: %d.\n", f.TTL)
	}
	if n := len(f.Events); n > 0 {
		b.WriteString("First packets (time since start, direction, TCP flags, payload bytes, note):\n")
		for i, e := range f.Events {
			if i == 25 {
				fmt.Fprintf(&b, "  ... %d more packets\n", n-25)
				break
			}
			arrow := "out"
			if e.Dir == DirIn || e.Dir == DirOther {
				arrow = "in"
			}
			fmt.Fprintf(&b, "  +%s %s %s %dB %s\n", fmtRel(e.T.Sub(f.First)), arrow, orDash(e.Flags), e.Len, e.Note)
		}
	}
	b.WriteString("\nWhat is this flow?")
	return "Ask Claude · " + flowTitle(f), b.String()
}

func (m model) aiHost(h Host) (title, prompt string) {
	var b strings.Builder
	b.WriteString(m.aiPreamble())
	b.WriteString("Selected item: one remote host, with all its traffic to and from this computer summed.\n")
	b.WriteString(m.hostFacts(h.IP))
	if len(h.Names) > 0 {
		fmt.Fprintf(&b, "Server names seen for it: %s.\n", strings.Join(topN(h.Names, 8), ", "))
	}
	if len(h.Procs) > 0 {
		fmt.Fprintf(&b, "Local processes that talked to it: %s.\n", strings.Join(topN(h.Procs, 6), ", "))
	}
	if h.MAC != "" {
		fmt.Fprintf(&b, "MAC address (from ARP): %s.\n", h.MAC)
	}
	fmt.Fprintf(&b, "Received %d packets / %d bytes. Sent %d packets / %d bytes. %d flows.\n", h.PktsIn, h.BytesIn, h.PktsOut, h.BytesOut, h.Flows)
	fmt.Fprintf(&b, "Protocols (packets): %s.\n", protoList(h.Protos))
	if len(h.Ports) > 0 {
		var ps []string
		for _, p := range topN(h.Ports, 8) {
			ps = append(ps, portLabel(p))
		}
		fmt.Fprintf(&b, "Ports on the remote side: %s.\n", strings.Join(ps, ", "))
		ps = ps[:0]
		for _, p := range topN(h.LocalPorts, 8) {
			ps = append(ps, portLabel(p))
		}
		fmt.Fprintf(&b, "Ports on this computer: %s.\n", strings.Join(ps, ", "))
	}
	if h.TTL != 0 {
		fmt.Fprintf(&b, "TTL on its packets: %d.\n", h.TTL)
	}
	fmt.Fprintf(&b, "First seen %s, last seen %s.\n", h.First.Format("15:04:05"), h.Last.Format("15:04:05"))
	b.WriteString("\nWho is this host and what is it doing with this computer?")
	return "Ask Claude · " + h.IP.String(), b.String()
}

func (m model) aiPacket(p Packet) (title, prompt string) {
	var b strings.Builder
	b.WriteString(m.aiPreamble())
	fmt.Fprintf(&b, "Selected item: one captured packet, direction %s, %d bytes on the wire, at %s.\n", p.Dir, p.Len, p.Time.Format("15:04:05.000"))
	fmt.Fprintf(&b, "Summary: %s %s -> %s. %s\n", p.Proto, addrPort(p.Src, p.SPort), addrPort(p.Dst, p.DPort), p.Info)
	remote := p.Src
	if p.Dir == DirOut || p.Dir == DirLocal {
		remote = p.Dst
	}
	if remote.IsValid() {
		b.WriteString(m.hostFacts(remote))
	}
	b.WriteString("Decoded layers:\n")
	hexLines := 0
	for _, l := range decodeTree(m.agg.Raw(p.ID), m.linkType) {
		if strings.HasPrefix(l, "▸ Hex dump") {
			b.WriteString("First bytes in hex:\n")
			hexLines = 1
			continue
		}
		if hexLines > 0 {
			if hexLines > 8 {
				b.WriteString("  ...\n")
				break
			}
			hexLines++
		}
		b.WriteString(l + "\n")
	}
	b.WriteString("\nWhat is this packet, and what do its fields mean?")
	return fmt.Sprintf("Ask Claude · packet %s %s", p.Time.Format("15:04:05.000"), p.Proto), b.String()
}

func (m model) aiNotice(n Notice) (title, prompt string) {
	var b strings.Builder
	b.WriteString(m.aiPreamble())
	fmt.Fprintf(&b, "Selected item: a notice raised by the tool at %s.\nKind: %s.\nText: %s\n", n.T.Format("15:04:05"), n.Kind, n.Text)
	for _, w := range strings.Fields(n.Text) {
		if ip, err := netip.ParseAddr(strings.Trim(w, "(),")); err == nil {
			b.WriteString(m.hostFacts(ip))
			for _, h := range m.snap.Hosts {
				if h.IP == ip {
					fmt.Fprintf(&b, "It sent %d packets / %d bytes and received %d / %d over %d flows. Remote ports: %s. Local ports: %s.\n",
						h.PktsIn, h.BytesIn, h.PktsOut, h.BytesOut, h.Flows, portList(h.Ports, 8), portList(h.LocalPorts, 8))
				}
			}
			break
		}
	}
	b.WriteString("\nWhat does this notice mean, and should I do anything about it?")
	return "Ask Claude · notice " + n.Kind, b.String()
}

// wrapText wraps plain text to width, keeping blank lines and list indents.
func wrapText(s string, width int) []string {
	if width < 20 {
		width = 20
	}
	var out []string
	for _, para := range strings.Split(s, "\n") {
		if strings.TrimSpace(para) == "" {
			out = append(out, "")
			continue
		}
		indent := para[:len(para)-len(strings.TrimLeft(para, " "))]
		if strings.HasPrefix(strings.TrimSpace(para), "- ") {
			indent += "  "
		}
		line := ""
		for _, w := range strings.Fields(para) {
			switch {
			case line == "":
				line = para[:len(para)-len(strings.TrimLeft(para, " "))] + w
			case len([]rune(line))+1+len([]rune(w)) > width:
				out = append(out, line)
				line = indent + w
			default:
				line += " " + w
			}
		}
		out = append(out, line)
	}
	return out
}
