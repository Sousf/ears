package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

type Capture struct {
	Iface   string
	Filter  string
	SnapLen int
	Promisc bool
	WriteTo string // optional pcap output path

	handle *pcap.Handle
	file   *os.File
	bw     *bufio.Writer
	pw     *pcapgo.Writer
	done   chan struct{}
}

func (c *Capture) Open() error {
	inactive, err := pcap.NewInactiveHandle(c.Iface)
	if err != nil {
		return err
	}
	defer inactive.CleanUp()
	if err := inactive.SetSnapLen(c.SnapLen); err != nil {
		return err
	}
	if err := inactive.SetPromisc(c.Promisc); err != nil {
		return err
	}
	// A short timeout lets the read loop notice cancellation.
	if err := inactive.SetTimeout(250 * time.Millisecond); err != nil {
		return err
	}
	_ = inactive.SetImmediateMode(true)
	h, err := inactive.Activate()
	if err != nil {
		return fmt.Errorf("open %s: %w", c.Iface, err)
	}
	if c.Filter != "" {
		if err := h.SetBPFFilter(c.Filter); err != nil {
			h.Close()
			return fmt.Errorf("bpf filter %q: %w", c.Filter, err)
		}
	}
	c.handle = h
	if c.WriteTo != "" {
		if err := c.openWriter(h.LinkType()); err != nil {
			h.Close()
			return err
		}
	}
	c.done = make(chan struct{})
	return nil
}

// openWriter creates the pcap output file.
func (c *Capture) openWriter(lt layers.LinkType) error {
	f, err := os.Create(c.WriteTo)
	if err != nil {
		return fmt.Errorf("pcap output: %w", err)
	}
	c.file = f
	c.bw = bufio.NewWriterSize(f, 1<<16)
	c.pw = pcapgo.NewWriter(c.bw)
	if err := c.pw.WriteFileHeader(uint32(c.SnapLen), lt); err != nil {
		f.Close()
		return fmt.Errorf("pcap output: %w", err)
	}
	return nil
}

func (c *Capture) LinkType() layers.LinkType {
	if c.handle == nil {
		return layers.LinkTypeEthernet
	}
	return c.handle.LinkType()
}

// Close stops reading and flushes the pcap file, if any. Call after cancelling Run's context.
func (c *Capture) Close() {
	if c.done != nil {
		select {
		case <-c.done:
		case <-time.After(2 * time.Second):
		}
	}
	if c.bw != nil {
		c.bw.Flush()
	}
	if c.file != nil {
		c.file.Close()
	}
	if c.handle != nil {
		c.handle.Close()
	}
}

// Dropped returns the kernel-side drop counter, or -1 if unavailable.
func (c *Capture) Dropped() int {
	if c.handle == nil {
		return -1
	}
	s, err := c.handle.Stats()
	if err != nil {
		return -1
	}
	return s.PacketsDropped + s.PacketsIfDropped
}

// Run reads frames until ctx is done and sends decoded summaries to out.
func (c *Capture) Run(ctx context.Context, out chan<- Packet, errs chan<- error) {
	defer close(c.done)
	opts := gopacket.DecodeOptions{Lazy: true, NoCopy: true}
	lt := c.handle.LinkType()
	for ctx.Err() == nil {
		data, ci, err := c.handle.ZeroCopyReadPacketData()
		if err != nil {
			if errors.Is(err, pcap.NextErrorTimeoutExpired) {
				continue
			}
			if ctx.Err() != nil {
				return
			}
			select {
			case errs <- err:
			default:
			}
			return
		}
		if c.pw != nil {
			_ = c.pw.WritePacket(ci, data)
		}
		p, ok := decode(data, lt, ci, opts)
		if !ok {
			continue
		}
		select {
		case out <- p:
		case <-ctx.Done():
			return
		}
	}
}

func decode(data []byte, lt layers.LinkType, ci gopacket.CaptureInfo, opts gopacket.DecodeOptions) (Packet, bool) {
	pkt := gopacket.NewPacket(data, lt, opts)
	p := Packet{Time: ci.Timestamp, Len: ci.Length}
	if l := pkt.Layer(layers.LayerTypeEthernet); l != nil {
		eth := l.(*layers.Ethernet)
		p.SrcMAC, p.DstMAC = eth.SrcMAC.String(), eth.DstMAC.String()
	}

	if l := pkt.Layer(layers.LayerTypeARP); l != nil {
		a := l.(*layers.ARP)
		p.Proto = "ARP"
		p.Src = toAddr(a.SourceProtAddress)
		p.Dst = toAddr(a.DstProtAddress)
		p.SrcMAC = net.HardwareAddr(a.SourceHwAddress).String()
		if a.Operation == layers.ARPRequest {
			p.Info = fmt.Sprintf("who-has %s tell %s", p.Dst, p.Src)
		} else {
			p.Info = fmt.Sprintf("%s is-at %s", p.Src, p.SrcMAC)
		}
		p.Raw = copyRaw(data)
		return p, true
	}

	switch nl := pkt.NetworkLayer().(type) {
	case *layers.IPv4:
		p.Src, p.Dst = toAddr(nl.SrcIP), toAddr(nl.DstIP)
		p.Proto = nl.Protocol.String()
		p.TTL = nl.TTL
	case *layers.IPv6:
		p.Src, p.Dst = toAddr(nl.SrcIP), toAddr(nl.DstIP)
		p.Proto = nl.NextHeader.String()
		p.TTL = nl.HopLimit
	default:
		return p, false
	}

	switch tl := pkt.TransportLayer().(type) {
	case *layers.TCP:
		p.Proto = "TCP"
		p.SPort, p.DPort = uint16(tl.SrcPort), uint16(tl.DstPort)
		p.Flags = tcpFlags(tl)
		p.Seq, p.Ack = tl.Seq, tl.Ack
		p.Payload = len(tl.Payload)
		p.Info = p.Flags
		if len(tl.Payload) > 0 {
			if name := tlsServerName(tl.Payload); name != "" {
				p.Name = name
				p.Info += "  TLS ClientHello " + name
			} else if host, line := httpRequest(tl.Payload); line != "" {
				p.Name = host
				p.Info += "  HTTP " + line
			}
		}
	case *layers.UDP:
		p.Proto = "UDP"
		p.SPort, p.DPort = uint16(tl.SrcPort), uint16(tl.DstPort)
		p.Payload = len(tl.Payload)
		if isDNSPort(p.SPort) || isDNSPort(p.DPort) {
			var d layers.DNS
			if err := d.DecodeFromBytes(tl.Payload, gopacket.NilDecodeFeedback); err == nil {
				p.Info = dnsInfo(&d)
				if p.SPort == 53 || p.DPort == 53 {
					p.DNS = dnsMsg(&d)
				}
				if p.SPort == 5353 && d.QR {
					p.LANName = mdnsNames(&d)
				}
			}
		}
		if (p.SPort == 68 && p.DPort == 67) || (p.SPort == 67 && p.DPort == 68) {
			var d layers.DHCPv4
			if err := d.DecodeFromBytes(tl.Payload, gopacket.NilDecodeFeedback); err == nil {
				p.DHCP = dhcpInfo(&d)
				p.Info = "DHCP " + d.Operation.String()
				if p.DHCP != nil && p.DHCP.Hostname != "" {
					p.Info += " from " + p.DHCP.Hostname
				}
			}
		}
	}
	if l := pkt.Layer(layers.LayerTypeICMPv4); l != nil {
		p.Proto = "ICMP"
		p.Info = l.(*layers.ICMPv4).TypeCode.String()
	}
	if l := pkt.Layer(layers.LayerTypeICMPv6); l != nil {
		p.Proto = "ICMPv6"
		p.Info = l.(*layers.ICMPv6).TypeCode.String()
	}
	p.Raw = copyRaw(data)
	return p, true
}

func copyRaw(data []byte) []byte {
	n := min(len(data), rawCap)
	raw := make([]byte, n)
	copy(raw, data)
	return raw
}

func isDNSPort(p uint16) bool { return p == 53 || p == 5353 || p == 5355 }

func toAddr(b []byte) netip.Addr {
	a, _ := netip.AddrFromSlice(b)
	return a.Unmap()
}

// flagNames holds every combination of the six TCP flags, built once so
// labelling a packet allocates nothing.
var flagNames = func() (t [64]string) {
	names := []string{"SYN", "ACK", "PSH", "FIN", "RST", "URG"}
	for bits := range t {
		var f []string
		for i, n := range names {
			if bits&(1<<i) != 0 {
				f = append(f, n)
			}
		}
		t[bits] = strings.Join(f, ",")
	}
	return t
}()

func tcpFlags(t *layers.TCP) string {
	bits := 0
	for i, set := range []bool{t.SYN, t.ACK, t.PSH, t.FIN, t.RST, t.URG} {
		if set {
			bits |= 1 << i
		}
	}
	return flagNames[bits]
}

func dnsInfo(d *layers.DNS) string {
	if len(d.Questions) == 0 {
		return "DNS"
	}
	q := d.Questions[0]
	kind := "query"
	if d.QR {
		kind = "reply"
	}
	s := fmt.Sprintf("DNS %s %s %s", kind, q.Type, string(q.Name))
	if d.QR {
		var ans []string
		for _, a := range d.Answers {
			if a.IP != nil {
				ans = append(ans, a.IP.String())
			} else if len(a.CNAME) > 0 {
				ans = append(ans, string(a.CNAME))
			}
			if len(ans) == 3 {
				break
			}
		}
		if len(ans) > 0 {
			s += " -> " + strings.Join(ans, ", ")
		}
	}
	return s
}

// dnsMsg summarises a unicast DNS query or reply for the DNS log.
func dnsMsg(d *layers.DNS) *DNSMsg {
	if len(d.Questions) == 0 {
		return nil
	}
	q := d.Questions[0]
	m := &DNSMsg{Reply: d.QR, Name: strings.TrimSuffix(string(q.Name), "."), Type: q.Type.String()}
	if !d.QR {
		return m
	}
	if d.ResponseCode != layers.DNSResponseCodeNoErr {
		m.Rcode = d.ResponseCode.String()
	}
	for _, a := range d.Answers {
		switch {
		case a.IP != nil:
			if ip := toAddr(a.IP); ip.IsValid() {
				m.Addrs = append(m.Addrs, ip)
			}
		case len(a.CNAME) > 0:
			m.CNAMEs = append(m.CNAMEs, string(a.CNAME))
		}
	}
	return m
}

// mdnsNames lists the .local names an mDNS response announces for addresses.
func mdnsNames(d *layers.DNS) []NameAddr {
	var out []NameAddr
	for _, rrs := range [][]layers.DNSResourceRecord{d.Answers, d.Additionals} {
		for _, a := range rrs {
			if (a.Type != layers.DNSTypeA && a.Type != layers.DNSTypeAAAA) || a.IP == nil {
				continue
			}
			name := strings.TrimSuffix(string(a.Name), ".")
			if ip := toAddr(a.IP); ip.IsValid() && strings.HasSuffix(name, ".local") {
				out = append(out, NameAddr{Name: name, Addr: ip})
			}
		}
	}
	return out
}

// dhcpInfo pulls the client hostname and vendor class out of a DHCP request.
func dhcpInfo(d *layers.DHCPv4) *DHCPInfo {
	if d.Operation != layers.DHCPOpRequest {
		return nil
	}
	info := &DHCPInfo{MAC: d.ClientHWAddr.String()}
	for _, o := range d.Options {
		switch o.Type {
		case layers.DHCPOptHostname:
			info.Hostname = string(o.Data)
		case layers.DHCPOptClassID:
			info.Vendor = string(o.Data)
		}
	}
	if info.Hostname == "" && info.Vendor == "" {
		return nil
	}
	return info
}

// ListInterfaces prints capture-capable interfaces with their addresses.
func ListInterfaces() (string, error) {
	devs, err := pcap.FindAllDevs()
	if err != nil {
		return "", err
	}
	var b strings.Builder
	for _, d := range devs {
		fmt.Fprintf(&b, "%-14s", d.Name)
		var addrs []string
		for _, a := range d.Addresses {
			addrs = append(addrs, a.IP.String())
		}
		b.WriteString(strings.Join(addrs, " "))
		if d.Description != "" {
			b.WriteString("  (" + d.Description + ")")
		}
		b.WriteByte('\n')
	}
	return b.String(), nil
}
