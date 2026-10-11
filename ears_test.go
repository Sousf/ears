package main

import (
	"encoding/binary"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

var (
	macA = net.HardwareAddr{0x02, 0, 0, 0, 0, 1}
	macB = net.HardwareAddr{0x02, 0, 0, 0, 0, 2}
	opts = gopacket.DecodeOptions{Lazy: true, NoCopy: true}
)

func serialize(t *testing.T, ls ...gopacket.SerializableLayer) []byte {
	t.Helper()
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ls...); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func tcpFrame(t *testing.T, src, dst string, sport, dport uint16, flags string, payload []byte) []byte {
	ip := &layers.IPv4{Version: 4, TTL: 57, Protocol: layers.IPProtocolTCP, SrcIP: net.ParseIP(src), DstIP: net.ParseIP(dst)}
	tcp := &layers.TCP{SrcPort: layers.TCPPort(sport), DstPort: layers.TCPPort(dport), Window: 1024, Seq: 1000}
	for _, f := range strings.Split(flags, ",") {
		switch f {
		case "SYN":
			tcp.SYN = true
		case "ACK":
			tcp.ACK = true
		case "PSH":
			tcp.PSH = true
		case "FIN":
			tcp.FIN = true
		case "RST":
			tcp.RST = true
		}
	}
	tcp.SetNetworkLayerForChecksum(ip)
	return serialize(t, &layers.Ethernet{SrcMAC: macA, DstMAC: macB, EthernetType: layers.EthernetTypeIPv4}, ip, tcp, gopacket.Payload(payload))
}

func dnsFrame(t *testing.T, src, dst string, reply bool) []byte {
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: net.ParseIP(src), DstIP: net.ParseIP(dst)}
	udp := &layers.UDP{SrcPort: 40000, DstPort: 53}
	if reply {
		udp.SrcPort, udp.DstPort = 53, 40000
	}
	udp.SetNetworkLayerForChecksum(ip)
	dns := &layers.DNS{ID: 1, RD: true, QR: reply, Questions: []layers.DNSQuestion{{Name: []byte("example.com"), Type: layers.DNSTypeA, Class: layers.DNSClassIN}}}
	if reply {
		dns.Answers = []layers.DNSResourceRecord{{Name: []byte("example.com"), Type: layers.DNSTypeA, Class: layers.DNSClassIN, TTL: 60, IP: net.ParseIP("203.0.113.5").To4()}}
	}
	return serialize(t, &layers.Ethernet{SrcMAC: macA, DstMAC: macB, EthernetType: layers.EthernetTypeIPv4}, ip, udp, dns)
}

func arpFrame(t *testing.T, senderMAC net.HardwareAddr, senderIP, targetIP []byte) []byte {
	arp := &layers.ARP{AddrType: layers.LinkTypeEthernet, Protocol: layers.EthernetTypeIPv4, HwAddressSize: 6, ProtAddressSize: 4,
		Operation: layers.ARPRequest, SourceHwAddress: senderMAC, SourceProtAddress: senderIP,
		DstHwAddress: make([]byte, 6), DstProtAddress: targetIP}
	return serialize(t, &layers.Ethernet{SrcMAC: senderMAC, DstMAC: net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, EthernetType: layers.EthernetTypeARP}, arp)
}

// clientHello builds a minimal TLS ClientHello carrying an SNI extension.
func clientHello(name string) []byte {
	sni := []byte{0, 0}  // list length placeholder
	sni = append(sni, 0) // host_name
	sni = binary.BigEndian.AppendUint16(sni, uint16(len(name)))
	sni = append(sni, name...)
	binary.BigEndian.PutUint16(sni, uint16(len(sni)-2))
	ext := binary.BigEndian.AppendUint16(nil, 0) // type server_name
	ext = binary.BigEndian.AppendUint16(ext, uint16(len(sni)))
	ext = append(ext, sni...)
	// pad with another extension before SNI to exercise the loop
	other := []byte{0x00, 0x17, 0x00, 0x00} // extended_master_secret, empty
	exts := append(other, ext...)

	body := []byte{3, 3}
	body = append(body, make([]byte, 32)...) // random
	body = append(body, 0)                   // session id
	body = append(body, 0, 2, 0x13, 0x01)    // cipher suites
	body = append(body, 1, 0)                // compression
	body = binary.BigEndian.AppendUint16(body, uint16(len(exts)))
	body = append(body, exts...)
	hs := []byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	hs = append(hs, body...)
	rec := []byte{0x16, 3, 1, byte(len(hs) >> 8), byte(len(hs))}
	return append(rec, hs...)
}

func ci(n int) gopacket.CaptureInfo {
	return gopacket.CaptureInfo{Timestamp: time.Now(), CaptureLength: n, Length: n}
}

func ciAt(n int, at time.Time) gopacket.CaptureInfo {
	return gopacket.CaptureInfo{Timestamp: at, CaptureLength: n, Length: n}
}

func TestDecode(t *testing.T) {
	f := tcpFrame(t, "203.0.113.5", "192.168.1.117", 54321, 22, "SYN", nil)
	p, ok := decode(f, layers.LinkTypeEthernet, ci(len(f)), opts)
	if !ok || p.Proto != "TCP" || p.SPort != 54321 || p.DPort != 22 || p.Src.String() != "203.0.113.5" || p.Flags != "SYN" || p.TTL != 57 || len(p.Raw) != len(f) {
		t.Fatalf("bad tcp decode: %+v ok=%v", p, ok)
	}
	f = tcpFrame(t, "192.168.1.117", "203.0.113.5", 40000, 443, "PSH,ACK", clientHello("api.example.com"))
	p, _ = decode(f, layers.LinkTypeEthernet, ci(len(f)), opts)
	if p.Name != "api.example.com" || !strings.Contains(p.Info, "TLS ClientHello api.example.com") || p.Payload == 0 {
		t.Fatalf("bad sni decode: %+v", p)
	}
	f = tcpFrame(t, "192.168.1.117", "203.0.113.5", 40000, 80, "PSH,ACK", []byte("GET /index.html HTTP/1.1\r\nHost: www.example.com\r\nUser-Agent: x\r\n\r\n"))
	p, _ = decode(f, layers.LinkTypeEthernet, ci(len(f)), opts)
	if p.Name != "www.example.com" || !strings.Contains(p.Info, "HTTP GET /index.html") {
		t.Fatalf("bad http decode: %+v", p)
	}
	f = dnsFrame(t, "192.168.1.117", "1.1.1.1", false)
	p, ok = decode(f, layers.LinkTypeEthernet, ci(len(f)), opts)
	if !ok || p.Proto != "UDP" || !strings.Contains(p.Info, "DNS query A example.com") || p.DNS != nil {
		t.Fatalf("bad dns decode: %+v ok=%v", p, ok)
	}
	f = dnsFrame(t, "1.1.1.1", "192.168.1.117", true)
	p, _ = decode(f, layers.LinkTypeEthernet, ci(len(f)), opts)
	if p.DNS == nil || p.DNS.Query != "example.com" || len(p.DNS.Addrs) != 1 || p.DNS.Addrs[0].String() != "203.0.113.5" {
		t.Fatalf("bad dns reply decode: %+v", p.DNS)
	}
	f = arpFrame(t, macA, []byte{192, 168, 1, 1}, []byte{192, 168, 1, 117})
	p, ok = decode(f, layers.LinkTypeEthernet, ci(len(f)), opts)
	if !ok || p.Proto != "ARP" || !strings.Contains(p.Info, "who-has 192.168.1.117") || p.SrcMAC != macA.String() {
		t.Fatalf("bad arp decode: %+v ok=%v", p, ok)
	}
}

func TestTLSServerNameRejectsGarbage(t *testing.T) {
	for _, b := range [][]byte{nil, {0x16}, {0x16, 3, 1, 0, 5, 1, 0, 0, 1, 0}, []byte("GET / HTTP/1.1\r\n"), clientHello("")[:20]} {
		if n := tlsServerName(b); n != "" {
			t.Fatalf("got %q from %x", n, b)
		}
	}
}

// testAgg builds an aggregator that believes 192.168.1.117 and 10.0.0.1 are local.
func testAgg(t *testing.T) (*Agg, *Resolver) {
	t.Helper()
	var res *Resolver
	agg := NewAgg(func(ip netip.Addr) { res.Enqueue(ip) })
	agg.local = map[netip.Addr]bool{netip.MustParseAddr("192.168.1.117"): true, netip.MustParseAddr("10.0.0.1"): true}
	agg.bcast = map[netip.Addr]bool{netip.MustParseAddr("192.168.1.255"): true, netip.MustParseAddr("255.255.255.255"): true}
	var err error
	res, err = NewResolver(false, "", "", agg.IsBroadcast)
	if err != nil {
		t.Fatal(err)
	}
	agg.kindOf = func(ip netip.Addr) string { return res.Get(ip).Kind }
	return agg, res
}

func feed(t *testing.T, agg *Agg, frames ...[]byte) {
	t.Helper()
	for _, f := range frames {
		p, ok := decode(f, layers.LinkTypeEthernet, ci(len(f)), opts)
		if !ok {
			t.Fatal("decode failed")
		}
		agg.Add(p)
	}
}

func feedAt(t *testing.T, agg *Agg, at time.Time, f []byte) {
	t.Helper()
	p, ok := decode(f, layers.LinkTypeEthernet, ciAt(len(f), at), opts)
	if !ok {
		t.Fatal("decode failed")
	}
	agg.Add(p)
}

func findFlow(s Snapshot, lport uint16) *Flow {
	for i := range s.Flows {
		if s.Flows[i].Key.LocalPort == lport && s.Flows[i].Key.Proto == "TCP" {
			return &s.Flows[i]
		}
	}
	return nil
}

func TestAggregateDirections(t *testing.T) {
	agg, res := testAgg(t)
	feed(t, agg,
		tcpFrame(t, "203.0.113.5", "192.168.1.117", 54321, 22, "SYN", nil),     // inbound
		tcpFrame(t, "192.168.1.117", "203.0.113.5", 22, 54321, "SYN,ACK", nil), // reply, same flow
		dnsFrame(t, "192.168.1.117", "1.1.1.1", false),                         // outbound
		tcpFrame(t, "192.168.1.50", "192.168.1.255", 1000, 2000, "", nil),      // LAN broadcast, not ours
	)
	s := agg.Snapshot()
	if s.Stats.Packets != 4 || s.Stats.PktsIn != 1 || s.Stats.PktsOut != 2 || s.Stats.PktsOther != 1 {
		t.Fatalf("stats: %+v", s.Stats)
	}
	if len(s.Flows) != 3 {
		t.Fatalf("want 3 flows, got %d: %+v", len(s.Flows), s.Flows)
	}
	ssh := findFlow(s, 22)
	if ssh == nil || ssh.Dir != DirIn || ssh.PktsIn != 1 || ssh.PktsOut != 1 || ssh.Key.Remote.String() != "203.0.113.5" || ssh.TTL != 57 || len(ssh.Events) != 2 {
		t.Fatalf("ssh flow: %+v", ssh)
	}
	if len(s.Hosts) != 3 {
		t.Fatalf("want 3 hosts, got %d", len(s.Hosts))
	}
	for _, h := range s.Hosts {
		hi := res.Get(h.IP)
		switch h.IP.String() {
		case "203.0.113.5":
			if hi.Kind != "public" || h.PktsIn != 1 || h.Ports[54321] != 2 {
				t.Fatalf("public host: %+v info=%+v", h, hi)
			}
		case "1.1.1.1":
			if hi.Kind != "public" || h.PktsOut != 1 {
				t.Fatalf("dns host: %+v", h)
			}
		case "192.168.1.50":
			if hi.Kind != "LAN" || h.PktsIn != 1 {
				t.Fatalf("lan host: %+v info=%+v", h, hi)
			}
		default:
			t.Fatalf("unexpected host %s", h.IP)
		}
	}
	// The inbound SYN from a public address raises a notice.
	if len(s.Notices) != 1 || s.Notices[0].Kind != "inbound" || !strings.Contains(s.Notices[0].Text, "local port 22") {
		t.Fatalf("notices: %+v", s.Notices)
	}
	if got := res.classify(netip.MustParseAddr("192.168.1.255")); got != "broadcast" {
		t.Fatalf("broadcast classify: %s", got)
	}
	if got := res.classify(netip.MustParseAddr("100.67.251.1")); got != "tailscale/CGNAT" {
		t.Fatalf("cgnat classify: %s", got)
	}
	if got := res.classify(netip.MustParseAddr("224.0.0.251")); got != "multicast" {
		t.Fatalf("multicast classify: %s", got)
	}
	agg.Reset()
	if s := agg.Snapshot(); s.Stats.Packets != 0 || len(s.Flows) != 0 || len(s.Packets) != 0 || len(s.Notices) != 0 {
		t.Fatalf("reset failed: %+v", s.Stats)
	}
}

func TestNamesAndRTT(t *testing.T) {
	agg, _ := testAgg(t)
	t0 := time.Now()
	// DNS reply teaches the name before the connection opens.
	feedAt(t, agg, t0, dnsFrame(t, "1.1.1.1", "192.168.1.117", true))
	feedAt(t, agg, t0.Add(10*time.Millisecond), tcpFrame(t, "192.168.1.117", "203.0.113.5", 40000, 443, "SYN", nil))
	feedAt(t, agg, t0.Add(35*time.Millisecond), tcpFrame(t, "203.0.113.5", "192.168.1.117", 443, 40000, "SYN,ACK", nil))
	feedAt(t, agg, t0.Add(36*time.Millisecond), tcpFrame(t, "192.168.1.117", "203.0.113.5", 40000, 443, "ACK", nil))
	s := agg.Snapshot()
	f := findFlow(s, 40000)
	if f == nil || f.Name != "example.com" || f.RTT != 25*time.Millisecond {
		t.Fatalf("flow after dns: %+v", f)
	}
	// SNI overrides the DNS-learned name.
	feedAt(t, agg, t0.Add(40*time.Millisecond), tcpFrame(t, "192.168.1.117", "203.0.113.5", 40000, 443, "PSH,ACK", clientHello("api.example.com")))
	s = agg.Snapshot()
	f = findFlow(s, 40000)
	if f.Name != "api.example.com" {
		t.Fatalf("sni name: %q", f.Name)
	}
	var h *Host
	for i := range s.Hosts {
		if s.Hosts[i].IP.String() == "203.0.113.5" {
			h = &s.Hosts[i]
		}
	}
	if h == nil || h.Names["example.com"] == 0 || h.Names["api.example.com"] == 0 {
		t.Fatalf("host names: %+v", h)
	}
	// Inbound connection: RTT measured from our SYN,ACK to their ACK.
	feedAt(t, agg, t0, tcpFrame(t, "198.51.100.9", "192.168.1.117", 5000, 22, "SYN", nil))
	feedAt(t, agg, t0.Add(1*time.Millisecond), tcpFrame(t, "192.168.1.117", "198.51.100.9", 22, 5000, "SYN,ACK", nil))
	feedAt(t, agg, t0.Add(81*time.Millisecond), tcpFrame(t, "198.51.100.9", "192.168.1.117", 5000, 22, "ACK", nil))
	f = findFlow(agg.Snapshot(), 22)
	if f == nil || f.RTT != 80*time.Millisecond {
		t.Fatalf("inbound rtt: %+v", f)
	}
	lines := timelineLines(*f, HostInfo{Kind: "public"})
	joined := strings.Join(lines, "\n")
	for _, want := range []string{"handshake complete", "round trip", "SYN,ACK", "←", "→"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("timeline missing %q:\n%s", want, joined)
		}
	}
}

func TestNotices(t *testing.T) {
	agg, _ := testAgg(t)
	t0 := time.Now()
	// Port scan: 10 different local ports from one host within 5 s.
	for i := 0; i < 10; i++ {
		feedAt(t, agg, t0.Add(time.Duration(i)*100*time.Millisecond), tcpFrame(t, "198.51.100.7", "192.168.1.117", 6000, uint16(8000+i), "SYN", nil))
	}
	// ARP: router changes MAC.
	feedAt(t, agg, t0, arpFrame(t, macA, []byte{192, 168, 1, 1}, []byte{192, 168, 1, 117}))
	feedAt(t, agg, t0.Add(time.Second), arpFrame(t, macB, []byte{192, 168, 1, 1}, []byte{192, 168, 1, 117}))
	s := agg.Snapshot()
	var kinds []string
	for _, n := range s.Notices {
		kinds = append(kinds, n.Kind)
	}
	got := strings.Join(kinds, ",")
	if !strings.Contains(got, "scan") || !strings.Contains(got, "arp") || !strings.Contains(got, "inbound") {
		t.Fatalf("notice kinds: %s\n%+v", got, s.Notices)
	}
	for _, h := range s.Hosts {
		if h.IP.String() == "192.168.1.1" && h.MAC != macB.String() {
			t.Fatalf("router mac: %+v", h)
		}
	}
}

func TestBucketsAndSpark(t *testing.T) {
	agg, _ := testAgg(t)
	now := time.Now()
	for i := 0; i < 5; i++ {
		feedAt(t, agg, now.Add(-time.Duration(i)*time.Second), tcpFrame(t, "203.0.113.5", "192.168.1.117", 443, 40000, "ACK", make([]byte, 100*(i+1))))
	}
	s := agg.Snapshot()
	if len(s.Buckets) != 60 {
		t.Fatalf("buckets: %d", len(s.Buckets))
	}
	var nonzero int
	for _, b := range s.Buckets {
		if b.In > 0 {
			nonzero++
		}
	}
	if nonzero < 4 || nonzero > 5 { // the oldest may straddle a boundary
		t.Fatalf("nonzero buckets: %d", nonzero)
	}
	sp := spark([]uint64{0, 1, 5, 10}, 6)
	if r := []rune(sp); len(r) != 6 || r[0] != ' ' || r[2] != '▁' || r[5] != '█' {
		t.Fatalf("spark: %q", sp)
	}
}

func TestRecentRing(t *testing.T) {
	agg, _ := testAgg(t)
	for i := 0; i < recentCap+10; i++ {
		agg.Add(Packet{Time: time.Now(), Len: i, Proto: "TCP", Src: netip.MustParseAddr("203.0.113.5"), Dst: netip.MustParseAddr("192.168.1.117")})
	}
	s := agg.Snapshot()
	if len(s.Packets) != recentCap || s.Packets[0].Len != recentCap+9 || s.Packets[recentCap-1].Len != 10 {
		t.Fatalf("ring order wrong: n=%d first=%d last=%d", len(s.Packets), s.Packets[0].Len, s.Packets[len(s.Packets)-1].Len)
	}
}

func TestDecodeTree(t *testing.T) {
	f := tcpFrame(t, "203.0.113.5", "192.168.1.117", 54321, 22, "SYN", []byte("hi"))
	lines := decodeTree(f, layers.LinkTypeEthernet)
	joined := strings.Join(lines, "\n")
	for _, want := range []string{"▸ Ethernet", "▸ IPv4", "▸ TCP", "TTL                57", "SrcIP              203.0.113.5", "SYN                true", "Hex dump"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("decode tree missing %q:\n%s", want, joined)
		}
	}
	if got := decodeTree(nil, layers.LinkTypeEthernet); len(got) != 1 {
		t.Fatalf("empty raw: %v", got)
	}
}

func TestProcTable(t *testing.T) {
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "net"), 0o755)
	os.MkdirAll(filepath.Join(root, "1234", "fd"), 0o755)
	os.WriteFile(filepath.Join(root, "net", "tcp"), []byte(
		"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"+
			"   0: 7501A8C0:9C44 18E0BA23:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 777777 1 0000000000000000 20 4 30 10 -1\n"), 0o644)
	os.WriteFile(filepath.Join(root, "net", "udp"), []byte("header\n"), 0o644)
	os.WriteFile(filepath.Join(root, "1234", "comm"), []byte("firefox\n"), 0o644)
	os.Symlink("socket:[777777]", filepath.Join(root, "1234", "fd", "5"))
	os.Symlink("/dev/null", filepath.Join(root, "1234", "fd", "0"))
	pt := NewProcTable()
	pt.root = root
	got := pt.scan()
	if got[portKey{"TCP", 0x9C44}] != "firefox(1234)" {
		t.Fatalf("scan: %+v", got)
	}
	if pt.Lookup("TCP", 0x9C44) != "" { // first lookup misses and kicks a refresh
		t.Fatal("expected miss before refresh")
	}
	deadline := time.Now().Add(2 * time.Second)
	for pt.Lookup("TCP", 0x9C44) == "" && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if pt.Lookup("TCP", 0x9C44) != "firefox(1234)" {
		t.Fatal("lookup after refresh failed")
	}
}

func TestPcapWriter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.pcap")
	c := &Capture{WriteTo: path, SnapLen: 65535}
	if err := c.openWriter(layers.LinkTypeEthernet); err != nil {
		t.Fatal(err)
	}
	f := tcpFrame(t, "203.0.113.5", "192.168.1.117", 54321, 22, "SYN", nil)
	if err := c.pw.WritePacket(ci(len(f)), f); err != nil {
		t.Fatal(err)
	}
	c.done = make(chan struct{})
	close(c.done)
	c.Close()
	fh, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer fh.Close()
	r, err := pcapgo.NewReader(fh)
	if err != nil {
		t.Fatal(err)
	}
	data, _, err := r.ReadPacketData()
	if err != nil || len(data) != len(f) {
		t.Fatalf("read back: %v len=%d want %d", err, len(data), len(f))
	}
}

func TestLayoutCols(t *testing.T) {
	cols := []col{{"A", 10, false, 0}, {"B", 10, false, 2}, {"C", 10, false, 1}, {"D", 10, false, 0}}
	kept, idx := layoutCols(cols, 200)
	if len(kept) != 4 {
		t.Fatalf("wide: %v", idx)
	}
	kept, idx = layoutCols(cols, 40) // 10+1 + 10+1 + 14 = 36 fits only with one optional dropped
	if len(kept) != 3 || idx[1] != 2 {
		t.Fatalf("narrow: kept=%d idx=%v", len(kept), idx)
	}
	kept, _ = layoutCols(cols, 10)
	if len(kept) != 2 {
		t.Fatalf("tiny: %d", len(kept))
	}
}

func key(s string) tea.KeyMsg {
	switch s {
	case "enter":
		return tea.KeyMsg{Type: tea.KeyEnter}
	case "esc":
		return tea.KeyMsg{Type: tea.KeyEsc}
	case "tab":
		return tea.KeyMsg{Type: tea.KeyTab}
	}
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)}
}

func TestViewsRender(t *testing.T) {
	agg, res := testAgg(t)
	feed(t, agg,
		tcpFrame(t, "203.0.113.5", "192.168.1.117", 54321, 22, "SYN", nil),
		tcpFrame(t, "192.168.1.117", "203.0.113.5", 22, 54321, "SYN,ACK", nil),
		dnsFrame(t, "192.168.1.117", "1.1.1.1", false),
		dnsFrame(t, "1.1.1.1", "192.168.1.117", true),
		tcpFrame(t, "192.168.1.117", "203.0.113.5", 40000, 443, "PSH,ACK", clientHello("api.example.com")),
		tcpFrame(t, "192.168.1.50", "192.168.1.255", 1000, 2000, "", nil),
		arpFrame(t, macA, []byte{192, 168, 1, 1}, []byte{192, 168, 1, 117}),
	)
	agg.Add(Packet{Time: time.Now(), Len: 80, Proto: "TCP", Src: netip.MustParseAddr("2001:db8::1"), Dst: netip.MustParseAddr("192.168.1.117"), SPort: 443, DPort: 5555})
	errs := make(chan error, 1)
	m := newModel(agg, res, &Capture{}, errs, "wlan0", "")
	for _, size := range [][2]int{{40, 10}, {80, 24}, {120, 40}, {200, 50}} {
		mm, _ := m.Update(tea.WindowSizeMsg{Width: size[0], Height: size[1]})
		m = mm.(model)
		mm, _ = m.Update(tickMsg(time.Now()))
		m = mm.(model)
		for v := view(0); v < viewCount; v++ {
			m.setView(v)
			for _, detail := range []bool{false, true} {
				m.detail = detail
				m.rebuild()
				out := m.View()
				lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
				if len(lines) > size[1] {
					t.Fatalf("view %s at %dx%d (detail=%v): %d lines > height", v, size[0], size[1], detail, len(lines))
				}
				for _, l := range lines {
					if w := lipgloss.Width(l); w > size[0] {
						t.Fatalf("view %s at %dx%d: line wider (%d) than terminal:\n%s", v, size[0], size[1], w, l)
					}
				}
				if v == viewFlows && size[0] >= 120 && !strings.Contains(out, "api.example.com") {
					t.Fatalf("flows view missing SNI name:\n%s", out)
				}
				if v == viewStats && size[0] >= 80 && !strings.Contains(out, "Protocols") {
					t.Fatalf("stats view missing sections:\n%s", out)
				}
				if v == viewNotices && size[0] >= 80 && !strings.Contains(out, "inbound") {
					t.Fatalf("notices view empty:\n%s", out)
				}
			}
		}
	}
	// Overlays: help, decode (Packets), timeline (Flows).
	for _, c := range []struct {
		view view
		key  string
		want string
	}{{viewFlows, "?", "Columns"}, {viewPackets, "enter", "Hex dump"}, {viewFlows, "t", "TIME"}} {
		m.setView(c.view)
		m.rebuild()
		if c.view == viewPackets {
			for i, p := range m.pkts { // pick a captured frame, not the hand-built one
				if len(p.Raw) > 0 {
					m.cursor = i
					break
				}
			}
		}
		mm, _ := m.Update(key(c.key))
		m = mm.(model)
		if m.overlay == nil {
			t.Fatalf("overlay %q did not open", c.key)
		}
		out := m.View()
		if !strings.Contains(out, c.want) {
			t.Fatalf("overlay %q missing %q:\n%s", c.key, c.want, out)
		}
		for _, k := range []string{"j", "G", "g", " "} {
			mm, _ = m.Update(key(k))
			m = mm.(model)
			_ = m.View()
		}
		mm, _ = m.Update(key("esc"))
		m = mm.(model)
		if m.overlay != nil {
			t.Fatal("overlay did not close")
		}
	}
	// Keys: sort, direction filter, navigation, reset.
	m.setView(viewFlows)
	for _, k := range []string{"s", "s", "s", "s", "d", "d", "d", "d", "i", "i", "j", "k", "G", "g", "enter", "esc", "tab", "tab", "r"} {
		mm, _ := m.Update(key(k))
		m = mm.(model)
		_ = m.View()
	}
	mm, _ := m.Update(key("/"))
	m = mm.(model)
	for _, r := range "203" {
		mm, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
		m = mm.(model)
	}
	if !m.searching || m.search != "203" {
		t.Fatalf("search state: %v %q", m.searching, m.search)
	}
	_ = m.View()
	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
	if cmd == nil {
		t.Fatal("ctrl+c should quit")
	}
}

func TestHumanFormats(t *testing.T) {
	if humanBytes(1536) != "1.5 KB" || humanBytes(10) != "10 B" || humanBits(2_500_000) != "2.5 Mb/s" || humanCount(12345) != "12.3k" {
		t.Fatalf("%s %s %s %s", humanBytes(1536), humanBytes(10), humanBits(2_500_000), humanCount(12345))
	}
	if rttStr(25*time.Millisecond) != "25.0ms" || ttlExplain(57) != "ttl 57 ≈ 7 hops away (if it started at 64)" {
		t.Fatalf("%s | %s", rttStr(25*time.Millisecond), ttlExplain(57))
	}
}
