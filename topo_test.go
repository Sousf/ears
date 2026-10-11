package main

import (
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
	"github.com/muesli/termenv"
)

func TestMain(m *testing.M) {
	topoOffline = true
	os.Exit(m.Run())
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	os.MkdirAll(filepath.Dir(path), 0o755)
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestRouteAndARP(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "net", "route"), "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"+
		"wlan0\t0001A8C0\t00000000\t0001\t0\t0\t600\t00FFFFFF\t0\t0\t0\n"+
		"wlan0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0\n")
	writeFile(t, filepath.Join(root, "net", "arp"), "IP address       HW type     Flags       HW address            Mask     Device\n"+
		"192.168.1.112    0x1         0x2         28:24:FF:ca:2e:90     *        wlan0\n"+
		"192.168.1.12     0x1         0x0         00:00:00:00:00:00     *        wlan0\n"+
		"192.168.1.1      0x1         0x2         78:20:51:81:77:5f     *        wlan0\n")
	tp := NewTopo("1.1.1.1")
	tp.root = root
	if gw := tp.defaultGateway("wlan0"); gw.String() != "192.168.1.1" {
		t.Fatalf("gateway %s", gw)
	}
	arp := tp.readARP()
	if len(arp) != 2 || arp[0].MAC != "28:24:ff:ca:2e:90" || arp[1].IP.String() != "192.168.1.1" {
		t.Fatalf("arp: %+v", arp)
	}
}

func TestOUIAndVendor(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oui.txt")
	writeFile(t, path, "OUI/MA-L\t\t\tOrganization\n78-20-51   (hex)\t\tTP-Link Systems Inc.\n782051     (base 16)\t\tTP-Link Systems Inc.\n00-68-EB   (hex)\t\tHP Inc.\n")
	f, _ := os.Open(path)
	table := map[[3]byte]string{}
	parseOUI(f, table)
	f.Close()
	tp := NewTopo("")
	tp.oui = table
	if v, p := tp.Vendor("78:20:51:81:77:5f"); v != "TP-Link Systems" || p {
		t.Fatalf("vendor %q private %v", v, p)
	}
	if v, p := tp.Vendor("6e:9e:9c:9c:07:37"); v != "" || !p {
		t.Fatalf("private MAC: %q %v", v, p)
	}
	if !sameDevice("78:20:51:81:77:5f", "78:20:51:81:77:61") || sameDevice("78:20:51:81:77:5f", "28:24:ff:ca:2e:90") {
		t.Fatal("sameDevice")
	}
	for in, want := range map[string]string{"Samsung Electronics Co.,Ltd": "Samsung", "ASRock Incorporation": "ASRock", "Apple, Inc.": "Apple", "Intel Corporate": "Intel Corporate"} {
		if got := shortVendor(in); got != want {
			t.Errorf("shortVendor(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseIwctl(t *testing.T) {
	out := "\x1b[1;90m  Settable  Property              Value\x1b[0m\n" +
		"            State                 connected\n" +
		"            Connected network     HomeNet_5G\n" +
		"            ConnectedBss          78:20:51:81:77:61\n" +
		"            Frequency             5180\n" +
		"            Channel               36\n" +
		"            Security              WPA2-Personal\n" +
		"            RSSI                  -43 dBm\n" +
		"            AverageRSSI           -45 dBm\n" +
		"            RxMode                802.11ax\n" +
		"            TxBitrate             1020600 Kbit/s\n"
	w := parseIwctl(out)
	if w == nil || w.SSID != "HomeNet_5G" || w.BSSID != "78:20:51:81:77:61" || w.FreqMHz != 5180 || w.Channel != 36 || w.RSSI != -43 || w.Mode != "802.11ax" || w.Bitrate != "1020 Mbit/s" {
		t.Fatalf("%+v", w)
	}
	if parseIwctl("State disconnected\n") != nil {
		t.Fatal("disconnected should be nil")
	}
}

func TestParseTrace(t *testing.T) {
	cases := map[string]Hop{
		" 1:  192.168.1.1                                           1.191ms ":          {N: 1, IP: netip.MustParseAddr("192.168.1.1"), RTT: 1191 * time.Microsecond},
		" 6:  203.50.11.199                                        14.643ms asymm  5 ": {N: 6, IP: netip.MustParseAddr("203.50.11.199"), RTT: 14643 * time.Microsecond},
		" 9:  no reply": {N: 9, NoReply: true},
	}
	for line, want := range cases {
		got, ok := parseTraceLine(line)
		if !ok || got != want {
			t.Errorf("%q -> %+v %v", line, got, ok)
		}
	}
	for _, line := range []string{" 1?: [LOCALHOST]                      pmtu 1500", "     Resume: pmtu 1500", ""} {
		if _, ok := parseTraceLine(line); ok {
			t.Errorf("%q should not parse", line)
		}
	}
}

func TestParseTailscale(t *testing.T) {
	js := `{"BackendState":"Running","Self":{"HostName":"me","OS":"linux","TailscaleIPs":["100.67.251.97"],"Online":false},
	"Peer":{"a":{"HostName":"zed","OS":"linux","TailscaleIPs":["100.1.1.1"],"Online":true,"Relay":"syd"},
	        "b":{"HostName":"amy","OS":"macOS","TailscaleIPs":["100.2.2.2"],"Online":false},
	        "c":{"HostName":"bob","OS":"iOS","TailscaleIPs":["100.3.3.3"],"Online":true,"CurAddr":"1.2.3.4:41641"}}}`
	p := parseTailscale([]byte(js))
	if len(p) != 4 || !p[0].Self || !p[0].Online || p[1].Name != "bob" || p[1].Direct == "" || p[2].Name != "zed" || p[3].Online {
		t.Fatalf("%+v", p)
	}
	if parseTailscale([]byte(`{"BackendState":"Stopped"}`)) != nil {
		t.Fatal("stopped should be nil")
	}
}

func mdnsFrame(t *testing.T) []byte {
	ip := &layers.IPv4{Version: 4, TTL: 255, Protocol: layers.IPProtocolUDP, SrcIP: net.ParseIP("192.168.1.50"), DstIP: net.ParseIP("224.0.0.251")}
	udp := &layers.UDP{SrcPort: 5353, DstPort: 5353}
	udp.SetNetworkLayerForChecksum(ip)
	dns := &layers.DNS{QR: true, AA: true, Answers: []layers.DNSResourceRecord{
		{Name: []byte("Living-Room-TV.local"), Type: layers.DNSTypeA, Class: layers.DNSClassIN, TTL: 120, IP: net.ParseIP("192.168.1.50").To4()}}}
	return serialize(t, &layers.Ethernet{SrcMAC: net.HardwareAddr{0x00, 0x68, 0xeb, 1, 2, 3}, DstMAC: net.HardwareAddr{0x01, 0, 0x5e, 0, 0, 0xfb}, EthernetType: layers.EthernetTypeIPv4}, ip, udp, dns)
}

func dhcpFrame(t *testing.T) []byte {
	mac := net.HardwareAddr{0x6e, 0x9e, 0x9c, 0x9c, 0x07, 0x37}
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: net.IPv4zero, DstIP: net.IPv4bcast}
	udp := &layers.UDP{SrcPort: 68, DstPort: 67}
	udp.SetNetworkLayerForChecksum(ip)
	d := &layers.DHCPv4{Operation: layers.DHCPOpRequest, HardwareType: layers.LinkTypeEthernet, HardwareLen: 6, ClientHWAddr: mac,
		Options: layers.DHCPOptions{
			layers.NewDHCPOption(layers.DHCPOptMessageType, []byte{byte(layers.DHCPMsgTypeRequest)}),
			layers.NewDHCPOption(layers.DHCPOptHostname, []byte("Pixel-8")),
			layers.NewDHCPOption(layers.DHCPOptClassID, []byte("android-dhcp-14")),
			layers.NewDHCPOption(layers.DHCPOptEnd, nil),
		}}
	return serialize(t, &layers.Ethernet{SrcMAC: mac, DstMAC: net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, EthernetType: layers.EthernetTypeIPv4}, ip, udp, d)
}

func TestLANNamesAndMACs(t *testing.T) {
	f := mdnsFrame(t)
	p, ok := decode(f, layers.LinkTypeEthernet, ci(len(f)), opts)
	if !ok || len(p.LANName) != 1 || p.LANName[0].Name != "Living-Room-TV.local" || p.SrcMAC != "00:68:eb:01:02:03" {
		t.Fatalf("mdns: %+v", p)
	}
	f = dhcpFrame(t)
	p, _ = decode(f, layers.LinkTypeEthernet, ci(len(f)), opts)
	if p.DHCP == nil || p.DHCP.Hostname != "Pixel-8" || p.DHCP.Vendor != "android-dhcp-14" || p.DHCP.MAC != "6e:9e:9c:9c:07:37" {
		t.Fatalf("dhcp: %+v", p.DHCP)
	}

	agg, res := testAgg(t)
	feed(t, agg, mdnsFrame(t), dhcpFrame(t))
	s := agg.Snapshot()
	if s.LANNames[netip.MustParseAddr("192.168.1.50")] != "Living-Room-TV.local" {
		t.Fatalf("lan names: %v", s.LANNames)
	}
	var tv, phone *MacInfo
	for i := range s.Macs {
		switch s.Macs[i].MAC {
		case "00:68:eb:01:02:03":
			tv = &s.Macs[i]
		case "6e:9e:9c:9c:07:37":
			phone = &s.Macs[i]
		}
	}
	if tv == nil || tv.IPs[netip.MustParseAddr("192.168.1.50")].IsZero() || tv.BytesFrom == 0 {
		t.Fatalf("tv mac: %+v", tv)
	}
	if phone == nil || phone.Hostname != "Pixel-8" || len(phone.IPs) != 0 {
		t.Fatalf("phone mac (0.0.0.0 must not be recorded): %+v", phone)
	}
	for _, mi := range s.Macs {
		if isGroupMAC(mi.MAC) {
			t.Fatalf("group MAC recorded: %s", mi.MAC)
		}
	}

	// The map merges ARP, capture and this machine, and picks out the router.
	m := newModel(agg, res, &Capture{}, make(chan error), "wlan0", "")
	m.snap = s
	m.topo.oui = map[[3]byte]string{{0x00, 0x68, 0xeb}: "HP", {0x78, 0x20, 0x51}: "TP-Link"}
	tvw := TopoView{Iface: "wlan0", Subnet: netip.MustParsePrefix("192.168.1.0/24"), LocalIP: netip.MustParseAddr("192.168.1.117"),
		LocalMAC: "04:e8:b9:48:29:f2", Gateway: netip.MustParseAddr("192.168.1.1"), Hostname: "box",
		ARP: []ARPEntry{{IP: netip.MustParseAddr("192.168.1.1"), MAC: "78:20:51:81:77:5f", Iface: "wlan0"},
			{IP: netip.MustParseAddr("192.168.1.50"), MAC: "00:68:eb:01:02:03", Iface: "wlan0"},
			{IP: netip.MustParseAddr("10.9.9.9"), MAC: "aa:aa:aa:aa:aa:aa", Iface: "eth9"}}}
	router, devs := m.buildDevices(tvw)
	if router == nil || router.Vendor != "TP-Link" {
		t.Fatalf("router: %+v", router)
	}
	if len(devs) != 2 || !devs[0].Self || devs[0].Name != "box" || devs[1].Name != "Living-Room-TV" || devs[1].Vendor != "HP" || devs[1].ARPOnly {
		t.Fatalf("devices: %+v", devs)
	}
}

func TestMapRender(t *testing.T) {
	agg, res := testAgg(t)
	feed(t, agg, mdnsFrame(t))
	m := newModel(agg, res, &Capture{}, make(chan error), "wlan0", "")
	var arp []ARPEntry
	for i := 2; i < 14; i++ {
		arp = append(arp, ARPEntry{IP: netip.AddrFrom4([4]byte{192, 168, 1, byte(i)}), MAC: "00:68:eb:01:02:" + string("0123456789abcdef"[i]) + "0", Iface: "wlan0"})
	}
	arp = append(arp, ARPEntry{IP: netip.MustParseAddr("192.168.1.1"), MAC: "78:20:51:81:77:5f", Iface: "wlan0"})
	m.topo.hops = []Hop{{N: 1, IP: netip.MustParseAddr("192.168.1.1"), RTT: time.Millisecond}, {N: 2, IP: netip.MustParseAddr("58.162.26.199"), RTT: 9 * time.Millisecond},
		{N: 3, NoReply: true}, {N: 4, IP: netip.MustParseAddr("162.158.0.10"), RTT: 12 * time.Millisecond}, {N: 5, IP: netip.MustParseAddr("162.158.0.10"), RTT: 13 * time.Millisecond}}
	m.topo.traceState = "done"
	m.topo.target = "1.1.1.1"
	m.topo.wifi = &WiFi{SSID: "HomeNet", BSSID: "78:20:51:81:77:61", FreqMHz: 5180, Channel: 36, RSSI: -48, Security: "WPA2-Personal"}
	m.topo.tailscale = []TSPeer{{Name: "me", Self: true, Online: true, IPs: []netip.Addr{netip.MustParseAddr("100.1.1.1")}}, {Name: "nas", Online: true, Relay: "syd"}}
	for _, size := range [][2]int{{40, 20}, {80, 30}, {130, 50}, {220, 60}} {
		mm, _ := m.Update(tea.WindowSizeMsg{Width: size[0], Height: size[1]})
		m = mm.(model)
		mm, _ = m.Update(key("6"))
		m = mm.(model)
		m.tv = m.topo.View("wlan0")
		m.tv.ARP, m.tv.Gateway, m.tv.Subnet, m.tv.Wireless = arp, netip.MustParseAddr("192.168.1.1"), netip.MustParsePrefix("192.168.1.0/24"), true
		lines := m.mapLines()
		joined := strings.Join(lines, "\n")
		for _, l := range lines {
			if w := lipgloss.Width(l); w > max(size[0], 40) {
				t.Fatalf("width %d: line is %d wide:\n%s", size[0], w, l)
			}
		}
		for _, want := range []string{"Internet", "Router", "HomeNet", "58.162.26.199", "Tailscale", "excellent", "built-in Wi-Fi"} {
			if !strings.Contains(joined, want) {
				t.Fatalf("width %d: map missing %q:\n%s", size[0], want, joined)
			}
		}
		if strings.Count(joined, "162.158.0.10") != 1 {
			t.Fatalf("repeated hop not collapsed:\n%s", joined)
		}
		out := m.View()
		if n := len(strings.Split(strings.TrimRight(out, "\n"), "\n")); n > size[1] {
			t.Fatalf("view taller than terminal: %d > %d", n, size[1])
		}
		// Scrolling stays in range.
		for _, k := range []string{"G", "j", "k", "g"} {
			mm, _ = m.Update(key(k))
			m = mm.(model)
			_ = m.View()
		}
	}
	// Animation only advances on the map.
	m.phase = 0
	mm, cmd := m.Update(animMsg{})
	m = mm.(model)
	if m.phase != 1 || cmd == nil {
		t.Fatal("anim tick on map")
	}
	m.setView(viewFlows)
	mm, cmd = m.Update(animMsg{})
	m = mm.(model)
	if cmd != nil || m.animOn {
		t.Fatal("anim should stop off the map")
	}
	_, prompt := m.aiMap()
	if !strings.Contains(prompt, "HomeNet") || !strings.Contains(prompt, "58.162.26.199") {
		t.Fatalf("map prompt:\n%s", prompt)
	}
}

var _ = gopacket.Payload(nil)

// Truncating coloured text must never cut inside an escape sequence: a broken
// sequence swallows the padding after it and shifts the rest of the line.
func TestFitColoured(t *testing.T) {
	prev := lipgloss.ColorProfile()
	lipgloss.SetColorProfile(termenv.ANSI256)
	defer lipgloss.SetColorProfile(prev)
	s := "↓960.0 KB ↑168.6 KB" + stDim.Render(" · now")
	if !strings.Contains(s, "\x1b[") {
		t.Fatal("colour not forced; the test would prove nothing")
	}
	for w := 4; w <= 30; w++ {
		got := fit(s, w, false)
		if lipgloss.Width(got) != w {
			t.Fatalf("w=%d: width %d: %q", w, lipgloss.Width(got), got)
		}
		if strings.Contains(stripANSI(got), "\x1b") {
			t.Fatalf("w=%d: broken escape sequence left behind: %q", w, got)
		}
		if l := truncLine(s, w); lipgloss.Width(l) > w || strings.Contains(stripANSI(l), "\x1b") {
			t.Fatalf("truncLine w=%d: %q", w, l)
		}
	}
	box := drawBox([]string{s, "short"}, 22, stMapDev, 11, -1)
	for _, l := range box {
		if lipgloss.Width(l) != 22 || strings.Contains(stripANSI(l), "\x1b") {
			t.Fatalf("box line %q is %d wide", l, lipgloss.Width(l))
		}
	}
}

func TestMapSelection(t *testing.T) {
	agg, res := testAgg(t)
	m := newModel(agg, res, &Capture{}, make(chan error), "wlan0", "")
	m.topo.hops = []Hop{{N: 1, IP: netip.MustParseAddr("192.168.1.1"), RTT: time.Millisecond}, {N: 2, IP: netip.MustParseAddr("58.162.26.199"), RTT: 9 * time.Millisecond}}
	m.topo.traceState, m.topo.target = "done", "1.1.1.1"
	m.topo.tailscale = []TSPeer{{Name: "me", Self: true, Online: true, Public: netip.MustParseAddr("120.148.41.212")}, {Name: "nas", Online: true, Relay: "syd"}}
	mm, _ := m.Update(tea.WindowSizeMsg{Width: 130, Height: 30})
	m = mm.(model)
	mm, _ = m.Update(key("6"))
	m = mm.(model)
	fixTV := func() {
		m.tv = m.topo.View("wlan0")
		m.tv.Gateway, m.tv.Subnet, m.tv.Iface = netip.MustParseAddr("192.168.1.1"), netip.MustParsePrefix("192.168.1.0/24"), "wlan0"
		m.tv.LocalIP, m.tv.LocalMAC = netip.MustParseAddr("192.168.1.117"), "04:e8:b9:48:29:f2"
		m.tv.ARP = []ARPEntry{{IP: netip.MustParseAddr("192.168.1.1"), MAC: "78:20:51:81:77:5f", Iface: "wlan0"}, {IP: netip.MustParseAddr("192.168.1.11"), MAC: "9c:7b:ef:4e:d7:f6", Iface: "wlan0"}}
	}
	fixTV()
	if m.mapSel != "router" {
		t.Fatalf("default selection %q", m.mapSel)
	}
	_, objs := m.mapLayout()
	var keys []string
	for _, o := range objs {
		keys = append(keys, o.key)
	}
	want := "inet hop:2 router dev:04:e8:b9:48:29:f2 dev:9c:7b:ef:4e:d7:f6 ts:me ts:nas"
	if strings.Join(keys, " ") != want {
		t.Fatalf("objects in order:\n got %s\nwant %s", strings.Join(keys, " "), want)
	}
	// Moving down from the router reaches the devices, and the map scrolls to keep the selection visible.
	for i := 0; i < 2; i++ {
		mm, _ = m.Update(key("j"))
		m = mm.(model)
	}
	if m.mapSel != "dev:9c:7b:ef:4e:d7:f6" {
		t.Fatalf("after 2 x j: %q", m.mapSel)
	}
	mm, _ = m.Update(key("G"))
	m = mm.(model)
	if m.mapSel != "ts:nas" {
		t.Fatalf("G: %q", m.mapSel)
	}
	mm, _ = m.Update(key("g"))
	m = mm.(model)
	if m.mapSel != "inet" || m.mapOff != 0 {
		t.Fatalf("g: %q offset %d", m.mapSel, m.mapOff)
	}
	lines, objs := m.mapLayout()
	for _, o := range objs {
		if o.key == m.mapSel && (o.line < m.mapOff || o.line+o.height > m.mapOff+m.rowsAvail()+1) {
			t.Fatalf("selection at line %d not visible from offset %d", o.line, m.mapOff)
		}
	}
	if !strings.Contains(strings.Join(lines, "\n"), "┏") {
		t.Fatal("selected box not drawn heavy")
	}
	// Each kind of object opens a detail panel with the right facts.
	for _, c := range []struct{ sel, want string }{
		{"dev:9c:7b:ef:4e:d7:f6", "9c:7b:ef:4e:d7:f6"},
		{"router", "default gateway"},
		{"hop:2", "time exceeded"},
		{"inet", "120.148.41.212"},
		{"ts:nas", "online, idle"},
		{"dev:04:e8:b9:48:29:f2", "this machine"},
	} {
		m.mapSel = c.sel
		mm, _ = m.Update(key("enter"))
		m = mm.(model)
		if m.overlay == nil || !strings.Contains(stripANSI(strings.Join(m.overlay.lines, "\n")), c.want) {
			t.Fatalf("detail for %s missing %q: %+v", c.sel, c.want, m.overlay)
		}
		mm, _ = m.Update(key("esc"))
		m = mm.(model)
		_, p := m.aiMapObject(c.sel)
		if !strings.Contains(p, c.want) {
			t.Fatalf("ask prompt for %s missing %q", c.sel, c.want)
		}
	}
	if (TSPeer{Online: true, Active: true, Relay: "syd"}).Path() != "through relay syd" || (TSPeer{Online: true, Relay: "syd"}).Path() != "online, idle" {
		t.Fatal("tailscale path wording")
	}
}
