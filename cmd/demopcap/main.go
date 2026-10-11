// demopcap writes a made-up capture for demos and the README recording.
// Every address is from a documentation range (RFC 5737 for the internet,
// RFC 1918 10.0.0.0/24 for the LAN) and every name is example.*, so the
// replay shows nothing about a real network.
//
//	go run ./cmd/demopcap -o testdata/demo.pcap
package main

import (
	"flag"
	"fmt"
	"math/rand/v2"
	"net"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// The LAN.
var (
	laptop  = host{"10.0.0.23", "3c:22:fb:10:20:23"} // records the capture
	router  = host{"10.0.0.1", "f0:9f:c2:10:20:01"}
	nas     = host{"10.0.0.30", "00:11:32:10:20:30"}
	printer = host{"10.0.0.40", "00:1b:a9:10:20:40"}
	tv      = host{"10.0.0.52", "44:65:0d:10:20:52"}
	phone   = host{"10.0.0.61", "da:a1:19:10:20:61"} // randomised MAC
	pi      = host{"10.0.0.70", "b8:27:eb:10:20:70"}
)

type host struct{ ip, mac string }

// headers is how much of a bulk data segment is kept, as a capture with a
// short snaplen would: Ethernet, IPv4 and TCP. Byte counts use the full length.
const headers = 14 + 20 + 20

type frame struct {
	t    time.Duration
	data []byte
	wire int
}

type gen struct {
	rng    *rand.Rand
	frames []frame
	port   uint16
}

func main() {
	out := flag.String("o", "testdata/demo.pcap", "output file")
	flag.Parse()
	g := &gen{rng: rand.New(rand.NewPCG(1, 2)), port: 40000}
	g.script()
	if err := g.write(*out); err != nil {
		fmt.Fprintln(os.Stderr, "demopcap:", err)
		os.Exit(1)
	}
}

func s(sec float64) time.Duration { return time.Duration(sec * float64(time.Second)) }

// script lays out about a minute of traffic.
func (g *gen) script() {
	g.arp(s(0), laptop, router, false)
	g.arp(s(0.004), router, laptop, true)

	g.mdns(s(0.6), nas, "nas.local")
	g.mdns(s(2.4), printer, "printer.local")
	g.arp(s(2.5), printer, router, false)
	g.mdns(s(5.1), tv, "living-room-tv.local")
	g.dhcp(s(6.5), phone, "phone")
	g.arp(s(6.9), phone, router, false)
	g.arp(s(7.3), pi, laptop, false)
	g.mdns(s(7.4), pi, "pihole.local")
	for t := 1.0; t < 70; t += 6 {
		g.ssdp(s(t), tv)
	}

	g.browse(s(0.5), "www.example.com", "example.com", "203.0.113.10", 443, 18, 220_000, 2)
	g.browse(s(1.4), "api.example.org", "", "203.0.113.25", 443, 41, 30_000, 1)
	g.heartbeat(s(3), "203.0.113.25", 41, 60)
	g.browse(s(3.2), "cdn.example.net", "edge.cdn.example.net", "198.51.100.7", 443, 9, 18_000_000, 32)
	g.lan(s(4.5), nas, 445, 9_000_000, 40)
	g.http(s(8.8), "updates.example.com", "198.51.100.40", "/releases/latest.tar.gz", 23, 1_600_000)
	g.ntp(s(10.2), "time.example.org", "198.51.100.123")
	g.ssh(s(11.5), "192.0.2.66", 64)
	g.browse(s(13.1), "mail.example.com", "", "203.0.113.50", 993, 33, 45_000, 3)
	g.lookupFail(s(15.4), "intranet.example")
	g.quic(s(17), "chat.example.org", "203.0.113.77", 27, 50)
	g.browse(s(19.6), "docs.example.com", "", "203.0.113.12", 443, 21, 380_000, 3)
	g.scan(s(24), "192.0.2.99")
	g.browse(s(27.5), "status.example.net", "", "198.51.100.88", 443, 15, 12_000, 1)
	g.browse(s(31), "img.example.org", "images.example.org", "203.0.113.31", 443, 26, 900_000, 4)
	g.browse(s(38), "fonts.example.net", "", "198.51.100.19", 443, 12, 160_000, 2)
	g.browse(s(44), "search.example.com", "", "203.0.113.90", 443, 24, 70_000, 2)
	g.lan(s(47), printer, 631, 400_000, 4)
	g.browse(s(52), "video.example.org", "", "203.0.113.140", 443, 30, 6_000_000, 15)
}

func (g *gen) add(t time.Duration, data []byte, keep int) {
	wire := len(data)
	if keep > 0 && keep < wire {
		data = data[:keep]
	}
	g.frames = append(g.frames, frame{t, data, wire})
}

func (g *gen) nextPort() uint16 { g.port += 1 + uint16(g.rng.IntN(40)); return g.port }

func (g *gen) jitter(ms float64) time.Duration {
	return s(ms / 1000 * (0.85 + 0.3*g.rng.Float64()))
}

func mac(s string) net.HardwareAddr {
	m, err := net.ParseMAC(s)
	if err != nil {
		panic(err)
	}
	return m
}

func eth(src, dst string, t layers.EthernetType) *layers.Ethernet {
	return &layers.Ethernet{SrcMAC: mac(src), DstMAC: mac(dst), EthernetType: t}
}

func ser(ls ...gopacket.SerializableLayer) []byte {
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ls...); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

// macFor returns the next-hop MAC on the LAN for an address.
func macFor(ip string) string {
	for _, h := range []host{laptop, router, nas, printer, tv, phone, pi} {
		if h.ip == ip {
			return h.mac
		}
	}
	return router.mac
}

func ipv4(src, dst string, proto layers.IPProtocol, ttl uint8) *layers.IPv4 {
	return &layers.IPv4{Version: 4, TTL: ttl, Protocol: proto, SrcIP: net.ParseIP(src), DstIP: net.ParseIP(dst), Flags: layers.IPv4DontFragment}
}

// ttlFrom is the TTL a packet from ip arrives with.
func ttlFrom(ip string) uint8 {
	if macFor(ip) != router.mac || ip == router.ip {
		return 64
	}
	return 52
}

func (g *gen) udp(t time.Duration, src, dst string, sport, dport uint16, payload []byte) {
	srcMAC, dstMAC := macFor(src), macFor(dst)
	ip := ipv4(src, dst, layers.IPProtocolUDP, ttlFrom(src))
	u := &layers.UDP{SrcPort: layers.UDPPort(sport), DstPort: layers.UDPPort(dport)}
	_ = u.SetNetworkLayerForChecksum(ip)
	g.add(t, ser(eth(srcMAC, dstMAC, layers.EthernetTypeIPv4), ip, u, gopacket.Payload(payload)), 0)
}

// ---- TCP ----

type conn struct {
	g              *gen
	client, server string
	cport, sport   uint16
	cseq, sseq     uint32
	t              time.Duration
	rtt            time.Duration
}

func (g *gen) dial(t time.Duration, client, server string, sport uint16, rttMS float64) *conn {
	c := &conn{g: g, client: client, server: server, cport: g.nextPort(), sport: sport,
		cseq: g.rng.Uint32(), sseq: g.rng.Uint32(), t: t, rtt: g.jitter(rttMS)}
	if client != laptop.ip {
		c.cport, c.sport = 50000+uint16(g.rng.IntN(15000)), sport
	}
	c.seg(true, "SYN", 0)
	c.t += c.rtt
	c.seg(false, "SYN,ACK", 0)
	c.t += c.rtt / 10
	c.seg(true, "ACK", 0)
	return c
}

// seg sends one segment with n payload bytes, or with payload if given.
// Only the headers of an n-byte segment are kept.
func (c *conn) seg(fromClient bool, flags string, n int, payload ...byte) {
	src, dst, sp, dp, seq, ack := c.client, c.server, c.cport, c.sport, &c.cseq, c.sseq
	if !fromClient {
		src, dst, sp, dp, seq, ack = c.server, c.client, c.sport, c.cport, &c.sseq, c.cseq
	}
	srcMAC, dstMAC := macFor(src), macFor(dst)
	ip := ipv4(src, dst, layers.IPProtocolTCP, ttlFrom(src))
	tcp := &layers.TCP{SrcPort: layers.TCPPort(sp), DstPort: layers.TCPPort(dp), Seq: *seq, Window: 502}
	for _, f := range strings.Split(flags, ",") {
		switch f {
		case "SYN":
			tcp.SYN = true
		case "ACK":
			tcp.ACK = true
			tcp.Ack = ack
		case "PSH":
			tcp.PSH = true
		case "FIN":
			tcp.FIN = true
		case "RST":
			tcp.RST = true
		}
	}
	_ = tcp.SetNetworkLayerForChecksum(ip)
	body := payload
	if len(body) == 0 && n > 0 {
		body = make([]byte, n)
	}
	keep := 0
	if len(payload) == 0 && n > 0 {
		keep = headers
	}
	c.g.add(c.t, ser(eth(srcMAC, dstMAC, layers.EthernetTypeIPv4), ip, tcp, gopacket.Payload(body)), keep)
	*seq += uint32(len(body))
	if tcp.SYN || tcp.FIN {
		*seq++
	}
}

// download sends n bytes from the server over secs, acked as it goes.
// Segments are GRO-sized, as a Linux capture records them.
func (c *conn) download(n int, secs float64) {
	end := c.t + s(secs)
	for n > 0 {
		k := min(n, 1448*(1+c.g.rng.IntN(22)))
		n -= k
		c.seg(false, "PSH,ACK", k)
		c.t += c.rtt / 20
		c.seg(true, "ACK", 0)
		left := end - c.t
		if left > 0 && n > 0 {
			c.t += time.Duration(float64(left) * float64(k) / float64(n+k) * (0.6 + 0.8*c.g.rng.Float64()))
		}
	}
}

func (c *conn) close() {
	c.t += s(0.05)
	c.seg(true, "FIN,ACK", 0)
	c.t += c.rtt
	c.seg(false, "FIN,ACK", 0)
	c.t += c.rtt / 10
	c.seg(true, "ACK", 0)
}

// ---- application traffic ----

// resolve looks name up at the router. A cname, if set, is answered first.
func (g *gen) resolve(t time.Duration, name, cname, addr string) time.Duration {
	sport := g.nextPort()
	id := uint16(g.rng.IntN(65536))
	q := layers.DNSQuestion{Name: []byte(name), Type: layers.DNSTypeA, Class: layers.DNSClassIN}
	g.udp(t, laptop.ip, router.ip, sport, 53, ser(&layers.DNS{ID: id, RD: true, Questions: []layers.DNSQuestion{q}}))
	var ans []layers.DNSResourceRecord
	target := name
	if cname != "" {
		ans = append(ans, layers.DNSResourceRecord{Name: []byte(name), Type: layers.DNSTypeCNAME, Class: layers.DNSClassIN, TTL: 300, CNAME: []byte(cname)})
		target = cname
	}
	ans = append(ans, layers.DNSResourceRecord{Name: []byte(target), Type: layers.DNSTypeA, Class: layers.DNSClassIN, TTL: 300, IP: net.ParseIP(addr).To4()})
	t += g.jitter(14)
	g.udp(t, router.ip, laptop.ip, 53, sport, ser(&layers.DNS{ID: id, QR: true, RD: true, RA: true, Questions: []layers.DNSQuestion{q}, Answers: ans}))
	return t + g.jitter(1)
}

func (g *gen) lookupFail(t time.Duration, name string) {
	sport := g.nextPort()
	q := layers.DNSQuestion{Name: []byte(name), Type: layers.DNSTypeA, Class: layers.DNSClassIN}
	g.udp(t, laptop.ip, router.ip, sport, 53, ser(&layers.DNS{ID: 7, RD: true, Questions: []layers.DNSQuestion{q}}))
	g.udp(t+g.jitter(20), router.ip, laptop.ip, 53, sport, ser(&layers.DNS{ID: 7, QR: true, RD: true, RA: true,
		ResponseCode: layers.DNSResponseCodeNXDomain, Questions: []layers.DNSQuestion{q}}))
}

// browse looks a name up and fetches size bytes over TLS from it.
func (g *gen) browse(t time.Duration, name, cname, addr string, port uint16, rttMS float64, size int, secs float64) {
	t = g.resolve(t, name, cname, addr)
	c := g.dial(t, laptop.ip, addr, port, rttMS)
	c.seg(true, "PSH,ACK", 0, clientHello(name)...)
	c.t += c.rtt
	c.seg(false, "PSH,ACK", 2800)
	c.t += c.rtt / 4
	c.seg(true, "PSH,ACK", 420)
	c.t += c.rtt
	c.download(size, secs)
	c.close()
}

// heartbeat keeps a connection alive with a small exchange every few seconds.
func (g *gen) heartbeat(t time.Duration, addr string, rttMS float64, secs float64) {
	c := g.dial(t, laptop.ip, addr, 443, rttMS)
	c.seg(true, "PSH,ACK", 0, clientHello("events.example.org")...)
	for end := t + s(secs); c.t < end; {
		c.t += s(2 + g.rng.Float64())
		c.seg(true, "PSH,ACK", 90+g.rng.IntN(200))
		c.t += c.rtt
		c.seg(false, "PSH,ACK", 120+g.rng.IntN(600))
		c.t += c.rtt / 10
		c.seg(true, "ACK", 0)
	}
}

func (g *gen) http(t time.Duration, name, addr, path string, rttMS float64, size int) {
	t = g.resolve(t, name, "", addr)
	c := g.dial(t, laptop.ip, addr, 80, rttMS)
	req := "GET " + path + " HTTP/1.1\r\nHost: " + name + "\r\nUser-Agent: curl/8.9.1\r\nAccept: */*\r\n\r\n"
	c.seg(true, "PSH,ACK", 0, []byte(req)...)
	c.t += c.rtt
	c.download(size, 4)
	c.close()
}

// lan copies size bytes to a device on the LAN, as a backup or print job would.
func (g *gen) lan(t time.Duration, dev host, port uint16, size int, secs float64) {
	c := g.dial(t, laptop.ip, dev.ip, port, 1.2)
	end := c.t + s(secs)
	for size > 0 {
		k := min(size, 1448*(1+g.rng.IntN(30)))
		size -= k
		c.seg(true, "PSH,ACK", k)
		c.t += c.rtt / 4
		c.seg(false, "ACK", 0)
		if left := end - c.t; left > 0 && size > 0 {
			c.t += time.Duration(float64(left) * float64(k) / float64(size+k) * (0.5 + g.rng.Float64()))
		}
	}
	c.close()
}

func (g *gen) ssh(t time.Duration, from string, rttMS float64) {
	c := g.dial(t, from, laptop.ip, 22, rttMS)
	c.seg(true, "PSH,ACK", 0, []byte("SSH-2.0-OpenSSH_9.9\r\n")...)
	c.t += c.rtt
	c.seg(false, "PSH,ACK", 0, []byte("SSH-2.0-OpenSSH_10.0\r\n")...)
	for i := 0; i < 40; i++ {
		c.t += s(0.2 + 0.6*g.rng.Float64())
		c.seg(true, "PSH,ACK", 36+g.rng.IntN(60))
		c.t += c.rtt
		c.seg(false, "PSH,ACK", 36+g.rng.IntN(400))
	}
	c.close()
}

// scan probes a run of ports: closed ones answer RST, 22 completes.
func (g *gen) scan(t time.Duration, from string) {
	ports := []uint16{21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 993, 3306, 3389, 5432, 5900, 8080, 8443}
	sp := uint16(61000)
	for _, p := range ports {
		c := &conn{g: g, client: from, server: laptop.ip, cport: sp, sport: p, cseq: g.rng.Uint32(), sseq: g.rng.Uint32(), t: t, rtt: g.jitter(70)}
		c.seg(true, "SYN", 0)
		c.t += s(0.0002)
		if p == 22 {
			c.seg(false, "SYN,ACK", 0)
			c.t += c.rtt
			c.seg(true, "RST", 0)
		} else {
			c.seg(false, "RST,ACK", 0)
		}
		t += g.jitter(110)
	}
}

func (g *gen) ntp(t time.Duration, name, addr string) {
	t = g.resolve(t, name, "", addr)
	req := make([]byte, 48)
	req[0] = 0x23 // v4, client
	g.udp(t, laptop.ip, addr, 123, 123, req)
	resp := make([]byte, 48)
	resp[0], resp[1] = 0x24, 2 // v4, server, stratum 2
	g.udp(t+g.jitter(31), addr, laptop.ip, 123, 123, resp)
}

// quic exchanges UDP bursts on 443, the way a chat app over QUIC looks.
func (g *gen) quic(t time.Duration, name, addr string, rttMS float64, secs float64) {
	t = g.resolve(t, name, "", addr)
	sport := g.nextPort()
	for end := t + s(secs); t < end; t += s(0.4 + 2*g.rng.Float64()) {
		for i := 0; i < 1+g.rng.IntN(3); i++ {
			g.udp(t, laptop.ip, addr, sport, 443, make([]byte, 60+g.rng.IntN(300)))
			g.udp(t+g.jitter(rttMS), addr, laptop.ip, 443, sport, make([]byte, 80+g.rng.IntN(1100)))
		}
	}
}

// ---- LAN chatter ----

func (g *gen) arp(t time.Duration, from, to host, reply bool) {
	a := &layers.ARP{AddrType: layers.LinkTypeEthernet, Protocol: layers.EthernetTypeIPv4, HwAddressSize: 6, ProtAddressSize: 4,
		Operation: layers.ARPRequest, SourceHwAddress: mac(from.mac), SourceProtAddress: net.ParseIP(from.ip).To4(),
		DstHwAddress: make([]byte, 6), DstProtAddress: net.ParseIP(to.ip).To4()}
	dst := "ff:ff:ff:ff:ff:ff"
	if reply {
		a.Operation = layers.ARPReply
		a.DstHwAddress = mac(to.mac)
		dst = to.mac
	}
	g.add(t, ser(eth(from.mac, dst, layers.EthernetTypeARP), a), 0)
}

func (g *gen) mdns(t time.Duration, h host, name string) {
	d := &layers.DNS{QR: true, AA: true, Answers: []layers.DNSResourceRecord{
		{Name: []byte(name), Type: layers.DNSTypeA, Class: layers.DNSClassIN, TTL: 120, IP: net.ParseIP(h.ip).To4()},
	}}
	ip := ipv4(h.ip, "224.0.0.251", layers.IPProtocolUDP, 255)
	u := &layers.UDP{SrcPort: 5353, DstPort: 5353}
	_ = u.SetNetworkLayerForChecksum(ip)
	g.add(t, ser(eth(h.mac, "01:00:5e:00:00:fb", layers.EthernetTypeIPv4), ip, u, d), 0)
}

func (g *gen) ssdp(t time.Duration, h host) {
	msg := "NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nNT: upnp:rootdevice\r\nNTS: ssdp:alive\r\n" +
		"LOCATION: http://" + h.ip + ":8060/\r\n\r\n"
	ip := ipv4(h.ip, "239.255.255.250", layers.IPProtocolUDP, 4)
	u := &layers.UDP{SrcPort: 1900, DstPort: 1900}
	_ = u.SetNetworkLayerForChecksum(ip)
	g.add(t, ser(eth(h.mac, "01:00:5e:7f:ff:fa", layers.EthernetTypeIPv4), ip, u, gopacket.Payload(msg)), 0)
}

func (g *gen) dhcp(t time.Duration, h host, name string) {
	d := &layers.DHCPv4{Operation: layers.DHCPOpRequest, HardwareType: layers.LinkTypeEthernet, HardwareLen: 6,
		Xid: g.rng.Uint32(), ClientHWAddr: mac(h.mac), Options: layers.DHCPOptions{
			layers.NewDHCPOption(layers.DHCPOptMessageType, []byte{byte(layers.DHCPMsgTypeRequest)}),
			layers.NewDHCPOption(layers.DHCPOptRequestIP, net.ParseIP(h.ip).To4()),
			layers.NewDHCPOption(layers.DHCPOptHostname, []byte(name)),
			layers.NewDHCPOption(layers.DHCPOptEnd, nil),
		}}
	ip := ipv4("0.0.0.0", "255.255.255.255", layers.IPProtocolUDP, 64)
	u := &layers.UDP{SrcPort: 68, DstPort: 67}
	_ = u.SetNetworkLayerForChecksum(ip)
	g.add(t, ser(eth(h.mac, "ff:ff:ff:ff:ff:ff", layers.EthernetTypeIPv4), ip, u, d), 0)
}

// clientHello builds a TLS 1.3 ClientHello carrying name as its SNI.
func clientHello(name string) []byte {
	sni := []byte(name)
	ext := []byte{0x00, 0x00} // server_name
	list := append([]byte{0x00, byte(len(sni) >> 8), byte(len(sni))}, sni...)
	body := append([]byte{byte(len(list) >> 8), byte(len(list))}, list...)
	ext = append(ext, byte(len(body)>>8), byte(len(body)))
	ext = append(ext, body...)

	hello := []byte{0x03, 0x03}                // legacy version
	hello = append(hello, make([]byte, 32)...) // random
	hello = append(hello, 0x00)                // session id
	hello = append(hello, 0x00, 0x02, 0x13, 0x01, 0x01, 0x00)
	hello = append(hello, byte(len(ext)>>8), byte(len(ext)))
	hello = append(hello, ext...)

	hs := append([]byte{0x01, 0x00, byte(len(hello) >> 8), byte(len(hello))}, hello...)
	return append([]byte{0x16, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs))}, hs...)
}

func (g *gen) write(path string) error {
	sort.SliceStable(g.frames, func(i, j int) bool { return g.frames[i].t < g.frames[j].t })
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		f.Close()
		return err
	}
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	for _, fr := range g.frames {
		ci := gopacket.CaptureInfo{Timestamp: base.Add(fr.t), CaptureLength: len(fr.data), Length: fr.wire}
		if err := w.WritePacket(ci, fr.data); err != nil {
			f.Close()
			return err
		}
	}
	return f.Close()
}
