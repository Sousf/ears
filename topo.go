package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Hop is one router on the path to the trace target.
type Hop struct {
	N       int
	IP      netip.Addr
	RTT     time.Duration
	NoReply bool
}

type WiFi struct {
	SSID     string
	BSSID    string
	Security string
	Mode     string
	Bitrate  string
	FreqMHz  int
	Channel  int
	RSSI     int // dBm, 0 when unknown
}

type TSPeer struct {
	Name   string
	OS     string
	IPs    []netip.Addr
	Online bool
	Active bool // traffic flowing right now
	Self   bool
	Direct string     // endpoint when connected directly
	Relay  string     // home DERP relay region
	Public netip.Addr // self only: public address Tailscale discovered
}

// Path describes how traffic to the peer travels right now.
func (p TSPeer) Path() string {
	switch {
	case p.Self:
		return "this machine"
	case !p.Online:
		return "offline"
	case !p.Active:
		return "online, idle"
	case p.Direct != "":
		return "direct to " + p.Direct
	case p.Relay != "":
		return "through relay " + p.Relay
	}
	return "online"
}

type ARPEntry struct {
	IP    netip.Addr
	MAC   string
	Iface string
}

// Topo gathers what the operating system knows about the local network.
// Slow sources (vendor database, Wi-Fi, trace, Tailscale) load in the
// background; View returns whatever is ready.
type Topo struct {
	mu      sync.Mutex
	root    string // "/proc", overridable in tests
	offline bool   // tests: never run external commands

	oui        map[[3]byte]string
	ouiLoading bool

	wifi       *WiFi
	wifiAt     time.Time
	wifiBusy   bool
	tailscale  []TSPeer
	tsAt       time.Time
	tsBusy     bool
	hops       []Hop
	traceState string // "", "running", "done", or an error
	target     string
	traceStop  context.CancelFunc
	traceGen   int // bumped per trace so a cancelled one cannot write into a newer one
}

// topoOffline makes new Topos skip external commands; tests set it.
var topoOffline bool

func NewTopo(target string) *Topo {
	return &Topo{root: "/proc", target: target, offline: topoOffline}
}

type TopoView struct {
	Iface      string
	Wireless   bool
	LocalIP    netip.Addr
	LocalMAC   string
	Subnet     netip.Prefix
	Gateway    netip.Addr
	ARP        []ARPEntry
	WiFi       *WiFi
	Tailscale  []TSPeer
	TSIP       netip.Addr
	Hops       []Hop
	TraceState string
	Target     string
	Hostname   string
	DNS        []netip.Addr
}

// View reads the routing and neighbour tables and returns a snapshot.
func (t *Topo) View(iface string) TopoView {
	v := TopoView{Iface: iface, Gateway: t.defaultGateway(iface), ARP: t.readARP()}
	v.Hostname, _ = os.Hostname()
	if ifc, err := net.InterfaceByName(iface); err == nil {
		v.LocalMAC = ifc.HardwareAddr.String()
		if addrs, err := ifc.Addrs(); err == nil {
			for _, a := range addrs {
				if ipn, ok := a.(*net.IPNet); ok {
					if ip := toAddr(ipn.IP); ip.Is4() {
						ones, _ := ipn.Mask.Size()
						v.LocalIP = ip
						v.Subnet = netip.PrefixFrom(ip, ones).Masked()
						break
					}
				}
			}
		}
	}
	if ifc, err := net.InterfaceByName("tailscale0"); err == nil {
		if addrs, err := ifc.Addrs(); err == nil {
			for _, a := range addrs {
				if ipn, ok := a.(*net.IPNet); ok {
					if ip := toAddr(ipn.IP); ip.Is4() {
						v.TSIP = ip
					}
				}
			}
		}
	}
	_, err := os.Stat(filepath.Join("/sys/class/net", iface, "wireless"))
	v.Wireless = err == nil
	v.DNS = dnsServers()

	t.mu.Lock()
	defer t.mu.Unlock()
	if v.Wireless && !t.offline && !t.wifiBusy && time.Since(t.wifiAt) > 15*time.Second {
		t.wifiBusy = true
		go t.loadWiFi(iface)
	}
	if !t.offline && !t.tsBusy && time.Since(t.tsAt) > 15*time.Second {
		t.tsBusy = true
		go t.loadTailscale()
	}
	if t.oui == nil && !t.ouiLoading {
		t.ouiLoading = true
		go t.loadOUI()
	}
	if t.wifi != nil {
		w := *t.wifi
		v.WiFi = &w
	}
	v.Tailscale = append([]TSPeer(nil), t.tailscale...)
	v.Hops = append([]Hop(nil), t.hops...)
	v.TraceState = t.traceState
	v.Target = t.target
	return v
}

// ---- routes and neighbours ----

// defaultGateway reads the IPv4 default route for iface from /proc/net/route.
func (t *Topo) defaultGateway(iface string) netip.Addr {
	f, err := os.Open(filepath.Join(t.root, "net", "route"))
	if err != nil {
		return netip.Addr{}
	}
	defer f.Close()
	return parseRoute(f, iface)
}

func parseRoute(f *os.File, iface string) netip.Addr {
	sc := bufio.NewScanner(f)
	sc.Scan()
	var any netip.Addr
	for sc.Scan() {
		fl := strings.Fields(sc.Text())
		if len(fl) < 3 || fl[1] != "00000000" {
			continue
		}
		raw, err := hex.DecodeString(fl[2])
		if err != nil || len(raw) != 4 {
			continue
		}
		var b [4]byte
		binary.LittleEndian.PutUint32(b[:], binary.BigEndian.Uint32(raw))
		gw := netip.AddrFrom4(b)
		if fl[0] == iface {
			return gw
		}
		if !any.IsValid() {
			any = gw
		}
	}
	return any
}

func (t *Topo) readARP() []ARPEntry {
	f, err := os.Open(filepath.Join(t.root, "net", "arp"))
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []ARPEntry
	sc := bufio.NewScanner(f)
	sc.Scan()
	for sc.Scan() {
		fl := strings.Fields(sc.Text())
		if len(fl) < 6 || fl[2] == "0x0" || fl[3] == "00:00:00:00:00:00" {
			continue // incomplete entry: the address did not answer
		}
		ip, err := netip.ParseAddr(fl[0])
		if err != nil {
			continue
		}
		out = append(out, ARPEntry{IP: ip, MAC: strings.ToLower(fl[3]), Iface: fl[5]})
	}
	return out
}

// dnsServers lists the resolvers this machine uses. With systemd-resolved,
// /etc/resolv.conf only names the local stub, so the real list is elsewhere.
func dnsServers() []netip.Addr {
	read := func(path string) []netip.Addr {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		var out []netip.Addr
		for _, line := range strings.Split(string(b), "\n") {
			f := strings.Fields(line)
			if len(f) >= 2 && f[0] == "nameserver" {
				if ip, err := netip.ParseAddr(f[1]); err == nil {
					out = append(out, ip)
				}
			}
		}
		return out
	}
	s := read("/etc/resolv.conf")
	if len(s) == 1 && s[0].IsLoopback() {
		if r := read("/run/systemd/resolve/resolv.conf"); len(r) > 0 {
			return r
		}
	}
	return s
}

// ---- MAC vendors ----

var ouiPaths = []string{"/usr/share/hwdata/oui.txt", "/usr/share/misc/oui.txt", "/usr/share/ieee-data/oui.txt"}

func (t *Topo) loadOUI() {
	table := map[[3]byte]string{}
	for _, p := range ouiPaths {
		if f, err := os.Open(p); err == nil {
			parseOUI(f, table)
			f.Close()
			break
		}
	}
	t.mu.Lock()
	t.oui = table
	t.ouiLoading = false
	t.mu.Unlock()
}

// parseOUI reads IEEE lines like "28-24-FF   (hex)\t\tWistron Neweb Corporation".
func parseOUI(f *os.File, table map[[3]byte]string) {
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		i := strings.Index(line, "(hex)")
		if i < 8 {
			continue
		}
		raw, err := hex.DecodeString(strings.ReplaceAll(strings.TrimSpace(line[:i]), "-", ""))
		if err != nil || len(raw) != 3 {
			continue
		}
		table[[3]byte{raw[0], raw[1], raw[2]}] = shortVendor(strings.TrimSpace(line[i+5:]))
	}
}

var vendorSuffix = regexp.MustCompile(`(?i)[\s,.]+(inc|incorporated|incorporation|corp|corporation|co|ltd|limited|llc|gmbh|ag|sa|s\.a|bv|b\.v|plc|pte|pty|company|technologies|technology|electronics|communications|international|holdings|group)\.?$`)

// shortVendor trims legal suffixes so vendor names fit in a box.
func shortVendor(s string) string {
	for i := 0; i < 4; i++ {
		t := strings.TrimSpace(vendorSuffix.ReplaceAllString(s, ""))
		t = strings.TrimRight(t, ",. ")
		if t == s || t == "" {
			break
		}
		s = t
	}
	return s
}

// Vendor returns the registered maker of a MAC address, or "" if unknown.
// Private reports a locally administered (usually randomised) address.
func (t *Topo) Vendor(mac string) (vendor string, private bool) {
	hw, err := net.ParseMAC(mac)
	if err != nil || len(hw) < 3 {
		return "", false
	}
	if hw[0]&0x02 != 0 {
		return "", true
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.oui[[3]byte{hw[0], hw[1], hw[2]}], false
}

// ---- Wi-Fi ----

var ansiRE = regexp.MustCompile(`\x1b\[[0-9;]*[A-Za-z]`)

func (t *Topo) loadWiFi(iface string) {
	w := wifiFromIwctl(iface)
	if w == nil {
		w = wifiFromNmcli()
	}
	if w == nil {
		w = t.wifiFromProc(iface)
	}
	t.mu.Lock()
	t.wifi, t.wifiAt, t.wifiBusy = w, time.Now(), false
	t.mu.Unlock()
}

func wifiFromIwctl(iface string) *WiFi {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "iwctl", "station", iface, "show").Output()
	if err != nil {
		return nil
	}
	return parseIwctl(string(out))
}

func parseIwctl(out string) *WiFi {
	w := &WiFi{}
	for _, line := range strings.Split(ansiRE.ReplaceAllString(out, ""), "\n") {
		l := strings.TrimSpace(line)
		val := func(key string) (string, bool) {
			if strings.HasPrefix(l, key) {
				return strings.TrimSpace(l[len(key):]), true
			}
			return "", false
		}
		if v, ok := val("Connected network"); ok {
			w.SSID = v
		} else if v, ok := val("ConnectedBss"); ok {
			w.BSSID = strings.ToLower(v)
		} else if v, ok := val("Frequency"); ok {
			w.FreqMHz, _ = strconv.Atoi(v)
		} else if v, ok := val("Channel"); ok {
			w.Channel, _ = strconv.Atoi(v)
		} else if v, ok := val("Security"); ok {
			w.Security = v
		} else if v, ok := val("RSSI"); ok {
			w.RSSI, _ = strconv.Atoi(strings.TrimSuffix(v, " dBm"))
		} else if v, ok := val("RxMode"); ok {
			w.Mode = v
		} else if v, ok := val("TxBitrate"); ok {
			if kb, err := strconv.Atoi(strings.TrimSuffix(v, " Kbit/s")); err == nil {
				w.Bitrate = strconv.Itoa(kb/1000) + " Mbit/s"
			}
		}
	}
	if w.SSID == "" {
		return nil
	}
	return w
}

func wifiFromNmcli() *WiFi {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "nmcli", "-t", "-f", "ACTIVE,SSID,BSSID,FREQ,CHAN,SIGNAL,SECURITY", "dev", "wifi").Output()
	if err != nil {
		return nil
	}
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.HasPrefix(line, "yes:") {
			continue
		}
		// nmcli escapes the colons inside the BSSID as \:
		f := strings.Split(strings.ReplaceAll(line, `\:`, "\x00"), ":")
		if len(f) < 7 {
			return nil
		}
		w := &WiFi{SSID: f[1], BSSID: strings.ToLower(strings.ReplaceAll(f[2], "\x00", ":")), Security: f[6]}
		w.FreqMHz, _ = strconv.Atoi(strings.Fields(f[3] + " ")[0])
		w.Channel, _ = strconv.Atoi(f[4])
		return w
	}
	return nil
}

// wifiFromProc gets at least the signal level from /proc/net/wireless.
func (t *Topo) wifiFromProc(iface string) *WiFi {
	b, err := os.ReadFile(filepath.Join(t.root, "net", "wireless"))
	if err != nil {
		return nil
	}
	for _, line := range strings.Split(string(b), "\n") {
		fl := strings.Fields(line)
		if len(fl) >= 4 && strings.TrimSuffix(fl[0], ":") == iface {
			lvl, err := strconv.ParseFloat(strings.TrimSuffix(fl[3], "."), 64)
			if err == nil {
				return &WiFi{RSSI: int(lvl)}
			}
		}
	}
	return nil
}

// ---- Tailscale ----

func (t *Topo) loadTailscale() {
	peers := tailscalePeers()
	t.mu.Lock()
	t.tailscale, t.tsAt, t.tsBusy = peers, time.Now(), false
	t.mu.Unlock()
}

type tsJSONPeer struct {
	HostName     string
	OS           string
	TailscaleIPs []string
	Online       bool
	Active       bool
	Relay        string
	CurAddr      string
	Addrs        []string
}

func tailscalePeers() []TSPeer {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "tailscale", "status", "--json").Output()
	if err != nil {
		return nil
	}
	return parseTailscale(out)
}

func parseTailscale(out []byte) []TSPeer {
	var st struct {
		BackendState string
		Self         tsJSONPeer
		Peer         map[string]tsJSONPeer
	}
	if json.Unmarshal(out, &st) != nil || st.BackendState != "Running" {
		return nil
	}
	conv := func(p tsJSONPeer, self bool) TSPeer {
		tp := TSPeer{Name: p.HostName, OS: p.OS, Online: p.Online || self, Active: p.Active, Self: self, Direct: p.CurAddr, Relay: p.Relay}
		for _, s := range p.TailscaleIPs {
			if ip, err := netip.ParseAddr(s); err == nil {
				tp.IPs = append(tp.IPs, ip)
			}
		}
		for _, s := range p.Addrs {
			if ap, err := netip.ParseAddrPort(s); err == nil && !ap.Addr().IsPrivate() && !tp.Public.IsValid() {
				tp.Public = ap.Addr()
			}
		}
		return tp
	}
	peers := []TSPeer{conv(st.Self, true)}
	var rest []TSPeer
	for _, p := range st.Peer {
		rest = append(rest, conv(p, false))
	}
	sort.Slice(rest, func(i, j int) bool {
		if rest[i].Online != rest[j].Online {
			return rest[i].Online
		}
		return strings.ToLower(rest[i].Name) < strings.ToLower(rest[j].Name)
	})
	return append(peers, rest...)
}

// ---- route trace ----

var traceLine = regexp.MustCompile(`^\s*(\d+)\??:\s+(\S+)(?:\s+(\d+(?:\.\d+)?)ms)?`)

// Trace runs tracepath to the target in the background, replacing any trace
// in progress. tracepath needs no privileges: it sends UDP probes with rising
// TTLs and reads the ICMP "time exceeded" replies.
func (t *Topo) Trace(onHop func(netip.Addr)) {
	t.mu.Lock()
	if t.traceStop != nil {
		t.traceStop()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	t.traceStop = cancel
	t.traceGen++
	gen := t.traceGen
	t.hops = nil
	t.traceState = "running"
	target := t.target
	t.mu.Unlock()

	go func() {
		defer cancel()
		state := t.runTrace(ctx, gen, target, onHop)
		t.mu.Lock()
		if t.traceGen == gen {
			t.traceState = state
		}
		t.mu.Unlock()
	}()
}

func (t *Topo) runTrace(ctx context.Context, gen int, target string, onHop func(netip.Addr)) string {
	bin, err := exec.LookPath("tracepath")
	if err != nil {
		return "tracepath is not installed (it comes with iputils)"
	}
	cmd := exec.CommandContext(ctx, bin, "-n", "-m", "24", target)
	out, err := cmd.StdoutPipe()
	if err != nil {
		return err.Error()
	}
	if err := cmd.Start(); err != nil {
		return err.Error()
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	misses := 0
	sc := bufio.NewScanner(out)
	for sc.Scan() {
		h, ok := parseTraceLine(sc.Text())
		if !ok {
			continue
		}
		t.mu.Lock()
		if t.traceGen != gen {
			t.mu.Unlock()
			return "superseded"
		}
		if n := len(t.hops); n > 0 && t.hops[n-1].N == h.N {
			t.mu.Unlock()
			continue // tracepath repeats a hop when the path MTU changes
		}
		t.hops = append(t.hops, h)
		t.mu.Unlock()
		if h.NoReply {
			misses++
		} else {
			misses = 0
			if onHop != nil {
				onHop(h.IP)
			}
			if h.IP.String() == target {
				return "done"
			}
		}
		if misses >= 3 {
			// The rest of the path does not answer probes; stop waiting.
			t.mu.Lock()
			if t.traceGen == gen {
				t.hops = t.hops[:len(t.hops)-misses]
			}
			t.mu.Unlock()
			return "done"
		}
	}
	return "done"
}

func parseTraceLine(line string) (Hop, bool) {
	if strings.Contains(line, "[LOCALHOST]") {
		return Hop{}, false
	}
	m := traceLine.FindStringSubmatch(line)
	if m == nil {
		return Hop{}, false
	}
	n, _ := strconv.Atoi(m[1])
	if m[2] == "no" {
		return Hop{N: n, NoReply: true}, true
	}
	ip, err := netip.ParseAddr(m[2])
	if err != nil {
		return Hop{}, false
	}
	h := Hop{N: n, IP: ip}
	if m[3] != "" {
		ms, _ := strconv.ParseFloat(m[3], 64)
		h.RTT = time.Duration(ms * float64(time.Millisecond))
	}
	return h, true
}

func (t *Topo) StopTrace() {
	t.mu.Lock()
	if t.traceStop != nil {
		t.traceStop()
	}
	t.mu.Unlock()
}
