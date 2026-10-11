// ears is a terminal traffic monitor: it captures packets arriving at this
// machine's network interface and shows who is talking to it, from where.
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

func main() {
	iface := flag.String("i", "", "interface (default: default route)")
	filter := flag.String("f", "", "BPF filter, e.g. 'not port 22'")
	snaplen := flag.Int("snaplen", 262144, "bytes kept per packet")
	promisc := flag.Bool("promisc", true, "promiscuous mode")
	list := flag.Bool("list", false, "list interfaces")
	online := flag.Bool("online", false, "look up public IPs via ip-api.com (sends them there)")
	geo := flag.String("geoip", "", "city .mmdb (default ~/.local/share/ears/city.mmdb)")
	asn := flag.String("asn", "", "ASN .mmdb (default ~/.local/share/ears/asn.mmdb)")
	writeTo := flag.String("w", "", "save frames to a pcap file")
	noProc := flag.Bool("no-proc", false, "skip process lookup")
	devFile := flag.String("devices", "", "known-devices file, \"none\" to disable (default ~/.local/share/ears/devices.json)")
	ai := flag.Bool("ai", false, "enable Ask Claude (a key)")
	aiBackend := flag.String("ai-backend", "auto", "auto, api or claude-code")
	traceTo := flag.String("trace", "1.1.1.1", "Map trace target")
	noTrace := flag.Bool("no-trace", false, "don't trace when Map opens")
	aiModel := flag.String("ai-model", "claude-opus-5-5", "model for -ai")
	readFrom := flag.String("r", "", "replay a pcap file instead of capturing (no capture rights needed)")
	speed := flag.Float64("speed", 1, "replay speed, 0 for as fast as possible")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: ears [flags]\n\nNeeds capture rights, except with -r: sudo setcap cap_net_raw,cap_net_admin=eip ./ears\n\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if *list {
		s, err := ListInterfaces()
		if err != nil {
			fatal(err)
		}
		fmt.Print(s)
		return
	}
	replay := *readFrom != ""
	var site Site
	if replay {
		var err error
		if site, err = inferSite(*readFrom); err != nil {
			fatal(err)
		}
		*iface = filepath.Base(*readFrom)
	}
	if *iface == "" {
		*iface = defaultIface()
		if *iface == "" {
			fatal(fmt.Errorf("could not determine default interface; pass -i (see -list)"))
		}
	}
	data := dataDir()
	if *geo == "" {
		*geo = firstExisting(data+"/city.mmdb", "/usr/share/GeoIP/GeoLite2-City.mmdb", "/usr/share/GeoIP/GeoLite2-Country.mmdb", "/var/lib/GeoIP/GeoLite2-City.mmdb")
	}
	if *asn == "" {
		*asn = firstExisting(data+"/asn.mmdb", "/usr/share/GeoIP/GeoLite2-ASN.mmdb", "/var/lib/GeoIP/GeoLite2-ASN.mmdb")
	}

	cap := &Capture{Iface: *iface, Filter: *filter, SnapLen: *snaplen, Promisc: *promisc, WriteTo: *writeTo}
	if replay {
		cap.ReadFrom, cap.Speed = *readFrom, *speed
	}
	if err := cap.Open(); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "permission") || strings.Contains(err.Error(), "Operation not permitted") {
			fmt.Fprintf(os.Stderr, "%v\n\nNo capture rights. Run:\n  sudo setcap cap_net_raw,cap_net_admin=eip %s\n", err, os.Args[0])
			os.Exit(1)
		}
		fatal(err)
	}

	var res *Resolver
	agg := NewAgg(func(ip netip.Addr) { res.Enqueue(ip) })
	if replay {
		agg.SetLocal(site.LocalIP, site.Subnet)
	}
	var err error
	res, err = NewResolver(*online, *geo, *asn, agg.IsBroadcast)
	if err != nil {
		fatal(err)
	}
	res.publicOnly = replay
	defer res.Close()
	agg.kindOf = func(ip netip.Addr) string { return res.Get(ip).Kind }
	res.onCountry = func(country string, ip netip.Addr, org string) {
		agg.AddNotice("country", fmt.Sprintf("first traffic with %s: %s (%s)", country, ip, firstNonEmpty(org, "unknown")))
	}
	// A replay's ports belong to programs on the recording machine.
	if !*noProc && !replay {
		agg.procs = NewProcTable()
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	packets := make(chan Packet, 4096)
	errs := make(chan error, 1)
	go cap.Run(ctx, packets, errs)
	defer cap.Close()

	// With a local caching resolver, programs' lookups go over loopback and
	// never reach the capture interface. Watch them there for the DNS log.
	if !replay && *iface != "lo" && usesStub() {
		stub := &Capture{Iface: "lo", Filter: "udp port 53", SnapLen: 1500}
		if stub.Open() == nil {
			stubPkts := make(chan Packet, 1024)
			go stub.Run(ctx, stubPkts, make(chan error, 1))
			defer stub.Close()
			go func() {
				for p := range stubPkts {
					agg.AddStubDNS(p)
				}
			}()
		}
	}
	go func() {
		for p := range packets {
			agg.Add(p)
		}
	}()

	m := newModel(agg, res, cap, errs, *iface, *filter)
	m.topo = NewTopo(*traceTo)
	switch {
	case replay:
		// The recorded devices are not this network's, so the book stays
		// in memory and announces each one as it first appears.
		m.topo = NewReplayTopo(site.TopoView(*iface))
		*devFile = ""
	case *devFile == "none":
		*devFile = ""
	case *devFile == "":
		*devFile = data + "/devices.json"
	}
	defer m.topo.StopTrace()
	book, err := LoadDeviceBook(*devFile)
	if err != nil {
		fatal(fmt.Errorf("devices file: %w", err))
	}
	if replay {
		book.quietTo = time.Time{}
	}
	m.book = book
	defer func() { _ = book.SaveIfDue(time.Now(), true) }()
	m.autoTrace = !*noTrace && !replay
	if *ai {
		modelSet := false
		flag.Visit(func(f *flag.Flag) { modelSet = modelSet || f.Name == "ai-model" })
		asker, err := pickAsker(*aiBackend, *aiModel, modelSet)
		if err != nil {
			cancel()
			fatal(err)
		}
		m.explain = asker
	}
	p := tea.NewProgram(m, tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		cancel()
		fatal(err)
	}
	cancel()
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "ears:", err)
	os.Exit(1)
}

// dataDir is where ears looks for databases: $XDG_DATA_HOME/ears or ~/.local/share/ears.
func dataDir() string {
	if x := os.Getenv("XDG_DATA_HOME"); x != "" {
		return x + "/ears"
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "/nonexistent"
	}
	return home + "/.local/share/ears"
}

func firstExisting(paths ...string) string {
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// defaultIface returns the interface carrying the IPv4 default route.
func defaultIface() string {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Scan() // header
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) >= 2 && fields[1] == "00000000" {
			return fields[0]
		}
	}
	return ""
}
