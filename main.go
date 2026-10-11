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
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

func main() {
	iface := flag.String("i", "", "interface to capture on (default: the default-route interface)")
	filter := flag.String("f", "", "BPF capture filter, e.g. 'not port 22' or 'tcp and dst host 192.168.1.117'")
	snaplen := flag.Int("snaplen", 262144, "bytes to capture per packet")
	promisc := flag.Bool("promisc", true, "capture in promiscuous mode (see other hosts' broadcast/mirrored traffic)")
	list := flag.Bool("list", false, "list capture interfaces and exit")
	online := flag.Bool("online", false, "look up country/ISP of public addresses via ip-api.com (sends those IPs to a third party, 40/min)")
	geo := flag.String("geoip", "", "City or Country .mmdb, MaxMind or DB-IP format (default: ~/.local/share/ears/city.mmdb if present)")
	asn := flag.String("asn", "", "ASN .mmdb, MaxMind or DB-IP format (default: ~/.local/share/ears/asn.mmdb if present)")
	writeTo := flag.String("w", "", "also write every captured frame to this pcap file (open it in Wireshark)")
	noProc := flag.Bool("no-proc", false, "do not map local ports to processes via /proc")
	ai := flag.Bool("ai", false, "enable the a key: send the selected row to Claude for an explanation")
	aiBackend := flag.String("ai-backend", "auto", "how -ai reaches Claude: api (ANTHROPIC_API_KEY), claude-code (your Claude plan via the claude command), or auto (api when a key is set)")
	traceTo := flag.String("trace", "1.1.1.1", "address the Map view traces the route to")
	noTrace := flag.Bool("no-trace", false, "do not trace the route automatically when the Map view opens (u still does)")
	aiModel := flag.String("ai-model", "claude-opus-5-5", "Claude model for -ai (the claude-code backend uses Claude Code's default unless this is set)")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: ears [flags]\n\nCapture needs raw-socket rights. Either run as root or grant them once:\n  sudo setcap cap_net_raw,cap_net_admin=eip ./ears\n\nflags:\n")
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
	if err := cap.Open(); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "permission") || strings.Contains(err.Error(), "Operation not permitted") {
			fmt.Fprintf(os.Stderr, "%v\n\nNo permission to capture. Run as root, or grant the binary capture rights once:\n  sudo setcap cap_net_raw,cap_net_admin=eip %s\n", err, os.Args[0])
			os.Exit(1)
		}
		fatal(err)
	}

	var res *Resolver
	agg := NewAgg(func(ip netip.Addr) { res.Enqueue(ip) })
	var err error
	res, err = NewResolver(*online, *geo, *asn, agg.IsBroadcast)
	if err != nil {
		fatal(err)
	}
	defer res.Close()
	agg.kindOf = func(ip netip.Addr) string { return res.Get(ip).Kind }
	if !*noProc {
		agg.procs = NewProcTable()
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	packets := make(chan Packet, 4096)
	errs := make(chan error, 1)
	go cap.Run(ctx, packets, errs)
	defer cap.Close()
	go func() {
		for p := range packets {
			agg.Add(p)
		}
	}()

	m := newModel(agg, res, cap, errs, *iface, *filter)
	m.topo = NewTopo(*traceTo)
	m.autoTrace = !*noTrace
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
