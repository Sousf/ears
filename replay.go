package main

import (
	"errors"
	"fmt"
	"io"
	"maps"
	"net/netip"
	"slices"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// Site is what a replay knows about the network a capture was made on. The
// machine running ears is somewhere else, so none of it comes from the OS.
type Site struct {
	LocalIP  netip.Addr
	LocalMAC string
	Subnet   netip.Prefix
	Gateway  netip.Addr
	DNS      []netip.Addr
}

// inferSite reads a capture once and guesses which machine recorded it: the
// IPv4 address in the most frames. The subnet is taken as its /24, the
// gateway as whatever that machine sends off-subnet traffic to.
func inferSite(path string) (Site, error) {
	h, err := pcap.OpenOffline(path)
	if err != nil {
		return Site{}, fmt.Errorf("replay %s: %w", path, err)
	}
	defer h.Close()
	lt := h.LinkType()
	opts := gopacket.DecodeOptions{Lazy: true, NoCopy: true}
	var pkts []Packet
	for {
		data, ci, err := h.ReadPacketData()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return Site{}, fmt.Errorf("replay %s: %w", path, err)
		}
		if p, ok := decode(data, lt, ci, opts); ok {
			p.Raw = nil
			pkts = append(pkts, p)
		}
	}
	return siteOf(pkts), nil
}

func siteOf(pkts []Packet) Site {
	unicast := func(ip netip.Addr) bool {
		if !ip.Is4() || ip.IsMulticast() || ip.IsUnspecified() || ip.IsLoopback() {
			return false
		}
		return ip.As4()[3] != 255
	}
	seen := map[netip.Addr]int{}
	for _, p := range pkts {
		if p.Proto == "ARP" {
			continue
		}
		for _, ip := range []netip.Addr{p.Src, p.Dst} {
			if unicast(ip) {
				seen[ip]++
			}
		}
	}
	var s Site
	s.LocalIP = top(seen, netip.Addr.Compare)
	if !s.LocalIP.IsValid() {
		return s
	}
	s.Subnet = netip.PrefixFrom(s.LocalIP, 24).Masked()

	macs, gwMACs := map[string]int{}, map[string]int{}
	dns := map[netip.Addr]bool{}
	for _, p := range pkts {
		if p.Src != s.LocalIP || p.Proto == "ARP" {
			continue
		}
		if p.SrcMAC != "" {
			macs[p.SrcMAC]++
		}
		if unicast(p.Dst) && !s.Subnet.Contains(p.Dst) && p.DstMAC != "" {
			gwMACs[p.DstMAC]++
		}
		if p.DPort == 53 && p.Dst.IsValid() {
			dns[p.Dst] = true
		}
	}
	s.LocalMAC = top(macs, strings.Compare)
	if gw := top(gwMACs, strings.Compare); gw != "" {
		for _, p := range pkts {
			if p.SrcMAC == gw && s.Subnet.Contains(p.Src) {
				s.Gateway = p.Src
				break
			}
		}
	}
	s.DNS = slices.SortedFunc(maps.Keys(dns), netip.Addr.Compare)
	return s
}

// top returns the key with the highest count, the lowest by cmpK on a tie.
func top[K comparable](counts map[K]int, cmpK func(a, b K) int) K {
	var best K
	n := 0
	for k, c := range counts {
		if c > n || c == n && cmpK(k, best) < 0 {
			best, n = k, c
		}
	}
	return best
}

// TopoView is the Map's picture of a replayed site: no Wi-Fi, Tailscale,
// trace or neighbour table, since those would describe this machine.
func (s Site) TopoView(label string) TopoView {
	return TopoView{Iface: label, LocalIP: s.LocalIP, LocalMAC: s.LocalMAC, Subnet: s.Subnet,
		Gateway: s.Gateway, DNS: s.DNS, Replay: true}
}
