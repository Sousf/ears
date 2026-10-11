package main

import (
	"errors"
	"fmt"
	"io"
	"iter"
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

// inferSite guesses which machine recorded a capture: the IPv4 address in
// the most frames. The subnet is taken as its /24, the gateway as whatever
// that machine sends off-subnet traffic to. The file is read twice, packet by
// packet, so memory does not grow with its size.
func inferSite(path string) (Site, error) {
	var readErr error
	each := func(yield func(Packet) bool) {
		h, err := pcap.OpenOffline(path)
		if err != nil {
			readErr = fmt.Errorf("replay %s: %w", path, err)
			return
		}
		defer h.Close()
		lt := h.LinkType()
		opts := gopacket.DecodeOptions{Lazy: true, NoCopy: true}
		for {
			data, ci, err := h.ZeroCopyReadPacketData()
			if errors.Is(err, io.EOF) {
				return
			}
			if err != nil {
				readErr = fmt.Errorf("replay %s: %w", path, err)
				return
			}
			if p, ok := decode(data, lt, ci, opts); ok && !yield(p) {
				return
			}
		}
	}
	s := siteOf(each)
	return s, readErr
}

// siteOf infers the recording site from the packets that pkts yields. It
// ranges over pkts twice.
func siteOf(pkts iter.Seq[Packet]) Site {
	unicast := func(ip netip.Addr) bool {
		if !ip.Is4() || ip.IsMulticast() || ip.IsUnspecified() || ip.IsLoopback() {
			return false
		}
		return ip.As4()[3] != 255
	}
	seen := map[netip.Addr]int{}
	for p := range pkts {
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
	lanBySrcMAC := map[string]netip.Addr{} // first LAN address seen from each MAC
	dns := map[netip.Addr]bool{}
	for p := range pkts {
		if p.SrcMAC != "" && s.Subnet.Contains(p.Src) {
			if _, ok := lanBySrcMAC[p.SrcMAC]; !ok {
				lanBySrcMAC[p.SrcMAC] = p.Src
			}
		}
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
		s.Gateway = lanBySrcMAC[gw]
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
