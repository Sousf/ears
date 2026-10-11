package main

import (
	"cmp"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"
)

// Limits that keep memory flat however long ears runs. Idle entries expire;
// when a table is still over its cap, the least recently seen go first.
const (
	recentCap  = 5000
	bucketCap  = 120
	noticeCap  = 500
	maxFlows   = 8192
	maxHosts   = 4096
	maxDNS     = 4096
	maxNames   = 16384
	macCap     = 4096
	flowIdle   = 10 * time.Minute
	hostIdle   = 30 * time.Minute
	nameTTL    = time.Hour
	pruneEvery = 5 * time.Second
	listCap    = 8 // per-entry lists in the DNS log
)

type stamped struct {
	name string
	t    time.Time
}

// Agg owns all counters. The capture goroutines write, the UI snapshots.
type Agg struct {
	mu       sync.Mutex
	local    map[netip.Addr]bool
	bcast    map[netip.Addr]bool
	flows    map[FlowKey]*Flow
	hosts    map[netip.Addr]*Host
	names    map[netip.Addr]stamped // DNS answers: address -> queried name
	lanNames map[netip.Addr]stamped // mDNS: address -> name.local
	arp      map[netip.Addr]string  // address -> MAC claimed in ARP
	macs     map[string]*MacInfo
	dns      map[string]*DNSEntry
	stubDNS  bool // DNS is logged from the local resolver stub, not the capture interface

	hostCopies map[netip.Addr]Host // last deep copy handed to Snapshot, reused while unchanged
	lastPrune  time.Time

	recent []Packet // ring buffer of the newest packets
	head   int
	n      int

	secs    [bucketCap]Bucket
	notices []Notice
	stats   Stats

	procs  *ProcTable
	kindOf func(netip.Addr) string // address classification, from the resolver
	onNew  func(netip.Addr)        // called (outside the lock) the first time a remote address appears
}

func NewAgg(onNew func(netip.Addr)) *Agg {
	a := &Agg{local: map[netip.Addr]bool{}, bcast: map[netip.Addr]bool{}, onNew: onNew, recent: make([]Packet, recentCap)}
	a.clear()
	a.loadLocalAddrs()
	return a
}

// clear empties every table that capture fills.
func (a *Agg) clear() {
	a.flows = map[FlowKey]*Flow{}
	a.hosts = map[netip.Addr]*Host{}
	a.names = map[netip.Addr]stamped{}
	a.lanNames = map[netip.Addr]stamped{}
	a.arp = map[netip.Addr]string{}
	a.macs = map[string]*MacInfo{}
	a.dns = map[string]*DNSEntry{}
	a.hostCopies = map[netip.Addr]Host{}
	clear(a.recent)
	a.head, a.n = 0, 0
	a.secs = [bucketCap]Bucket{}
	a.notices = nil
	a.stats = Stats{Start: time.Now()}
}

// loadLocalAddrs records every address on every interface as "this machine",
// plus the directed broadcast address of each IPv4 subnet.
func (a *Agg) loadLocalAddrs() {
	a.bcast[netip.MustParseAddr("255.255.255.255")] = true
	ifs, err := net.Interfaces()
	if err != nil {
		return
	}
	for _, ifc := range ifs {
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, ad := range addrs {
			ipn, ok := ad.(*net.IPNet)
			if !ok {
				continue
			}
			ip := toAddr(ipn.IP)
			if !ip.IsValid() {
				continue
			}
			a.local[ip] = true
			if ip.Is4() && len(ipn.Mask) == 4 {
				b := ip.As4()
				for i := range b {
					b[i] |= ^ipn.Mask[i]
				}
				a.bcast[netip.AddrFrom4(b)] = true
			}
		}
	}
}

// IsBroadcast reads a map that is never written after NewAgg, so it needs no
// lock and is safe to call from the onNew hook.
func (a *Agg) IsBroadcast(ip netip.Addr) bool { return a.bcast[ip] }

// Add classifies a packet and folds it into flows, hosts and stats.
func (a *Agg) Add(p Packet) {
	a.mu.Lock()
	newRemote := a.add(p)
	a.mu.Unlock()
	// Run the hook outside the lock so it may call back into Agg.
	if newRemote.IsValid() && a.onNew != nil {
		a.onNew(newRemote)
	}
}

// AddStubDNS logs a DNS packet seen on the local resolver stub (127.0.0.53).
// Those packets show every lookup a program makes, cache hits included, so
// once they arrive the log stops counting the resolver's upstream queries.
func (a *Agg) AddStubDNS(p Packet) {
	if p.DNS == nil {
		return
	}
	a.mu.Lock()
	a.stubDNS = true
	a.logDNS(p, true)
	a.mu.Unlock()
}

// add does the work of Add under a.mu and reports a remote address seen for the first time.
func (a *Agg) add(p Packet) (newRemote netip.Addr) {
	if p.Time.Sub(a.lastPrune) >= pruneEvery {
		a.prune(p.Time)
	}
	srcLocal, dstLocal := a.local[p.Src], a.local[p.Dst]
	var remote, local netip.Addr
	var rport, lport uint16
	switch {
	case srcLocal && dstLocal:
		p.Dir = DirLocal
		local, lport, remote, rport = p.Src, p.SPort, p.Dst, p.DPort
	case dstLocal:
		p.Dir = DirIn
		local, lport, remote, rport = p.Dst, p.DPort, p.Src, p.SPort
	case srcLocal:
		p.Dir = DirOut
		local, lport, remote, rport = p.Src, p.SPort, p.Dst, p.DPort
	default:
		// Not addressed to us: the sender is the interesting party.
		p.Dir = DirOther
		local, lport, remote, rport = p.Dst, p.DPort, p.Src, p.SPort
	}
	inbound := p.Dir == DirIn || p.Dir == DirOther
	n := uint64(p.Len)

	a.stats.Packets++
	a.stats.Bytes += n
	sec := p.Time.Unix()
	b := &a.secs[sec%bucketCap]
	if b.T != sec {
		*b = Bucket{T: sec}
	}
	b.Pkts++
	switch p.Dir {
	case DirIn:
		a.stats.PktsIn++
		a.stats.BytesIn += n
		b.In += n
	case DirOut, DirLocal:
		a.stats.PktsOut++
		a.stats.BytesOut += n
		b.Out += n
	default:
		a.stats.PktsOther++
		a.stats.BytesOther += n
		b.In += n
	}

	a.trackMACs(p, n)
	if p.DNS != nil && p.Dir != DirOther {
		a.logDNS(p, false)
	}

	key := FlowKey{Proto: p.Proto, Remote: remote, RemotePort: rport, Local: local, LocalPort: lport}
	f := a.flows[key]
	newFlow := f == nil
	if newFlow {
		f = &Flow{Key: key, Dir: p.Dir, First: p.Time, Name: a.names[remote].name}
		a.flows[key] = f
	}
	f.Last = p.Time
	if inbound {
		f.PktsIn++
		f.BytesIn += n
		if p.TTL != 0 {
			f.TTL = p.TTL
		}
	} else {
		f.PktsOut++
		f.BytesOut += n
	}

	h := a.hosts[remote]
	if h == nil {
		h = &Host{IP: remote, First: p.Time, Ports: map[uint16]uint64{}, LocalPorts: map[uint16]uint64{},
			Protos: map[string]uint64{}, Names: map[string]uint64{}, Procs: map[string]uint64{}}
		a.hosts[remote] = h
		newRemote = remote
	}
	h.gen++
	h.Last = p.Time
	if inbound {
		h.PktsIn++
		h.BytesIn += n
		if p.TTL != 0 {
			h.TTL = p.TTL
		}
	} else {
		h.PktsOut++
		h.BytesOut += n
	}
	if newFlow {
		h.Flows++
		if f.Name != "" {
			h.Names[f.Name]++
		}
	}
	h.Protos[p.Proto]++

	if p.Name != "" {
		h.AppName = p.Name
		if f.Name != p.Name {
			f.Name = p.Name
			h.Names[p.Name]++
		}
	}
	// Overheard traffic (broadcast, multicast, mirrored) never belonged to a
	// local socket, even when a program here listens on the same port.
	if f.Proc == "" && a.procs != nil && p.Dir != DirOther {
		if f.Proc = a.procs.Lookup(p.Proto, lport); f.Proc != "" {
			h.Procs[f.Proc]++
		}
	}

	if p.Proto == "TCP" || p.Proto == "UDP" {
		h.Ports[rport]++
		if _, seen := h.LocalPorts[lport]; !seen && p.Dir == DirIn {
			a.notePortHit(h, p.Time)
		}
		h.LocalPorts[lport]++
	}
	if p.Proto == "TCP" {
		a.trackTCP(f, h, p, inbound)
	}
	if p.Proto == "ARP" && p.SrcMAC != "" && p.Src.IsValid() && !p.Src.IsUnspecified() {
		if old, ok := a.arp[p.Src]; ok && old != p.SrcMAC {
			a.notice(p.Time, "arp", fmt.Sprintf("%s changed MAC %s → %s", p.Src, old, p.SrcMAC))
		}
		a.arp[p.Src] = p.SrcMAC
		if hs := a.hosts[p.Src]; hs != nil {
			hs.MAC = p.SrcMAC
			hs.gen++
		}
	}

	if len(f.Events) < eventCap {
		ev := FlowEvent{T: p.Time, Dir: p.Dir, Flags: p.Flags, Len: uint32(p.Payload), Seq: p.Seq, Note: p.Name}
		if p.Proto != "TCP" {
			ev.Note = p.Info
			ev.Len = uint32(p.Len)
		}
		f.Events = append(f.Events, ev)
	}

	a.recent[a.head] = p
	a.head = (a.head + 1) % recentCap
	if a.n < recentCap {
		a.n++
	}
	return newRemote
}

// logDNS records a lookup or its answer, and learns address -> name pairs so
// flows to those addresses get a name.
func (a *Agg) logDNS(p Packet, stub bool) {
	d := p.DNS
	if d.Reply {
		for _, ip := range d.Addrs {
			a.names[ip] = stamped{d.Name, p.Time}
			if h := a.hosts[ip]; h != nil && len(h.Names) == 0 {
				h.Names[d.Name]++
				h.gen++
			}
		}
	}
	if d.Name == "" || (a.stubDNS && !stub) {
		return
	}
	e := a.dns[d.Name]
	if e == nil {
		if d.Reply {
			return // an answer to a query that was not logged
		}
		if len(a.dns) >= maxDNS {
			a.evictOldestDNS()
		}
		e = &DNSEntry{Name: d.Name, First: p.Time}
		a.dns[d.Name] = e
	}
	e.Last = p.Time
	if !d.Reply {
		e.Count++
		e.Types = addUnique(e.Types, d.Type)
		if a.procs != nil {
			if proc := a.procs.Lookup("UDP", p.SPort); proc != "" {
				e.Procs = addUnique(e.Procs, proc)
			}
		}
		return
	}
	if d.Rcode != "" {
		e.Fails++
	}
	for _, ip := range d.Addrs {
		e.Answers = addUnique(e.Answers, ip)
	}
	for _, c := range d.CNAMEs {
		e.CNAMEs = addUnique(e.CNAMEs, c)
	}
}

// addUnique appends v unless present, keeping at most listCap items.
func addUnique[T comparable](list []T, v T) []T {
	if slices.Contains(list, v) || len(list) >= listCap {
		return list
	}
	return append(list, v)
}

func (a *Agg) evictOldestDNS() {
	var oldest *DNSEntry
	for _, e := range a.dns {
		if oldest == nil || e.Last.Before(oldest.Last) {
			oldest = e
		}
	}
	if oldest != nil {
		delete(a.dns, oldest.Name)
	}
}

// prune drops idle entries and trims every table to its cap.
func (a *Agg) prune(now time.Time) {
	a.lastPrune = now
	for k, f := range a.flows {
		if now.Sub(f.Last) > flowIdle {
			delete(a.flows, k)
		}
	}
	trimOldest(a.flows, maxFlows, func(f *Flow) time.Time { return f.Last })
	for ip, h := range a.hosts {
		if now.Sub(h.Last) > hostIdle {
			delete(a.hosts, ip)
		}
	}
	trimOldest(a.hosts, maxHosts, func(h *Host) time.Time { return h.Last })
	for ip := range a.hostCopies {
		if a.hosts[ip] == nil {
			delete(a.hostCopies, ip)
		}
	}
	for _, m := range []map[netip.Addr]stamped{a.names, a.lanNames} {
		for ip, s := range m {
			if now.Sub(s.t) > nameTTL {
				delete(m, ip)
			}
		}
		trimOldest(m, maxNames, func(s stamped) time.Time { return s.t })
	}
	for name, e := range a.dns {
		if now.Sub(e.Last) > nameTTL {
			delete(a.dns, name)
		}
	}
	for mac, mi := range a.macs {
		if now.Sub(mi.Last) > nameTTL && mi.Hostname == "" {
			delete(a.macs, mac)
		}
	}
}

// trimOldest deletes the least recently seen entries until m holds at most limit,
// leaving 10% headroom so the next prune has work only when traffic grows again.
func trimOldest[K comparable, V any](m map[K]V, limit int, last func(V) time.Time) {
	if len(m) <= limit {
		return
	}
	keys := slices.Collect(maps.Keys(m))
	slices.SortFunc(keys, func(x, y K) int { return last(m[x]).Compare(last(m[y])) })
	for _, k := range keys[:len(keys)-limit*9/10] {
		delete(m, k)
	}
}

// lanAddr reports whether an address can belong to a device on the local segment.
func lanAddr(ip netip.Addr) bool {
	return ip.IsValid() && !ip.IsUnspecified() && (ip.IsPrivate() || ip.IsLinkLocalUnicast())
}

func unicastMAC(mac string) bool {
	return mac != "" && mac != "00:00:00:00:00:00" && !isGroupMAC(mac)
}

// isGroupMAC is true for multicast and broadcast hardware addresses (low bit of the first byte).
func isGroupMAC(mac string) bool {
	hw, err := net.ParseMAC(mac)
	return err == nil && len(hw) > 0 && hw[0]&1 == 1
}

func (a *Agg) macEntry(mac string) *MacInfo {
	mi := a.macs[mac]
	if mi == nil {
		if len(a.macs) >= macCap {
			return nil
		}
		mi = &MacInfo{MAC: mac, IPs: map[netip.Addr]time.Time{}}
		a.macs[mac] = mi
	}
	return mi
}

// trackMACs ties hardware addresses to LAN addresses and counts bytes per device.
func (a *Agg) trackMACs(p Packet, n uint64) {
	if unicastMAC(p.SrcMAC) {
		if mi := a.macEntry(p.SrcMAC); mi != nil {
			mi.BytesFrom += n
			mi.Last = p.Time
			if lanAddr(p.Src) {
				mi.IPs[p.Src] = p.Time
			}
		}
	}
	if unicastMAC(p.DstMAC) {
		if mi := a.macEntry(p.DstMAC); mi != nil {
			mi.BytesTo += n
			if lanAddr(p.Dst) {
				mi.IPs[p.Dst] = p.Time
			}
		}
	}
	for _, na := range p.LANName {
		a.lanNames[na.Addr] = stamped{na.Name, p.Time}
	}
	if p.DHCP != nil && unicastMAC(p.DHCP.MAC) {
		if mi := a.macEntry(p.DHCP.MAC); mi != nil {
			if p.DHCP.Hostname != "" {
				mi.Hostname = p.DHCP.Hostname
			}
			if p.DHCP.Vendor != "" {
				mi.Vendor = p.DHCP.Vendor
			}
		}
	}
}

// trackTCP records sequence bases and measures the handshake round trip.
func (a *Agg) trackTCP(f *Flow, h *Host, p Packet, inbound bool) {
	side := 0
	if inbound {
		side = 1
	}
	if !f.ISNSet[side] {
		f.ISN[side] = p.Seq
		f.ISNSet[side] = true
	}
	switch p.Flags {
	case "SYN":
		f.synAt = p.Time
		if p.Dir == DirIn && a.kindOf != nil && a.kindOf(f.Key.Remote) == "public" && p.Time.Sub(h.synNoticeAt) > time.Minute {
			h.synNoticeAt = p.Time
			a.notice(p.Time, "inbound", fmt.Sprintf("%s opened TCP to local port %d", f.Key.Remote, f.Key.LocalPort))
		}
	case "SYN,ACK":
		if f.Dir == DirOut && !f.synAt.IsZero() && f.RTT == 0 {
			f.RTT = p.Time.Sub(f.synAt)
		}
		f.synAckAt = p.Time
	case "ACK":
		if f.Dir == DirIn && !f.synAckAt.IsZero() && f.RTT == 0 && inbound {
			f.RTT = p.Time.Sub(f.synAckAt)
		}
	}
}

// notePortHit flags a remote that touches many distinct local ports in a few seconds.
func (a *Agg) notePortHit(h *Host, t time.Time) {
	h.portHits = append(h.portHits, t)
	cut := 0
	for cut < len(h.portHits) && t.Sub(h.portHits[cut]) > 5*time.Second {
		cut++
	}
	h.portHits = h.portHits[cut:]
	if len(h.portHits) >= 10 && t.Sub(h.scanNoticeAt) > time.Minute {
		h.scanNoticeAt = t
		h.portHits = h.portHits[:0]
		a.notice(t, "scan", fmt.Sprintf("%s hit 10+ local ports in 5s", h.IP))
	}
}

func (a *Agg) notice(t time.Time, kind, text string) {
	a.notices = append(a.notices, Notice{T: t, Kind: kind, Text: text})
	if len(a.notices) > noticeCap {
		a.notices = slices.Clone(a.notices[len(a.notices)-noticeCap:])
	}
}

// AddNotice records a notice raised outside the capture path.
func (a *Agg) AddNotice(kind, text string) {
	a.mu.Lock()
	a.notice(time.Now(), kind, text)
	a.mu.Unlock()
}

func (a *Agg) SetDropped(d int) {
	a.mu.Lock()
	a.stats.Dropped = d
	a.mu.Unlock()
}

// Reset clears all counters but keeps local address knowledge.
func (a *Agg) Reset() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.clear()
}

// Snapshot holds copies safe for the UI goroutine to read.
type Snapshot struct {
	Flows    []Flow
	Hosts    []Host
	Packets  []Packet   // newest first; only with SnapOpts.Packets
	DNS      []DNSEntry // only with SnapOpts.DNS
	StubDNS  bool
	Buckets  []Bucket // last 60 seconds, oldest first
	Notices  []Notice // newest first
	Macs     []MacInfo
	LANNames map[netip.Addr]string
	Stats    Stats
}

// SnapOpts selects the expensive parts of a snapshot, so the UI copies only
// what the current view shows.
type SnapOpts struct {
	Packets bool
	DNS     bool
}

func (a *Agg) Snapshot(o SnapOpts) Snapshot {
	a.mu.Lock()
	defer a.mu.Unlock()
	s := Snapshot{Stats: a.stats, StubDNS: a.stubDNS}
	s.Flows = make([]Flow, 0, len(a.flows))
	for _, f := range a.flows {
		c := *f
		c.Events = slices.Clip(f.Events) // appends beyond len never touch the shared prefix
		s.Flows = append(s.Flows, c)
	}
	s.Hosts = make([]Host, 0, len(a.hosts))
	for ip, h := range a.hosts {
		c, ok := a.hostCopies[ip]
		if !ok || c.gen != h.gen {
			c = *h
			c.Ports, c.LocalPorts = maps.Clone(h.Ports), maps.Clone(h.LocalPorts)
			c.Protos, c.Names, c.Procs = maps.Clone(h.Protos), maps.Clone(h.Names), maps.Clone(h.Procs)
			c.portHits = nil
			a.hostCopies[ip] = c
		}
		s.Hosts = append(s.Hosts, c)
	}
	if o.Packets {
		s.Packets = make([]Packet, 0, a.n)
		for i := 0; i < a.n; i++ {
			s.Packets = append(s.Packets, a.recent[(a.head-1-i+recentCap)%recentCap])
		}
	}
	if o.DNS {
		s.DNS = make([]DNSEntry, 0, len(a.dns))
		for _, e := range a.dns {
			c := *e
			c.Types, c.Answers, c.CNAMEs, c.Procs = slices.Clone(e.Types), slices.Clone(e.Answers), slices.Clone(e.CNAMEs), slices.Clone(e.Procs)
			s.DNS = append(s.DNS, c)
		}
	}
	now := time.Now().Unix()
	s.Buckets = make([]Bucket, 60)
	for i := range s.Buckets {
		sec := now - int64(59-i)
		s.Buckets[i].T = sec
		if b := a.secs[sec%bucketCap]; b.T == sec {
			s.Buckets[i] = b
		}
	}
	for _, mi := range a.macs {
		c := *mi
		c.IPs = maps.Clone(mi.IPs)
		s.Macs = append(s.Macs, c)
	}
	s.LANNames = make(map[netip.Addr]string, len(a.lanNames))
	for k, v := range a.lanNames {
		s.LANNames[k] = v.name
	}
	s.Notices = slices.Clone(a.notices)
	slices.Reverse(s.Notices)
	return s
}

// topN returns map keys sorted by value, largest first, ties by key.
func topN[K cmp.Ordered](m map[K]uint64, n int) []K {
	ks := slices.Collect(maps.Keys(m))
	slices.SortFunc(ks, func(x, y K) int {
		if c := cmp.Compare(m[y], m[x]); c != 0 {
			return c
		}
		return cmp.Compare(x, y)
	})
	return ks[:min(n, len(ks))]
}
