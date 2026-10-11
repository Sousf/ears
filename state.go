package main

import (
	"fmt"
	"net"
	"net/netip"
	"sort"
	"sync"
	"time"
)

const (
	recentCap = 5000
	bucketCap = 120
	noticeCap = 500
)

// Agg owns all counters. The capture goroutine writes, the UI snapshots.
type Agg struct {
	mu    sync.Mutex
	local map[netip.Addr]bool
	bcast map[netip.Addr]bool
	flows map[FlowKey]*Flow
	hosts map[netip.Addr]*Host
	names map[netip.Addr]string // DNS-learned: address -> queried name
	arp   map[netip.Addr]string // address -> MAC claimed in ARP

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
	a := &Agg{
		local:  map[netip.Addr]bool{},
		bcast:  map[netip.Addr]bool{},
		flows:  map[FlowKey]*Flow{},
		hosts:  map[netip.Addr]*Host{},
		names:  map[netip.Addr]string{},
		arp:    map[netip.Addr]string{},
		recent: make([]Packet, recentCap),
		onNew:  onNew,
	}
	a.stats.Start = time.Now()
	a.loadLocalAddrs()
	return a
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

// IsLocal and IsBroadcast read maps that are never written after NewAgg,
// so they need no lock and are safe to call from the onNew hook.
func (a *Agg) IsLocal(ip netip.Addr) bool     { return a.local[ip] }
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

// add does the work of Add under a.mu and reports a remote address seen for the first time.
func (a *Agg) add(p Packet) (newRemote netip.Addr) {
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

	// DNS answers teach us names for addresses we will see shortly.
	if p.DNS != nil {
		for _, ip := range p.DNS.Addrs {
			a.names[ip] = p.DNS.Query
			if h := a.hosts[ip]; h != nil && len(h.Names) == 0 {
				h.Names[p.DNS.Query]++
			}
		}
	}

	key := FlowKey{Proto: p.Proto, Remote: remote, RemotePort: rport, Local: local, LocalPort: lport}
	f := a.flows[key]
	newFlow := f == nil
	if newFlow {
		f = &Flow{Key: key, Dir: p.Dir, First: p.Time, Name: a.names[remote]}
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
		if name := a.names[remote]; name != "" {
			h.Names[name]++
		}
	}
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
	if f.Proc == "" && a.procs != nil {
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
			a.notice(p.Time, "arp", fmt.Sprintf("%s changed MAC from %s to %s (ARP spoofing, or a replaced device)", p.Src, old, p.SrcMAC))
		}
		a.arp[p.Src] = p.SrcMAC
		if hs := a.hosts[p.Src]; hs != nil {
			hs.MAC = p.SrcMAC
		}
	}

	if len(f.Events) < eventCap {
		ev := FlowEvent{T: p.Time, Dir: p.Dir, Flags: p.Flags, Len: p.Payload, Seq: p.Seq, Note: p.Name}
		if p.Proto != "TCP" {
			ev.Note = p.Info
			ev.Len = p.Len
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
			a.notice(p.Time, "inbound", fmt.Sprintf("%s (public) opened a TCP connection to local port %d", f.Key.Remote, f.Key.LocalPort))
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
		a.notice(t, "scan", fmt.Sprintf("%s hit 10+ different local ports within 5 s (port scan?)", h.IP))
	}
}

func (a *Agg) notice(t time.Time, kind, text string) {
	a.notices = append(a.notices, Notice{T: t, Kind: kind, Text: text})
	if len(a.notices) > noticeCap {
		a.notices = a.notices[len(a.notices)-noticeCap:]
	}
}

// AddNotice records a notice raised outside the capture path (e.g. by the UI).
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
	a.flows = map[FlowKey]*Flow{}
	a.hosts = map[netip.Addr]*Host{}
	a.notices = nil
	a.secs = [bucketCap]Bucket{}
	a.head, a.n = 0, 0
	a.stats = Stats{Start: time.Now()}
}

// Snapshot returns copies safe for the UI goroutine to read.
type Snapshot struct {
	Flows   []Flow
	Hosts   []Host
	Packets []Packet // newest first
	Buckets []Bucket // last 60 seconds, oldest first
	Notices []Notice // newest first
	Stats   Stats
}

func (a *Agg) Snapshot() Snapshot {
	a.mu.Lock()
	defer a.mu.Unlock()
	s := Snapshot{Stats: a.stats}
	s.Flows = make([]Flow, 0, len(a.flows))
	for _, f := range a.flows {
		s.Flows = append(s.Flows, *f)
	}
	s.Hosts = make([]Host, 0, len(a.hosts))
	for _, h := range a.hosts {
		c := *h
		c.Ports = copyMap(h.Ports)
		c.LocalPorts = copyMap(h.LocalPorts)
		c.Protos = copyMapS(h.Protos)
		c.Names = copyMapS(h.Names)
		c.Procs = copyMapS(h.Procs)
		c.portHits = nil
		s.Hosts = append(s.Hosts, c)
	}
	s.Packets = make([]Packet, 0, a.n)
	for i := 0; i < a.n; i++ {
		idx := (a.head - 1 - i + recentCap) % recentCap
		s.Packets = append(s.Packets, a.recent[idx])
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
	s.Notices = make([]Notice, len(a.notices))
	for i, n := range a.notices {
		s.Notices[len(a.notices)-1-i] = n
	}
	return s
}

func copyMap(m map[uint16]uint64) map[uint16]uint64 {
	c := make(map[uint16]uint64, len(m))
	for k, v := range m {
		c[k] = v
	}
	return c
}

func copyMapS(m map[string]uint64) map[string]uint64 {
	c := make(map[string]uint64, len(m))
	for k, v := range m {
		c[k] = v
	}
	return c
}

// topPorts returns ports sorted by packet count, most first.
func topPorts(m map[uint16]uint64, max int) []uint16 {
	ps := make([]uint16, 0, len(m))
	for p := range m {
		ps = append(ps, p)
	}
	sort.Slice(ps, func(i, j int) bool {
		if m[ps[i]] != m[ps[j]] {
			return m[ps[i]] > m[ps[j]]
		}
		return ps[i] < ps[j]
	})
	if len(ps) > max {
		ps = ps[:max]
	}
	return ps
}

// topKeys returns map keys sorted by value, largest first.
func topKeys(m map[string]uint64, max int) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Slice(ks, func(i, j int) bool {
		if m[ks[i]] != m[ks[j]] {
			return m[ks[i]] > m[ks[j]]
		}
		return ks[i] < ks[j]
	})
	if len(ks) > max {
		ks = ks[:max]
	}
	return ks
}
