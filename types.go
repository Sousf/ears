package main

import (
	"net/netip"
	"time"
)

// Direction says how a packet relates to this machine.
type Direction uint8

const (
	DirIn    Direction = iota // remote -> this machine
	DirOut                    // this machine -> remote
	DirLocal                  // both ends on this machine (loopback)
	DirOther                  // neither end is this machine: broadcast, multicast, mirrored traffic
)

func (d Direction) String() string {
	switch d {
	case DirIn:
		return "in"
	case DirOut:
		return "out"
	case DirLocal:
		return "local"
	default:
		return "other"
	}
}

// rawCap caps how many bytes of each frame are kept for the decode view.
const rawCap = 2048

// Packet is the decoded summary of one captured frame.
type Packet struct {
	Time    time.Time
	Len     int // frame length on the wire
	Payload int // transport payload bytes
	Proto   string
	Src     netip.Addr
	Dst     netip.Addr
	SPort   uint16
	DPort   uint16
	Info    string
	Dir     Direction
	TTL     uint8
	Flags   string // TCP flags, e.g. "SYN,ACK"
	Seq     uint32
	Ack     uint32
	Name    string     // server name from TLS SNI or HTTP Host
	SrcMAC  string     // Ethernet source (or ARP sender) hardware address
	DstMAC  string     // Ethernet destination
	LANName []NameAddr // names announced over mDNS
	DHCP    *DHCPInfo  // hostname and vendor from a DHCP request
	DNS     *DNSMsg    // set on unicast DNS (port 53) queries and replies
	Raw     []byte     // the frame, borrowed from the capture buffer until Agg.Add copies it
	ID      uint64     // capture sequence number, for fetching the bytes back with Agg.Raw
}

type NameAddr struct {
	Name string
	Addr netip.Addr
}

type DHCPInfo struct {
	MAC      string
	Hostname string
	Vendor   string // vendor class, e.g. "android-dhcp-14" or "MSFT 5.0"
}

// MacInfo is what the capture has learned about one hardware address.
type MacInfo struct {
	MAC       string
	IPs       map[netip.Addr]time.Time // LAN addresses seen with this MAC
	BytesFrom uint64
	BytesTo   uint64
	Last      time.Time
	Hostname  string // from DHCP
	Vendor    string // DHCP vendor class
}

type DNSMsg struct {
	Reply  bool
	Name   string
	Type   string
	Rcode  string // "" for no error, else e.g. "Non-Existent Domain"
	Addrs  []netip.Addr
	CNAMEs []string
}

// DNSEntry is the DNS log's record of one queried name.
type DNSEntry struct {
	Name    string
	Types   []string
	Count   int // queries
	Fails   int // error replies (no such domain, server failure)
	First   time.Time
	Last    time.Time
	Answers []netip.Addr
	CNAMEs  []string
	Procs   []string
	gen     uint64 // bumped on every change; lets Snapshot reuse an unchanged copy
}

// FlowKey identifies a conversation between a remote endpoint and a local one.
type FlowKey struct {
	Proto      string
	Remote     netip.Addr
	RemotePort uint16
	Local      netip.Addr
	LocalPort  uint16
}

// FlowEvent is one packet of a flow, kept for the timeline view.
type FlowEvent struct {
	T     time.Time
	Flags string // shares the static strings from tcpFlags
	Note  string
	Len   uint32 // payload bytes
	Seq   uint32
	Dir   Direction
}

const eventCap = 32

type Flow struct {
	Key      FlowKey
	Dir      Direction // direction of the first packet seen
	PktsIn   uint64
	PktsOut  uint64
	BytesIn  uint64
	BytesOut uint64
	First    time.Time
	Last     time.Time
	Name     string        // TLS SNI, HTTP Host, or the DNS name that resolved to the remote
	Proc     string        // local process owning the socket, if known
	TTL      uint8         // last TTL seen from the remote
	RTT      time.Duration // handshake round trip
	Events   []FlowEvent
	ISN      [2]uint32 // initial sequence numbers: [0] out, [1] in
	ISNSet   [2]bool
	synAt    time.Time
	synAckAt time.Time
}

func (f *Flow) Pkts() uint64  { return f.PktsIn + f.PktsOut }
func (f *Flow) Bytes() uint64 { return f.BytesIn + f.BytesOut }

// Host aggregates everything seen from or to one remote address.
type Host struct {
	IP         netip.Addr
	PktsIn     uint64
	PktsOut    uint64
	BytesIn    uint64
	BytesOut   uint64
	First      time.Time
	Last       time.Time
	Ports      map[uint16]uint64 // remote-side ports -> packets
	LocalPorts map[uint16]uint64 // ports on this machine -> packets
	Protos     map[string]uint64
	Names      map[string]uint64 // server names seen for this address -> flows
	AppName    string            // last name seen in TLS SNI or HTTP Host
	Procs      map[string]uint64 // local processes that talked to it -> flows
	MAC        string
	TTL        uint8
	Flows      int

	gen          uint64      // bumped on every change; lets Snapshot reuse an unchanged copy
	portHits     []time.Time // first-contact times of new local ports, for scan detection
	scanNoticeAt time.Time
	synNoticeAt  time.Time
}

func (h *Host) Pkts() uint64  { return h.PktsIn + h.PktsOut }
func (h *Host) Bytes() uint64 { return h.BytesIn + h.BytesOut }

// BestName is the most informative name known for the host: the name an
// application asked for in TLS or HTTP, else the most frequent DNS name.
func (h *Host) BestName() string {
	if h.AppName != "" {
		return h.AppName
	}
	var best string
	var n uint64
	for name, c := range h.Names {
		if c > n || (c == n && name < best) {
			best, n = name, c
		}
	}
	return best
}

type Stats struct {
	Start      time.Time
	Packets    uint64
	Bytes      uint64
	PktsIn     uint64
	BytesIn    uint64
	PktsOut    uint64
	BytesOut   uint64
	PktsOther  uint64
	BytesOther uint64
	Dropped    int
}

// Bucket is one second of traffic.
type Bucket struct {
	T    int64 // unix seconds
	In   uint64
	Out  uint64
	Pkts uint64
}

type Notice struct {
	T    time.Time
	Kind string
	Text string
}
