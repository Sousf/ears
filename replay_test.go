package main

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// writePcap saves frames one second apart, starting long ago.
func writePcap(t *testing.T, frames ...[]byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "in.pcap")
	fh, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	w := pcapgo.NewWriter(fh)
	if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatal(err)
	}
	base := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	for i, f := range frames {
		if err := w.WritePacket(ciAt(len(f), base.Add(time.Duration(i)*time.Second)), f); err != nil {
			t.Fatal(err)
		}
	}
	if err := fh.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

// replayAll runs a replay to the end of the file and returns what it decoded.
func replayAll(t *testing.T, c *Capture) []Packet {
	t.Helper()
	if err := c.Open(); err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	var got []Packet
	errs := make(chan error, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c.Run(ctx, func(p Packet) {
		p.Raw = slices.Clone(p.Raw) // borrowed from the capture buffer
		got = append(got, p)
	}, errs)
	select {
	case err := <-errs:
		t.Fatalf("replay error: %v", err)
	default:
	}
	if !c.Ended() {
		t.Fatal("replay did not reach the end of the file")
	}
	return got
}

func TestReplay(t *testing.T) {
	path := writePcap(t,
		dnsFrame(t, "10.0.0.23", "10.0.0.1", false),
		dnsFrame(t, "10.0.0.1", "10.0.0.23", true),
		tcpFrame(t, "10.0.0.23", "203.0.113.5", 40000, 443, "SYN", nil),
	)
	start := time.Now()
	got := replayAll(t, &Capture{ReadFrom: path, Speed: 0})
	if len(got) != 3 || got[2].Proto != "TCP" || got[1].DNS == nil || !got[1].DNS.Reply {
		t.Fatalf("replayed %d packets: %+v", len(got), got)
	}
	for _, p := range got {
		if p.Time.Before(start) {
			t.Fatalf("timestamp %v not moved to the wall clock", p.Time)
		}
	}

	got = replayAll(t, &Capture{ReadFrom: path, Filter: "tcp"})
	if len(got) != 1 || got[0].DPort != 443 {
		t.Fatalf("filtered replay: %+v", got)
	}
}

func TestReplayPacing(t *testing.T) {
	var p pacer
	ctx := context.Background()
	t0 := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	a, _ := p.wait(ctx, t0, 100)
	b, ok := p.wait(ctx, t0.Add(2*time.Second), 100)
	if !ok || b.Sub(a) != 20*time.Millisecond {
		t.Fatalf("2s at 100x spaced %v", b.Sub(a))
	}
	if time.Now().Before(b) {
		t.Fatal("wait returned before the frame was due")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, ok := p.wait(cancelled, t0.Add(time.Hour), 1); ok {
		t.Fatal("wait ignored a cancelled context")
	}
}

func TestSiteOf(t *testing.T) {
	var pkts []Packet
	for _, f := range [][]byte{
		dnsFrame(t, "10.0.0.23", "10.0.0.1", false),
		dnsFrame(t, "10.0.0.1", "10.0.0.23", true),
		tcpFrame(t, "10.0.0.23", "203.0.113.5", 40000, 443, "SYN", nil),
		tcpFrame(t, "203.0.113.5", "10.0.0.23", 443, 40000, "SYN,ACK", nil),
		arpFrame(t, macB, []byte{10, 0, 0, 1}, []byte{10, 0, 0, 23}),
	} {
		p, ok := decode(f, layers.LinkTypeEthernet, ci(len(f)), opts)
		if !ok {
			t.Fatal("decode failed")
		}
		pkts = append(pkts, p)
	}
	s := siteOf(slices.Values(pkts))
	if s.LocalIP != netip.MustParseAddr("10.0.0.23") || s.LocalMAC != macA.String() ||
		s.Subnet != netip.MustParsePrefix("10.0.0.0/24") || s.Gateway != netip.MustParseAddr("10.0.0.1") ||
		len(s.DNS) != 1 || s.DNS[0] != s.Gateway {
		t.Fatalf("site: %+v", s)
	}

	agg := NewAgg(nil)
	agg.SetLocal(s.LocalIP, s.Subnet)
	if !agg.IsBroadcast(netip.MustParseAddr("10.0.0.255")) || agg.IsBroadcast(netip.MustParseAddr("10.0.0.254")) {
		t.Fatal("subnet broadcast not derived from the replayed site")
	}
	agg.Add(pkts[2])
	if f := agg.Snapshot(SnapOpts{}).Flows; len(f) != 1 || f[0].Dir != DirOut {
		t.Fatalf("direction not judged from the recording machine: %+v", f)
	}
}

// The committed demo capture must keep describing the made-up site.
func TestDemoPcap(t *testing.T) {
	s, err := inferSite("testdata/demo.pcap")
	if err != nil {
		t.Fatal(err)
	}
	if s.LocalIP != netip.MustParseAddr("10.0.0.23") || s.Gateway != netip.MustParseAddr("10.0.0.1") {
		t.Fatalf("demo site: %+v", s)
	}
}
