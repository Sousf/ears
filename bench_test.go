package main

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/google/gopacket/layers"
)

// fullModel fills the aggregator to its flow and host caps.
func fullModel(b *testing.B) model {
	t := &testing.T{}
	agg, res := testAgg(t)
	now := time.Now()
	local := netip.MustParseAddr("192.168.1.117")
	for i := 0; i < maxFlows; i++ {
		remote := netip.AddrFrom4([4]byte{byte(20 + i%200), byte(i / 200), 1, byte(i % 7)})
		agg.Add(Packet{Time: now, Len: 1200, Proto: "TCP", Src: local, Dst: remote, SPort: uint16(30000 + i), DPort: 443, Flags: "ACK", Raw: make([]byte, 1200)})
	}
	m := newModel(agg, res, &Capture{}, make(chan error), "wlan0", "")
	mm, _ := m.Update(tea.WindowSizeMsg{Width: 160, Height: 50})
	return mm.(model)
}

func BenchmarkDecodeAdd(b *testing.B) {
	t := &testing.T{}
	agg, _ := testAgg(t)
	f := tcpFrame(t, "203.0.113.5", "192.168.1.117", 443, 40000, "PSH,ACK", make([]byte, 1200))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		p, _ := decode(f, layers.LinkTypeEthernet, ci(len(f)), opts)
		agg.Add(p)
	}
}

// BenchmarkTick is one half-second refresh with full tables: snapshot,
// filter and sort, and a frame of the Flows view.
func BenchmarkTick(b *testing.B) {
	m := fullModel(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mm, _ := m.Update(tickMsg(time.Now()))
		m = mm.(model)
		_ = m.View()
	}
}

// BenchmarkMapFrame is one animation frame of the Map view.
func BenchmarkMapFrame(b *testing.B) {
	m := fullModel(b)
	m.setView(viewMap)
	m.tv.Subnet = netip.MustParsePrefix("192.168.1.0/24")
	for i := 2; i < 12; i++ {
		m.tv.ARP = append(m.tv.ARP, ARPEntry{IP: netip.AddrFrom4([4]byte{192, 168, 1, byte(i)}), MAC: fmt.Sprintf("00:68:eb:01:02:%02x", i), Iface: "wlan0"})
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mm, _ := m.Update(animMsg{})
		m = mm.(model)
		_ = m.View()
	}
}
