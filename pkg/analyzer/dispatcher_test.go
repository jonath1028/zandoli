package analyzer_test

import (
	"strings"
	"sync"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"zandoli/pkg/analyzer"
)

func makeDummyPacket() gopacket.Packet {
	buf := gopacket.NewSerializeBuffer()
	_ = gopacket.SerializeLayers(buf, gopacket.SerializeOptions{},
		&layers.Ethernet{
			SrcMAC:       []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
			DstMAC:       []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
			EthernetType: layers.EthernetTypeIPv4,
		},
	)
	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}

func TestHandlePacket_AnalyzerOrder(t *testing.T) {
	var trace strings.Builder
	var mu sync.Mutex

	analyzer.ActiveAnalyzers = []func(gopacket.Packet){
		func(p gopacket.Packet) { mu.Lock(); trace.WriteString("A"); mu.Unlock() },
		func(p gopacket.Packet) { mu.Lock(); trace.WriteString("B"); mu.Unlock() },
		func(p gopacket.Packet) { mu.Lock(); trace.WriteString("C"); mu.Unlock() },
		func(p gopacket.Packet) { mu.Lock(); trace.WriteString("D"); mu.Unlock() },
		func(p gopacket.Packet) { mu.Lock(); trace.WriteString("E"); mu.Unlock() },
	}

	packet := makeDummyPacket()
	analyzer.HandlePacket(packet)

	assert.Equal(t, "ABCDE", trace.String(), "Analyzers should be called in exact order")
}

func TestHandlePacket_AnalyzerWithPanic(t *testing.T) {
	var trace strings.Builder
	var mu sync.Mutex

	analyzer.ActiveAnalyzers = []func(gopacket.Packet){
		func(p gopacket.Packet) { mu.Lock(); trace.WriteString("A"); mu.Unlock() },
		func(p gopacket.Packet) { panic("intentional panic") },
		func(p gopacket.Packet) { mu.Lock(); trace.WriteString("C"); mu.Unlock() },
	}

	packet := makeDummyPacket()
	analyzer.HandlePacket(packet)

	assert.Equal(t, "AC", trace.String(), "Analyzers before and after panic should still be executed")
}

func TestHandlePacket_MultiplePanics(t *testing.T) {
	var trace strings.Builder
	var mu sync.Mutex

	analyzer.ActiveAnalyzers = []func(gopacket.Packet){
		func(p gopacket.Packet) { panic("P1") },
		func(p gopacket.Packet) { mu.Lock(); trace.WriteString("B"); mu.Unlock() },
		func(p gopacket.Packet) { panic("P2") },
		func(p gopacket.Packet) { mu.Lock(); trace.WriteString("D"); mu.Unlock() },
	}

	packet := makeDummyPacket()
	analyzer.HandlePacket(packet)

	assert.Equal(t, "BD", trace.String(), "Analyzers after panics should still execute")
}

func TestHandlePacket_MutatesPacket(t *testing.T) {
	var trace strings.Builder
	var mu sync.Mutex

	packetBytes := []byte{0xde, 0xad, 0xbe, 0xef}
	packet := gopacket.NewPacket(packetBytes, layers.LayerTypeEthernet, gopacket.Default)

	analyzer.ActiveAnalyzers = []func(gopacket.Packet){
		func(p gopacket.Packet) {
			copy(packetBytes, []byte{0x00, 0x00, 0x00, 0x00})
			mu.Lock(); trace.WriteString("A"); mu.Unlock()
		},
		func(p gopacket.Packet) {
			mu.Lock(); trace.WriteString("B"); mu.Unlock()
		},
	}

	analyzer.HandlePacket(packet)
	assert.Equal(t, "AB", trace.String(), "Packet mutation should not interrupt analyzer chain")
}

func TestHandlePacket_EmptyAnalyzerList(t *testing.T) {
	analyzer.ActiveAnalyzers = []func(gopacket.Packet){}
	packet := makeDummyPacket()
	analyzer.HandlePacket(packet)
	// No assert needed: success = no panic
}

