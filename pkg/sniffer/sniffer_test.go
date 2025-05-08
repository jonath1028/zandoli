package sniffer

import (
	"net"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/stretchr/testify/assert"
)

func getTestInterface() string {
	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback == 0 && iface.Flags&net.FlagUp != 0 {
			return iface.Name
		}
	}
	return "eth0"
}

func TestHandleOpenClose(t *testing.T) {
	iface := getTestInterface()

	t.Logf("[TEST] Opening handle on interface: %s", iface)
	start := time.Now()

	handle, err := pcap.OpenLive(iface, 65536, true, pcap.BlockForever)
	assert.NoError(t, err)

	go func() {
		time.Sleep(1 * time.Second)
		handle.Close()
	}()

	time.Sleep(2 * time.Second)

	elapsed := time.Since(start)
	assert.Less(t, elapsed.Seconds(), 5.0)
}

func TestHandleWithTimeout(t *testing.T) {
	iface := getTestInterface()

	start := time.Now()
	handle, err := pcap.OpenLive(iface, 65536, true, 500*time.Millisecond)
	assert.NoError(t, err)

	time.Sleep(500 * time.Millisecond)
	handle.Close()

	elapsed := time.Since(start)
	assert.Less(t, elapsed.Seconds(), 5.0)
}

func TestPacketSourceDrainBlocking(t *testing.T) {
	iface := getTestInterface()

	handle, err := pcap.OpenLive(iface, 65536, true, 500*time.Millisecond)
	assert.NoError(t, err)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()

	done := make(chan struct{})

	go func() {
		time.Sleep(1 * time.Second)
		handle.Close()
		close(done)
	}()

	// Vidage explicite du canal (évite blocage Go vet)
	go func() {
		for range packets {
		}
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Error("[ERROR] Blocking detected: packetSource likely holding up handle closure")
	}
}
