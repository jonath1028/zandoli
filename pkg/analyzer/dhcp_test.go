package analyzer

import (
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"zandoli/pkg/sniffer"
)

func TestAnalyzeDHCP_MinimalDetection(t *testing.T) {
	// Reset
	sniffer.DiscoveredHosts = nil

	// IP cible
	ipv4 := net.IPv4(192, 168, 1, 42)
	mac := net.HardwareAddr{0x00, 0x0c, 0x29, 0xaa, 0xbb, 0xcc}

	// Crée un host simulé
	host := sniffer.NewHost(ipv4, mac, "passive")
	sniffer.DiscoveredHosts = append(sniffer.DiscoveredHosts, host)

	// Forge un paquet DHCP (minimal)
	dhcp := &layers.DHCPv4{
		Operation:    layers.DHCPOpReply,
		ClientIP:     net.IPv4zero,
		YourClientIP: ipv4,
	}

	udp := &layers.UDP{
		SrcPort: 67,
		DstPort: 68,
	}

	ip := &layers.IPv4{
		SrcIP:    net.IPv4(10, 0, 0, 1),
		DstIP:    net.IPv4(255, 255, 255, 255),
		Protocol: layers.IPProtocolUDP,
	}

	eth := &layers.Ethernet{
		SrcMAC:       mac,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeIPv4,
	}

	udp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

	if err := gopacket.SerializeLayers(buf, opts,
		eth, ip, udp, dhcp,
	); err != nil {
		t.Fatalf("serialization error: %v", err)
	}

	packet := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	AnalyzeDHCP(packet)

	// Vérifie la détection
	h := sniffer.FindHostByIP(ipv4)
	if h == nil {
		t.Fatal("host not found")
	}
	if !h.ProtocolsSeen["DHCP"] {
		t.Error("expected protocol 'dhcp' to be seen, but it was not")
	}
}

