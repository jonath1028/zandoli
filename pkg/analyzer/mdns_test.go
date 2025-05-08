package analyzer

import (
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"zandoli/pkg/sniffer"
)

func TestAnalyzeMDNS_MinimalDetection(t *testing.T) {
	// Reset hosts
	sniffer.DiscoveredHosts = []sniffer.Host{}

	ip := net.IPv4(192, 168, 1, 42)
	mac, _ := net.ParseMAC("00:0c:29:ab:cd:ef")
	h := sniffer.NewHost(ip, mac, "passive")
	sniffer.DiscoveredHosts = append(sniffer.DiscoveredHosts, h)

	udp := &layers.UDP{
		SrcPort: 5353,
		DstPort: 5353,
	}
	ip4 := &layers.IPv4{
		SrcIP: ip,
	}
	dnsResp := &layers.DNS{
		QR: true, // réponse
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}
	gopacket.SerializeLayers(buf, opts, ip4, udp, dnsResp)

	packet := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
	AnalyzeMDNS(packet)

	found := sniffer.FindHostByIP(ip)
	if found == nil {
		t.Fatal("host not found")
	}

	t.Logf("Host protocols seen: %+v", found.ProtocolsSeen)
	if !found.ProtocolsSeen["mDNS"] {
		t.Errorf("expected mDNS to be marked as seen, but it was not")
	}
}

