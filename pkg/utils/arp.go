package utils

import (
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// GetMACFromARP envoie une requête ARP et retourne la MAC de la cible (ou nil si pas de réponse)
func GetMACFromARP(targetIP net.IP, handle *pcap.Handle, srcMAC net.HardwareAddr, srcIP net.IP) net.HardwareAddr {
	eth := layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   srcMAC,
		SourceProtAddress: srcIP.To4(),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    targetIP.To4(),
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}
	_ = gopacket.SerializeLayers(buf, opts, &eth, &arp)
	_ = handle.WritePacketData(buf.Bytes())

	// Capture les réponses ARP pendant 300 ms
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	timeout := time.After(300 * time.Millisecond)

	for {
		select {
		case packet := <-packetSource.Packets():
			if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
				arpResp := arpLayer.(*layers.ARP)
				if net.IP(arpResp.SourceProtAddress).Equal(targetIP) {
					return net.HardwareAddr(arpResp.SourceHwAddress)
				}
			}
		case <-timeout:
			return nil
		}
	}
}
