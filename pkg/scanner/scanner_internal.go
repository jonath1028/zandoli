package scanner

import (
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"zandoli/pkg/sniffer"
	"zandoli/pkg/utils"
)

// sendARP envoie une requête ARP sur le handle pcap fourni pour la cible IP.
func sendARP(handle *pcap.Handle, ip net.IP, srcMAC net.HardwareAddr, srcIP net.IP) {
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
		DstProtAddress:    ip.To4(),
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}
	_ = gopacket.SerializeLayers(buf, opts, &eth, &arp)
	_ = handle.WritePacketData(buf.Bytes())
}

// gatherTargets retourne la liste des IP d'un sous-réseau à scanner (hors IP locale et déjà découvertes).
func gatherTargets(subnet *net.IPNet, localIP net.IP) []net.IP {
	var targets []net.IP
	for ip := range utils.IPsInSubnet(subnet, localIP) {
		if !sniffer.IsAlreadyKnown(ip) {
			targets = append(targets, ip)
		}
	}
	return targets
}

// iterateIPs fournit un channel d'IPs sur un sous-réseau donné (incluant l'IP locale).
func iterateIPs(subnet *net.IPNet) <-chan net.IP {
	// Utilise utils.IPsInSubnet sans exclure d’adresse pour inclure l’IP locale
	return utils.IPsInSubnet(subnet, net.IP{})
}
