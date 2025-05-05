package utils

import (
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// GetInterfaceInfo retourne l'interface, l'IP locale et la MAC associée
func GetInterfaceInfo(ifaceName string) (iface *net.Interface, ip net.IP, mac net.HardwareAddr) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		panic(err)
	}
	addrs, err := iface.Addrs()
	if err != nil || len(addrs) == 0 {
		panic("No IP found on interface " + ifaceName)
	}
	var ipAddr net.IP
	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok && ipNet.IP.To4() != nil {
			ipAddr = ipNet.IP
			break
		}
	}
	return iface, ipAddr, iface.HardwareAddr
}

// GetLocalSubnet calcule le sous-réseau basé sur l'IP locale et le masque
func GetLocalSubnet(ip net.IP, ifaceName string) *net.IPNet {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		panic(err)
	}
	addrs, err := iface.Addrs()
	if err != nil {
		panic(err)
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil && ip.Equal(ipnet.IP) {
			networkIP := ip.Mask(ipnet.Mask)
			return &net.IPNet{
				IP:   networkIP,
				Mask: ipnet.Mask,
			}
		}
	}
	panic("Subnet not found for IP " + ip.String())
}

// IPsInSubnet retourne un channel contenant les IPs d’un sous-réseau (sauf exclude)
func IPsInSubnet(subnet *net.IPNet, exclude net.IP) <-chan net.IP {
	ch := make(chan net.IP)
	go func() {
		defer close(ch)
		for ip := subnet.IP.Mask(subnet.Mask); subnet.Contains(ip); incIP(ip) {
			tmp := make(net.IP, len(ip))
			copy(tmp, ip)
			if !tmp.Equal(exclude) {
				ch <- tmp
			}
		}
	}()
	return ch
}

// incIP incrémente une IP de 1 (utile pour itérer sur un range IP)
func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

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
	gopacket.SerializeLayers(buf, opts, &eth, &arp)
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

