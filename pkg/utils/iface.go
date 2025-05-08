package utils

import (
	"net"
)

// GetInterfaceInfo retourne l'interface, l'IP locale et la MAC associée
func GetInterfaceInfo(ifaceName string) (*net.Interface, net.IP, net.HardwareAddr) {
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
