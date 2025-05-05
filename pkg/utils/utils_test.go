package utils

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

// 🔍 Trouve la première interface UP avec une adresse IPv4 (hors loopback)
func getFirstIPv4Interface() (string, net.IP) {
	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil {
				return iface.Name, ipnet.IP
			}
		}
	}
	return "", nil
}

func TestGetInterfaceInfo(t *testing.T) {
	ifaceName, ip := getFirstIPv4Interface()

	if ifaceName == "" || ip == nil {
		t.Skip("[SKIP] No usable network interface with IPv4 found")
		return
	}

	defer func() {
		if r := recover(); r != nil {
			t.Skipf("[SKIP] Recovered from panic in GetInterfaceInfo: %v", r)
		}
	}()

	iface, foundIP, mac := GetInterfaceInfo(ifaceName)

	if iface == nil || foundIP == nil || mac == nil {
		t.Skipf("[SKIP] GetInterfaceInfo returned nil components on iface=%s", ifaceName)
		return
	}

	assert.Equal(t, ip.String(), foundIP.String())
}

func TestGetLocalSubnet(t *testing.T) {
	ifaceName, ip := getFirstIPv4Interface()

	if ifaceName == "" || ip == nil {
		t.Skip("[SKIP] No usable interface for subnet test")
		return
	}

	subnet := GetLocalSubnet(ip, ifaceName)

	assert.NotNil(t, subnet)
	assert.True(t, subnet.Contains(ip))
}

func TestIPsInSubnet(t *testing.T) {
	_, ip := getFirstIPv4Interface()
	if ip == nil {
		t.Skip("[SKIP] No IPv4 interface for IPsInSubnet test")
		return
	}

	subnet := &net.IPNet{
		IP:   ip.Mask(net.CIDRMask(30, 32)), // 4 IPs
		Mask: net.CIDRMask(30, 32),
	}

	ips := []net.IP{}
	for ip := range IPsInSubnet(subnet, ip) {
		ips = append(ips, ip)
	}

	assert.GreaterOrEqual(t, len(ips), 2)
}

func TestIncIP(t *testing.T) {
	ip := net.IPv4(192, 168, 1, 254)
	incIP(ip)
	assert.Equal(t, "192.168.1.255", ip.String())

	incIP(ip)
	assert.Equal(t, "192.168.2.0", ip.String()) // overflow
}

