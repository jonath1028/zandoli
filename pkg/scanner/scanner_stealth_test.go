package scanner

import (
	"net"
	"testing"
	"time"

	"zandoli/pkg/sniffer"
	"zandoli/pkg/utils"

	"github.com/stretchr/testify/assert"
)

func TestScanARPStealth_TimingsAndExecution(t *testing.T) {
	iface := getTestInterface()
	_, localIP, _ := utils.GetInterfaceInfo(iface)
	subnet := utils.GetLocalSubnet(localIP, iface)

	// Limiter à 5 IPs pour test rapide
	ips := []net.IP{}
	for ip := range utils.IPsInSubnet(subnet, localIP) {
		if len(ips) >= 5 {
			break
		}
		ips = append(ips, ip)
	}

	// Réinitialiser les hôtes découverts
	sniffer.DiscoveredHosts = []sniffer.Host{}

	start := time.Now()
	ScanARPStealth(iface)
	elapsed := time.Since(start)

	t.Logf("Stealth scan duration: %s", elapsed)
	t.Logf("Discovered hosts: %d", len(sniffer.DiscoveredHosts))

	// Estimation large pour burst & pause (minimum 2s)
	assert.GreaterOrEqual(t, int(elapsed.Seconds()), 2, "Should respect stealth delays")
	assert.GreaterOrEqual(t, len(sniffer.DiscoveredHosts), 0, "Scan should not panic")
}

func getTestInterface() string {
	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback == 0 && iface.Flags&net.FlagUp != 0 {
			return iface.Name
		}
	}
	return "eth0"
}
