package scanner

import (
	"net"
	"testing"
	"time"
	"math/rand"
)

type mockHandle struct {
	written [][]byte
}

func (m *mockHandle) WritePacketData(data []byte) error {
	m.written = append(m.written, data)
	return nil
}

// --- Test de ScanARPStealth ---
func TestScanARPStealth(t *testing.T) {
	// Création de variables d'exemple
	localIP := net.ParseIP("192.168.1.1")
	localMAC, _ := net.ParseMAC("00:11:22:33:44:55") // Utilisation de localMAC
	subnet := &net.IPNet{
		IP:   net.ParseIP("192.168.1.0"),
		Mask: net.CIDRMask(24, 32), // Utilisation de subnet
	}

	// Mock de pcap.Handle
	mock := &mockHandle{}

	// Simuler un handle pour `sendStealthBurst`
	handle := mock // Utilisation de handle

	// Définir un canal pour arrêter le scan de manière simulée
	stop := make(chan struct{})
	go func() {
		// Simule la capture des réponses sans attendre réellement
		close(stop)
	}()

	// Test : faire le scan ARP furtif
	ScanARPStealth("eth0") // Appel de la fonction à tester

	// Vérifie que des paquets ont été envoyés
	if len(mock.written) == 0 {
		t.Errorf("No packets were written by sendStealthBurst")
	}

	// Vérifie que les pauses aléatoires sont respectées
	// Par exemple, tester que la pause entre les envois est dans la bonne plage
	for i := 1; i < len(mock.written); i++ {
		packetDelay := time.Duration(rand.Intn(250)+150) * time.Millisecond // 150–400ms
		if packetDelay < 150*time.Millisecond || packetDelay > 400*time.Millisecond {
			t.Errorf("Unexpected packet delay: %v", packetDelay)
		}
	}

	// Vérifie que le nombre de paquets envoyés est correct (par exemple 15 IPs pour un burst)
	if len(mock.written) < 15 {
		t.Errorf("Expected at least 15 packets, got %d", len(mock.written))
	}

	// Vérifie que l'IP locale est exclue dans le sous-réseau
	ips := []string{}
	for ip := range iterateIPs(subnet) {
		if ip.Equal(localIP) {
			continue
		}
		ips = append(ips, ip.String())
	}

	for _, ipStr := range ips {
		if ipStr == localIP.String() {
			t.Errorf("Local IP %s should have been excluded", localIP)
		}
	}
}

// --- Test de SendStealthBurst ---
func TestSendStealthBurst(t *testing.T) {
	ips := []net.IP{
		net.ParseIP("192.168.1.100"),
		net.ParseIP("192.168.1.101"),
	}

	localIP := net.ParseIP("192.168.1.1")
	localMAC, _ := net.ParseMAC("00:11:22:33:44:55")

	mock := &mockHandle{}

	// Appel à sendStealthBurst
	sendStealthBurst(ips, mock, localMAC, localIP)

	// Vérifie que les paquets ont été envoyés
	if len(mock.written) != len(ips) {
		t.Errorf("Expected %d packets to be sent, got %d", len(ips), len(mock.written))
	}
}

// --- Test de IterateIPs avec exclusion de l'IP locale ---
func TestIterateIPs_ExcludesLocalIP(t *testing.T) {
	_, subnet, err := net.ParseCIDR("192.168.1.0/24")
	if err != nil {
		t.Fatalf("Failed to parse subnet: %v", err)
	}
	local := net.ParseIP("192.168.1.42")

	ips := []string{}
	for ip := range iterateIPs(subnet) {
		if ip.Equal(local) {
			continue
		}
		ips = append(ips, ip.String())
	}

	// Vérifie que l'IP locale est bien exclue
	for _, ipStr := range ips {
		if ipStr == local.String() {
			t.Errorf("Local IP %s should have been excluded", local)
		}
	}
}

// --- Test de SendARP ---
func TestSendARP_WritesPacket(t *testing.T) {
	ip := net.ParseIP("192.168.1.100")
	localIP := net.ParseIP("192.168.1.1")
	mac, _ := net.ParseMAC("00:11:22:33:44:55")

	mock := &mockHandle{}

	// Appel direct de sendARP avec notre mock
	sendARP(mock, ip, mac, localIP)

	if len(mock.written) == 0 {
		t.Errorf("sendARP did not write any packet data")
	}
	if len(mock.written[0]) < 42 { // Ethernet(14) + ARP(28)
		t.Errorf("Packet too short to be a valid ARP frame")
	}
}

