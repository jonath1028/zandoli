# Statistiques de Trafic par Hôte

Ce module fournit des fonctionnalités de suivi des statistiques de trafic pour chaque hôte découvert sur le réseau.

## Fonctionnalités

- **Comptage de paquets** : Suivi du nombre de paquets observés par hôte
- **Comptage d'octets** : Suivi du volume de données par hôte
- **Thread-safe** : Compteurs sécurisés pour utilisation concurrente
- **Export JSON** : Les statistiques sont automatiquement incluses dans `hosts.json`

## Utilisation

### Création d'une instance

```go
import (
    "zandoli/internal/config"
    "zandoli/internal/logger"
    "zandoli/pkg/sniffer"
)

log, err := logger.New("output_dir", cfg)
if err != nil {
    // Handle error
}
stats := sniffer.NewTrafficStats(log)
```

### Enregistrement de paquets

```go
// Lors de la réception d'un paquet
mac, _ := net.ParseMAC("00:11:22:33:44:55")
ip := net.ParseIP("192.168.1.100")
packetSize := 1500

stats.RecordPacket(mac, ip, packetSize)
```

### Mise à jour des hôtes avec leurs statistiques

```go
// Avant l'export, mettre à jour les hôtes avec leurs statistiques
for _, host := range hosts {
    stats.UpdateHostWithStats(host)
}
```

### Récupération des statistiques

```go
// Statistiques pour un hôte spécifique
packets, bytes := stats.GetStats(mac, ip)

// Statistiques globales
totalPackets, totalBytes, hostCount := stats.GetTotalStats()

// Toutes les statistiques
allStats := stats.GetAllStats()
```

## Structure des données

### Champs ajoutés à Host

```go
type Host struct {
    // ... autres champs existants ...
    PacketCount uint64 `json:"packetCount,omitempty"` // nombre de paquets observés
    ByteCount   uint64 `json:"byteCount,omitempty"`   // nombre d'octets observés
}
```

### Export JSON

Les statistiques sont automatiquement incluses dans le fichier `hosts.json` :

```json
{
  "metadata": {
    "version": "0.94",
    "generated_at": "2025-01-11T10:30:00Z",
    "total_hosts": 10,
    "valid_hosts": 10
  },
  "hosts": [
    {
      "ip": "192.168.1.100",
      "macStr": "00:11:22:33:44:55",
      "vendor": "Cisco Systems",
      "packetCount": 1250,
      "byteCount": 1875000,
      "protocols": ["DHCP", "ARP"],
      "firstSeen": "2025-01-11T10:00:00Z",
      "lastSeen": "2025-01-11T10:30:00Z"
    }
  ]
}
```

## Intégration avec les sniffers existants

### Avec LiveSniffer

```go
// Créer le tracker de trafic
tracker := NewExampleTrafficTracker(log)

// Connecter le canal de paquets
go func() {
    for packet := range snifferPacketChan {
        // Extraire les IPs du paquet
        srcIP, dstIP := extractIPsFromPacket(packet)
        
        // Enregistrer les statistiques
        tracker.trafficStats.RecordPacket(packet.SrcMAC, srcIP, len(packet.Payload))
        tracker.trafficStats.RecordPacket(packet.DstMAC, dstIP, len(packet.Payload))
    }
}()
```

### Avec PcapSniffer

```go
// Même approche, mais pour l'analyse de fichiers PCAP
// Les statistiques sont calculées pendant la lecture du fichier
```

## Sécurité des threads

Les compteurs utilisent des mutex pour garantir la sécurité lors d'accès concurrents :

- `RecordPacket()` : Verrou en écriture pour mise à jour atomique
- `GetStats()` : Verrou en lecture pour accès concurrent
- `GetAllStats()` : Verrou en lecture avec copie des données

## Tests

Les tests unitaires couvrent :

- Enregistrement de paquets
- Récupération des statistiques
- Mise à jour des structures Host
- Accès concurrent sécurisé

```bash
go test ./pkg/sniffer/statistics_test.go ./pkg/sniffer/statistics.go -v
```

## Performance

- Utilisation de `sync.RWMutex` pour optimiser les lectures concurrentes
- Clés d'hôte générées à partir de MAC ou IP pour identification unique
- Copie des données lors de `GetAllStats()` pour éviter les race conditions
