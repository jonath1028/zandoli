# Modèle de Données Zandoli

> 📊 **Schémas visuels** : Consultez [schemas/data_model.md](schemas/data_model.md) pour des diagrammes détaillés du modèle de données.

## Vue d'ensemble

Le modèle de données Zandoli est structuré autour de l'entité centrale `Host` qui représente un équipement découvert sur le réseau. Chaque hôte est enrichi avec des informations Layer 2, Layer 3, des métadonnées et des détections d'anomalies.

## Structures Principales

### Host
**Fichier** : `pkg/model/types.go`
**Description** : Structure centrale représentant un équipement découvert

#### Champs d'Identification
```go
IP               net.IP           `json:"ip,omitempty"`   // IP principale IPv4 (pour compatibilité)
IPv6Primary      net.IP           `json:"ipv6,omitempty"` // IP principale IPv6
IPs              []net.IP         `json:"ips,omitempty"`  // Toutes les adresses IP observées (v4 et v6)
MAC              net.HardwareAddr `json:"-"`              // Adresse MAC (non sérialisée)
MACStr           string           `json:"macStr,omitempty"` // MAC en string
```

#### Champs de Classification
```go
Vendor           string           `json:"vendor,omitempty"`         // Vendor OUI
Role             string           `json:"role,omitempty"`           // Rôle inféré
RoleConfidence   int              `json:"roleConfidence,omitempty"` // Confiance (0-100)
RoleSignals      []string         `json:"roleSignals,omitempty"`    // Signaux utilisés
RoleConflict     bool             `json:"roleConflict,omitempty"`   // Conflits détectés
Category         string           `json:"category,omitempty"`       // Catégorie fonctionnelle
```

#### Champs de Découverte
```go
Protocols        []string         `json:"protocols,omitempty"`      // Protocoles observés
Info             string           `json:"info,omitempty"`           // Infos additionnelles
Hostname         string           `json:"hostname,omitempty"`       // Nom d'hôte
Source           string           `json:"source,omitempty"`         // "passive", "active", "combined"
OnlyARP          bool             `json:"onlyArp,omitempty"`        // Découvert uniquement par ARP
```

#### Champs de Fingerprinting
```go
TTL              int              `json:"ttl,omitempty"`            // TTL observé
TTLAvg           uint8            `json:"ttlAvg,omitempty"`         // TTL moyen
OSGuess          string           `json:"osGuess,omitempty"`        // OS deviné
OSScore          uint8            `json:"osScore,omitempty"`        // Confiance OS (0-100)
OSSignals        []string         `json:"osSignals,omitempty"`      // Sources OS
WindowSize       int              `json:"windowSize,omitempty"`     // Taille fenêtre TCP
TCPOpts          []string         `json:"tcpOpts,omitempty"`        // Options TCP legacy
TCPOptions       *TCPOptions      `json:"tcpOptions,omitempty"`     // Options TCP détaillées
```

#### Champs de Métadonnées
```go
FirstSeen        time.Time        `json:"firstSeen,omitempty"`      // Premier paquet
LastSeen         time.Time        `json:"lastSeen,omitempty"`       // Dernier paquet
PacketCount      uint64           `json:"packetCount,omitempty"`    // Nombre de paquets
ByteCount        uint64           `json:"byteCount,omitempty"`      // Nombre d'octets
Ports            []int            `json:"ports,omitempty"`          // Ports observés (legacy)
```

#### Champs VLAN
```go
VLANs            []int            `json:"vlans,omitempty"`          // VLANs observés
VLANStats        map[int]int      `json:"vlanStats,omitempty"`      // Fréquence par VLAN
PrimaryVLAN      int              `json:"primaryVlan,omitempty"`    // VLAN principal
```

#### Champs de Sécurité
```go
SecurityFeatures []string         `json:"securityFeatures,omitempty"` // Fonctionnalités sécurité
Anomalies        []Anomaly        `json:"anomalies,omitempty"`        // Anomalies détectées
```

#### Champs L2 Détailés
```go
CDP              *CDPInfo         `json:"cdp,omitempty"`            // Détails CDP
LLDP             *LLDPInfo        `json:"lldp,omitempty"`           // Détails LLDP
STP              *STPInfo         `json:"stp,omitempty"`            // Détails STP
RoleInfo         *RoleInfo        `json:"roleInfo,omitempty"`       // Inférence de rôle
```

#### Champs Multi-IP
```go
IPsAll           []IPObservation  `json:"ipsAll,omitempty"`         // IPs avec force d'association
ProtocolsByIP    map[string][]string `json:"protocolsByIP,omitempty"` // Protocoles par IP
```

#### Champs Standardisés
```go
L2Signals        L2SignalsInfo    `json:"l2,omitempty"`             // Signaux L2 consolidés
Services         ServicesInfo     `json:"services,omitempty"`       // Services TCP/UDP
```

### CDPInfo
**Description** : Informations Cisco Discovery Protocol

```go
type CDPInfo struct {
    DeviceID            string   `json:"device_id,omitempty"`     // Device ID (TLV 0x01)
    PortID              string   `json:"port_id,omitempty"`       // Port ID (TLV 0x03)
    Platform            string   `json:"platform,omitempty"`      // Platform (TLV 0x06)
    Version             string   `json:"version,omitempty"`       // Software Version (TLV 0x05)
    Capabilities        uint32   `json:"capabilities,omitempty"`  // Capabilities (TLV 0x04)
    NativeVLAN          int      `json:"native_vlan,omitempty"`   // Native VLAN (TLV 0x0a)
    Addresses           []string `json:"addresses,omitempty"`     // Management addresses
    DecodedCaps         []string `json:"decoded_caps,omitempty"`  // Decoded capabilities
    CapabilitiesDecoded []string `json:"capabilitiesDecoded,omitempty"` // Human-readable
}
```

### LLDPInfo
**Description** : Informations Link Layer Discovery Protocol

```go
type LLDPInfo struct {
    ChassisID    string   `json:"chassis_id,omitempty"`   // Chassis ID
    PortID       string   `json:"port_id,omitempty"`      // Port ID
    SysName      string   `json:"sys_name,omitempty"`     // System Name
    SysDescr     string   `json:"sys_descr,omitempty"`    // System Description
    MgmtAddrs    []string `json:"mgmt_addrs,omitempty"`   // Management Addresses
    Capabilities []string `json:"capabilities,omitempty"` // System Capabilities
}
```

### STPInfo
**Description** : Informations Spanning Tree Protocol

```go
type STPInfo struct {
    RootBridgeID string `json:"root_bridge_id,omitempty"` // Root Bridge ID (priority + MAC)
    RootPathCost uint32 `json:"root_path_cost,omitempty"` // Root Path Cost
    BridgeID     string `json:"bridge_id,omitempty"`      // Bridge ID (priority + MAC)
    PortID       uint16 `json:"port_id,omitempty"`        // Port ID
    HelloTime    uint16 `json:"hello_time,omitempty"`     // Hello Time (in 1/256 seconds)
    MaxAge       uint16 `json:"max_age,omitempty"`        // Max Age (in 1/256 seconds)
    ForwardDelay uint16 `json:"forward_delay,omitempty"`  // Forward Delay (in 1/256 seconds)
    MessageAge   uint16 `json:"message_age,omitempty"`    // Message Age (in 1/256 seconds)
    IsRoot       bool   `json:"is_root,omitempty"`        // True if this bridge is the root
}
```

### RoleInfo
**Description** : Informations d'inférence de rôle

```go
type RoleInfo struct {
    Role       string   `json:"role,omitempty"`       // Inferred role (router, switch, client, etc.)
    Confidence int      `json:"confidence,omitempty"` // Confidence level (0-100)
    Signals    []string `json:"signals,omitempty"`    // Signals used for inference
    Rationale  string   `json:"rationale,omitempty"`  // Human-readable explanation
}
```

### Anomaly
**Description** : Anomalie détectée avec métadonnées

```go
type Anomaly struct {
    Type        string                 `json:"type"`        // Type d'anomalie
    Severity    string                 `json:"severity"`    // Sévérité: low/medium/high
    Key         string                 `json:"key"`         // Clé de déduplication
    Parameters  map[string]interface{} `json:"parameters"`  // Paramètres spécifiques
    Scope       string                 `json:"scope"`       // Scope: global ou vlan:id
    Description string                 `json:"description"` // Description lisible
}
```

#### Types d'Anomalies
- `ip_duplicate_v4` : IP IPv4 dupliquée sur plusieurs MACs
- `mac_multiple_ip` : MAC avec plusieurs IPs
- `flip_suspect` : Tentative de changement IP↔MAC
- `duplicate_hostname` : Hostname dupliqué
- `arp_storm` : Tempête ARP détectée

### Subnet
**Description** : Sous-réseau découvert

```go
type Subnet struct {
    CIDR       string   `json:"cidr"`        // CIDR notation
    Source     string   `json:"source"`      // Source: dhcp, computed, arp, ndp
    Hosts      []string `json:"hosts,omitempty"` // IPs dans ce sous-réseau
    CountHosts int      `json:"countHosts,omitempty"` // Nombre d'hôtes
    VLANs      []int    `json:"vlans,omitempty"`      // VLANs associés
}
```

### SubnetEntry
**Description** : Entrée de sous-réseau avec métadonnées VLAN

```go
type SubnetEntry struct {
    CIDR       string    `json:"cidr"`                // CIDR notation (e.g., "192.168.1.0/24")
    Version    string    `json:"version"`             // "ipv4" or "ipv6"
    VLAN       *int      `json:"vlan,omitempty"`      // VLAN ID (null if untagged)
    Source     string    `json:"source"`              // "dhcp", "ra", "computed"
    HostsCount int       `json:"hostsCount"`          // Number of unique hosts in this subnet
    IPSamples  []string  `json:"ipSamples"`           // Max 5 sample IPs, sorted, unique
    FirstSeen  time.Time `json:"firstSeen,omitempty"` // Optional: first time this subnet was observed
    LastSeen   time.Time `json:"lastSeen,omitempty"`  // Optional: last time this subnet was observed
}
```

### TCPOptions
**Description** : Options TCP pour fingerprinting OS

```go
type TCPOptions struct {
    MSS             int      `json:"mss,omitempty"`               // Maximum Segment Size
    WSCALE          int      `json:"wscale,omitempty"`            // Window Scale Factor
    SACKPermitted   bool     `json:"sackPermitted,omitempty"`     // Selective Acknowledgment
    Timestamp       bool     `json:"timestamp,omitempty"`         // Timestamp Option
    NOPCount        int      `json:"nopCount,omitempty"`          // Number of NOP options
    Order           []string `json:"order,omitempty"`             // Order of TCP options
    MSSSamples      []int    `json:"mss_samples,omitempty"`       // MSS samples
    WScaleSamples   []int    `json:"wscale_samples,omitempty"`    // WScale samples
    TCPFPConfidence int      `json:"tcp_fp_confidence,omitempty"` // Confidence (0-100)
}
```

### L2SignalsInfo
**Description** : Signaux L2 consolidés

```go
type L2SignalsInfo struct {
    VLANs []int `json:"vlans,omitempty"` // VLANs observés (dédupliqués)
    EAPOL bool  `json:"eapol,omitempty"` // EAPOL (802.1X) détecté
    STP   bool  `json:"stp,omitempty"`   // STP/RSTP détecté
    LLDP  bool  `json:"lldp,omitempty"`  // LLDP détecté
    CDP   bool  `json:"cdp,omitempty"`   // CDP détecté
}
```

### ServicesInfo
**Description** : Services TCP/UDP détectés

```go
type ServicesInfo struct {
    TCP []int `json:"tcp,omitempty"` // Ports TCP (triés, uniques)
    UDP []int `json:"udp,omitempty"` // Ports UDP (triés, uniques)
}
```

### IPObservation
**Description** : Observation d'IP avec force d'association

```go
type IPObservation struct {
    IP       net.IP `json:"ip"`
    Strength string `json:"strength"` // "high", "medium", "low"
}
```

### PacketEvent
**Description** : Paquet brut capturé

```go
type PacketEvent struct {
    Timestamp time.Time
    SrcMAC    net.HardwareAddr
    DstMAC    net.HardwareAddr
    Payload   []byte
    PacketID  string
    TTL       uint8
    VLANID    int // VLAN identifier from 802.1Q tag (-1 if not present)
}
```

## Méthodes Utilitaires

### Host Methods

#### AddPort
```go
func (h *Host) AddPort(port int)
```
Ajoute un port à la liste s'il n'existe pas déjà.

#### AddVLAN
```go
func (h *Host) AddVLAN(vlan int)
```
Ajoute un VLAN à la liste et met à jour les statistiques.

#### AddIP
```go
func (h *Host) AddIP(ip net.IP)
```
Ajoute une IP à la liste et met à jour l'IP principale.

### Anomaly Constructors

#### NewAnomaly
```go
func NewAnomaly(anomalyType, severity, description string, parameters map[string]interface{}) Anomaly
```

#### NewARPStormAnomaly
```go
func NewARPStormAnomaly(pps int, durationSeconds int) Anomaly
```

#### NewMACMultipleIPAnomaly
```go
func NewMACMultipleIPAnomaly(ips []string) Anomaly
```

#### NewIPDuplicateV4Anomaly
```go
func NewIPDuplicateV4Anomaly(ip string, vlanID int, macs []string) Anomaly
```

## Exemples JSON

### Hôte Simple (Client)
```json
{
  "ip": "192.168.1.100",
  "macStr": "00:11:22:33:44:55",
  "vendor": "Apple",
  "role": "client",
  "roleConfidence": 75,
  "roleSignals": ["HTTP_REQUEST", "DNS_QUERY"],
  "protocols": ["HTTP", "DNS", "mDNS"],
  "hostname": "macbook-pro.local",
  "ttl": 64,
  "osGuess": "macOS",
  "osScore": 85,
  "osSignals": ["vendor", "tcp"],
  "firstSeen": "2025-01-30T10:30:00Z",
  "lastSeen": "2025-01-30T10:35:00Z",
  "packetCount": 1250,
  "byteCount": 156000,
  "vlans": [10],
  "primaryVlan": 10,
  "l2": {
    "vlans": [10],
    "eapol": false,
    "stp": false,
    "lldp": false,
    "cdp": false
  },
  "services": {
    "tcp": [80, 443, 548],
    "udp": [53, 5353]
  }
}
```

### Hôte Infrastructure (Routeur)
```json
{
  "ip": "192.168.1.1",
  "ipv6": "2001:db8::1",
  "macStr": "aa:bb:cc:dd:ee:ff",
  "vendor": "Cisco Systems",
  "role": "reseau",
  "roleConfidence": 100,
  "roleSignals": ["L2_PRESENT"],
  "protocols": ["CDP", "OSPF", "BGP"],
  "ttl": 255,
  "osGuess": "Cisco IOS",
  "osScore": 95,
  "osSignals": ["cdp", "vendor"],
  "firstSeen": "2025-01-30T10:30:00Z",
  "lastSeen": "2025-01-30T10:35:00Z",
  "packetCount": 5000,
  "byteCount": 250000,
  "vlans": [1, 10, 20],
  "primaryVlan": 1,
  "cdp": {
    "device_id": "Router-01",
    "platform": "Cisco 2960",
    "version": "15.2(4)S7",
    "capabilities": 142,
    "capabilitiesDecoded": ["Router", "Switch", "IGMP"]
  },
  "l2": {
    "vlans": [1, 10, 20],
    "eapol": true,
    "stp": true,
    "lldp": false,
    "cdp": true
  },
  "services": {
    "tcp": [22, 23, 80, 443],
    "udp": [161, 162]
  }
}
```

## Relations et Contraintes

### Contraintes d'Intégrité
- **MAC unique** : Un MAC ne peut appartenir qu'à un seul Host
- **IPs multiples** : Un Host peut avoir plusieurs IPs (dual-stack)
- **VLANs** : Un Host peut être sur plusieurs VLANs
- **Anomalies** : Une anomalie appartient à un Host spécifique

### Relations
- **Host → CDP/LLDP/STP** : Relation 1:1 optionnelle
- **Host → Anomalies** : Relation 1:N
- **Host → Subnets** : Relation N:M (via IPs)
- **Host → Protocols** : Relation N:M (via observation)

### Validations
- **IPs valides** : Format IPv4/IPv6 correct
- **MACs valides** : Format Ethernet correct
- **VLANs** : Valeurs 1-4094
- **Timestamps** : Cohérence FirstSeen ≤ LastSeen
- **Confidence** : Valeurs 0-100

## Sérialisation

### JSON
- **Champs optionnels** : `omitempty` pour éviter les valeurs nulles
- **Timestamps** : Format RFC3339
- **MACs** : Convertis en string pour compatibilité
- **IPs** : Format texte standard

### CSV
- **Délimiteur** : Point-virgule (`;`)
- **Encodage** : UTF-8
- **Échappement** : Guillemets doubles pour valeurs contenant le délimiteur

### XML
- **Namespace** : `http://zandoli.net/schema/v2`
- **Structure** : Hiérarchique avec éléments imbriqués
- **Attributs** : Métadonnées (type, version)

---

**Voir aussi** : [Pipeline](PIPELINE.md) | [Architecture](ARCHITECTURE.md) | [Formats d'Export](EXPORTS.md) | [Protocoles L2](L2_PROTOCOLS.md)