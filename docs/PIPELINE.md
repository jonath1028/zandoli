# Pipeline de Traitement Zandoli

> 📊 **Schémas visuels** : Consultez [schemas/pipeline.md](schemas/pipeline.md) pour des diagrammes détaillés du pipeline.

## Vue d'ensemble du Pipeline

Le pipeline Zandoli traite le trafic réseau en plusieurs étapes séquentielles, de la capture des paquets jusqu'à la génération des rapports. Chaque étape enrichit les données avec des informations spécifiques.

## Étapes Détaillées

### 1. Capture des Paquets
**Module** : `pkg/sniffer/`
**Entrée** : Fichier PCAP ou interface réseau
**Sortie** : Stream de `PacketEvent`

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

**Fonctionnalités** :
- Support PCAP/PCAPNG
- Détection automatique des VLANs (802.1Q)
- Filtrage BPF pour optimiser les performances
- Parsing Ethernet/IP/TCP/UDP de base
- Enregistrement PCAP optionnel

### 2. Dispatch des Protocoles
**Module** : `pkg/analyzer/dispatcher.go`
**Entrée** : `PacketEvent`
**Sortie** : `ParsedRecord` vers parseurs spécialisés

**Logique de routage** :
- **CDP** : Port 2000, TLV Cisco
- **LLDP** : EtherType 0x88CC
- **STP** : EtherType 0x42 (802.3) ou 0x26 (802.1D)
- **DHCP** : UDP 67/68
- **ARP** : EtherType 0x0806
- **mDNS** : UDP 5353
- **TCP** : Ports configurés pour fingerprinting

### 3. Analyse Layer 2
**Parseurs spécialisés** : `cdp.go`, `lldp.go`, `stp.go`, `8021x.go`

#### CDP (Cisco Discovery Protocol)
**Extraction** :
- Device ID (TLV 0x01)
- Port ID (TLV 0x03)
- Platform (TLV 0x06)
- Software Version (TLV 0x05)
- Capabilities (TLV 0x04)
- Native VLAN (TLV 0x0A)
- Management Addresses (TLV 0x02)

#### LLDP (Link Layer Discovery Protocol)
**Extraction** :
- Chassis ID
- Port ID
- System Name (TLV 1)
- System Description (TLV 2)
- Management Addresses (TLV 5)
- System Capabilities (TLV 7)

#### STP (Spanning Tree Protocol)
**Extraction** :
- Root Bridge ID
- Root Path Cost
- Bridge ID
- Port ID
- Hello Time / Max Age / Forward Delay
- Message Age

#### 802.1X/EAPOL
**Détection** :
- EAPOL-Start, EAPOL-Logoff
- EAP-Request/Response
- EAP-Success/Failure

### 4. Analyse Layer 3
**Parseurs** : `dhcp.go`, `arp_passive.go`, `tcp.go`, `mdns.go`, `netbios.go`

#### DHCP
**Extraction** :
- Client IP (Option 50)
- Server IP (Option 54)
- Hostname (Option 12)
- Vendor Class (Option 60)
- Lease Time (Option 51)

#### ARP Passif
**Extraction** :
- IP → MAC mapping
- VLAN context
- TTL values

#### TCP Fingerprinting
**Extraction** :
- MSS (Maximum Segment Size)
- Window Scale
- TCP Options (SACK, Timestamp, NOP)
- OS fingerprinting basé sur les patterns

### 5. Agrégation des Données
**Module** : `pkg/analyzer/aggregator.go`
**Entrée** : Stream de `ParsedRecord`
**Sortie** : Hôtes consolidés

**Fonctionnalités** :
- Fusion des données par MAC
- Déduplication des IPs
- Consolidation des protocoles
- Statistiques VLAN
- Compteurs de paquets/octets

### 6. Corrélation IP↔MAC
**Logique de priorité** : `pkg/analyzer/priority_matrix.go`

#### Matrice de Priorités
```go
// Association IP↔MAC (qui peut créer/écraser)
IPToMAC: {
    "CDP":      100,  // Priorité maximale
    "LLDP":     100,
    "DHCP":     90,   // Très fiable
    "ARP":      80,   // Fiable
    "TCP":      70,   // Modéré
    "UDP":      60,   // Modéré
    "mDNS":     50,   // Faible
}
```

#### Gestion des Conflits
- **Fenêtre anti-flip** : 90 secondes
- **Résolution par priorité** : Protocole de priorité supérieure gagne
- **Détection d'anomalies** : Tentatives de flip bloquées

### 7. Inférence des Rôles
**Module** : `pkg/analyzer/role_inference.go`

#### Hiérarchie de Décision

#### Signaux L2 (Priorité Absolue)
- **CDP/LLDP/STP** → Rôle = "reseau", Confiance = 100%
- **EAPOL** → Indicateur d'infrastructure

#### Fallback OUI
- **Vendors réseau** : Cisco, Juniper, Aruba, etc.
- **Confiance** : 90%
- **Liste** : Configurable via `utils.IsNetworkVendor()`

#### Analyse Client/Serveur
**Signaux serveur** :
- SYN-ACK responses
- DNS responses
- HTTP server headers
- TLS Server Hello
- DHCP OFFER/ACK

**Signaux client** :
- SYN outbound
- DNS queries
- HTTP requests
- TLS Client Hello
- DHCP DISCOVER/REQUEST

#### Tie-breakers
- **Par défaut** : Client (confiance 30%)
- **Score égal** : Client prioritaire
- **Aucun signal** : Client par défaut

### 8. Détection d'Anomalies
**Module** : `pkg/analyzer/anomaly.go`

#### Types d'Anomalies
- **IP Duplicate** : Même IP sur plusieurs MACs
- **MAC Multiple IP** : Même MAC avec plusieurs IPs
- **Flip Suspect** : Tentatives de changement IP↔MAC
- **Duplicate Hostname** : Même hostname sur plusieurs MACs
- **ARP Storm** : Volume anormal de requêtes ARP

#### Déduplication
- **Clés uniques** : `ip:<ip>/vlan:<vlan>` ou `mac:<mac>/vlan:<vlan>`
- **Scope** : Global ou par VLAN
- **Sévérité** : Low, Medium, High

### 9. Classification des Sous-réseaux
**Logique** : `pkg/analyzer/subnet.go`

#### Sources de Sous-réseaux
- **DHCP** : Pool d'adresses du serveur
- **RA** : Router Advertisements IPv6
- **Computed** : Calculés à partir des IPs observées

#### Règles de Classification
- **Classe A** : 10.0.0.0/8 (privé)
- **Classe B** : 172.16.0.0/12 (privé)
- **Classe C** : 192.168.0.0/16 (privé)
- **CGNAT** : 100.64.0.0/10
- **Public** : Autres plages

#### Déduplication
- **IPv4** : Agrégation /24
- **IPv6** : Agrégation /64
- **VLANs** : Association par contexte

### 10. Fusion des Résultats
**Module** : `pkg/fusion/`
**Fonctionnalités** :
- Fusion des données passives et actives
- Déduplication des hôtes
- Consolidation des informations

### 11. Génération des Exports
**Module** : `pkg/exporter/`

#### Formats Supportés
- **HTML** : Rapport interactif avec filtres
- **CSV** : Export tabulaire (délimiteur `;`)
- **JSON** : Données structurées
- **Markdown** : Documentation textuelle
- **XML** : Format standardisé
- **IPSet** : Export pour outils réseau

#### Structure des Exports
```json
{
  "version": "2.0",
  "generatedAt": "2025-01-30T10:30:00Z",
  "count": 42,
  "hosts": [...],
  "subnets": [...],
  "anomalies": [...]
}
```

## Modes d'Exécution

### Mode Passif
1. Capture live ou PCAP
2. Analyse des paquets
3. Agrégation des données
4. Export des résultats

### Mode Actif
1. Scan ARP du sous-réseau
2. Scan SYN optionnel
3. Consolidation des résultats
4. Export des résultats

### Mode Combiné
1. Capture passive
2. Analyse des paquets
3. Scan actif ciblé
4. Fusion des résultats
5. Export des résultats

## Gestion des Erreurs

### Erreurs de Parsing
- **Paquets corrompus** : Loggés et ignorés
- **Protocoles inconnus** : Passés au parseur générique
- **Truncation** : Détection automatique

### Erreurs de Configuration
- **Interface inexistante** : Validation préalable
- **PCAP corrompu** : Détection et message d'erreur
- **Permissions** : Vérification des droits

### Erreurs de Performance
- **Mémoire insuffisante** : Garbage collection forcé
- **CPU surchargé** : Réduction du nombre de goroutines
- **Disque plein** : Arrêt propre avec logs

## Optimisations

### Streaming
- **Chunks** : Traitement par blocs de 1000 paquets
- **Buffers** : Taille adaptative selon la charge
- **Backpressure** : Pause si consommation lente

### Cache
- **OUI** : Cache en mémoire des vendors
- **DNS** : Cache des résolutions
- **ARP** : Cache des associations récentes

### Parallélisation
- **Parseurs** : Goroutines parallèles par protocole
- **Export** : Génération parallèle des formats
- **Active Scan** : Workers parallèles pour ARP/SYN

## Métriques et Monitoring

### Métriques Internes
- **Paquets/seconde** : Débit de traitement
- **Hôtes découverts** : Compteur par minute
- **Erreurs** : Taux d'erreur par type
- **Mémoire** : Utilisation du heap

### Logs de Debug
- **Trace** : Chaque paquet traité
- **Debug** : Détails des décisions
- **Info** : Événements importants
- **Warn** : Problèmes non critiques
- **Error** : Erreurs bloquantes

---

**Voir aussi** : [Architecture](ARCHITECTURE.md) | [Modèle de Données](DATA_MODEL.md) | [Protocoles L2](L2_PROTOCOLS.md) | [Formats d'Export](EXPORTS.md)