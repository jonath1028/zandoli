# Protocoles Layer 2 - Détails Techniques

> 📊 **Schémas visuels** : Consultez [schemas/protocols.md](schemas/protocols.md) pour des diagrammes détaillés des protocoles.

## Vue d'ensemble

Zandoli analyse plusieurs protocoles Layer 2 pour identifier les équipements d'infrastructure réseau. Ces informations sont affichées dans la section "Détails L2" des rapports et sont prioritaires pour l'inférence des rôles.

## Protocoles Supportés

### 1. CDP (Cisco Discovery Protocol)

**Fichier** : `pkg/analyzer/cdp.go`

#### Description
Protocole propriétaire Cisco pour la découverte automatique des équipements voisins. Fonctionne sur les ports 2000 et utilise des TLV (Type-Length-Value) pour transporter les informations.

#### Détection
- **EtherType** : 0x2000 (direct)
- **LLC/SNAP** : OUI Cisco (0x00000c) + PID 0x2000

#### TLV Extraits
- **Device ID** (TLV 0x01) : Identifiant unique de l'équipement
- **Port ID** (TLV 0x03) : Identifiant du port local
- **Platform** (TLV 0x06) : Modèle de l'équipement
- **Software Version** (TLV 0x05) : Version du logiciel
- **Capabilities** (TLV 0x04) : Capacités de l'équipement
- **Native VLAN** (TLV 0x0A) : VLAN natif du port
- **Management Addresses** (TLV 0x02) : Adresses de gestion

#### Exemple d'Affichage
```
Device ID: Router-01
Platform: Cisco 2960
Version: 15.2(4)S7
Capabilities: Router, Switch, IGMP
Native VLAN: 1
Management Addresses: 192.168.1.1
```

#### Capacités CDP (Bits)
```go
const (
    CDPCapRouter   = 0x01 // Router
    CDPCapTB       = 0x02 // Transparent Bridge
    CDPCapSRB      = 0x04 // Source Route Bridge
    CDPCapSwitch   = 0x08 // Switch/Bridge
    CDPCapHost     = 0x10 // Host
    CDPCapIGMP     = 0x20 // IGMP
    CDPCapRepeater = 0x40 // Repeater
    CDPCapPhone    = 0x80 // Phone/AP
)
```

### 2. LLDP (Link Layer Discovery Protocol)

**Fichier** : `pkg/analyzer/lldp.go`

#### Description
Protocole standard IEEE 802.1AB pour la découverte des équipements voisins. Utilise l'EtherType 0x88CC et des TLV standardisés.

#### Détection
- **EtherType** : 0x88CC

#### TLV Extraits
- **Chassis ID** : Identifiant du châssis
- **Port ID** : Identifiant du port
- **System Name** (TLV 1) : Nom système
- **System Description** (TLV 2) : Description système
- **Management Addresses** (TLV 5) : Adresses de gestion
- **System Capabilities** (TLV 7) : Capacités système

#### Exemple d'Affichage
```
Chassis ID: 00:11:22:33:44:55
Port ID: Gi0/1
System Name: Switch-02
System Description: Cisco IOS Software, C2960 Software (C2960-LANBASE-M), Version 15.2(4)S7
Capabilities: Bridge, Router
Management Addresses: 192.168.1.2
```

#### Capacités LLDP (Bits)
```go
const (
    LLDPCapOther      = 0x01 // Other
    LLDPCapRepeater   = 0x02 // Repeater
    LLDPCapBridge     = 0x04 // Bridge
    LLDPCapWLAN       = 0x08 // WLAN Access Point
    LLDPCapRouter     = 0x10 // Router
    LLDPCapTelephone  = 0x20 // Telephone
    LLDPCapDOCSIS     = 0x40 // DOCSIS cable device
    LLDPCapStation    = 0x80 // Station Only
)
```

### 3. STP (Spanning Tree Protocol)

**Fichier** : `pkg/analyzer/stp.go`

#### Description
Protocole IEEE 802.1D pour éviter les boucles dans les réseaux commutés. Zandoli analyse les BPDU (Bridge Protocol Data Units) pour identifier les équipements STP.

#### Détection
- **EtherType** : 0x42 (802.3) ou 0x26 (802.1D)

#### Champs Extraits
- **Root Bridge ID** : ID du pont racine (Priority + MAC)
- **Root Path Cost** : Coût du chemin vers la racine
- **Bridge ID** : ID du pont local
- **Port ID** : ID du port
- **Timers** : Hello Time, Max Age, Forward Delay
- **Message Age** : Âge du message
- **Is Root** : Indique si ce pont est la racine

#### Exemple d'Affichage
```
Root Bridge ID: 32768.00:11:22:33:44:55
Root Path Cost: 0
Bridge ID: 32768.aa:bb:cc:dd:ee:ff
Port ID: 0x8001
Hello Time: 2s, Max Age: 20s, Forward Delay: 15s
Message Age: 0s
Is Root: false
```

#### Formats de Bridge ID
- **Priority** : 4 bits (0-15, multiplié par 4096)
- **MAC Address** : 6 octets
- **Port ID** : 2 octets (Priority + Port Number)

### 4. 802.1X/EAPOL

**Fichier** : `pkg/analyzer/8021x.go`

#### Description
Protocole IEEE 802.1X pour l'authentification des ports réseau. Zandoli détecte la présence d'EAPOL (EAP over LAN) pour identifier les équipements d'authentification.

#### Détection
- **EtherType** : 0x888E

#### Types EAPOL Détectés
- **EAPOL-Start** : Démarrage de l'authentification
- **EAPOL-Logoff** : Fin de session
- **EAP-Request** : Demande d'authentification
- **EAP-Response** : Réponse d'authentification
- **EAP-Success** : Authentification réussie
- **EAP-Failure** : Échec d'authentification

#### Exemple d'Affichage
```
EAPOL detected: Yes
Authentication State: Active
EAP Method: EAP-TLS
```

#### Codes EAP
```go
const (
    EAPCodeRequest  = 1 // EAP Request
    EAPCodeResponse = 2 // EAP Response
    EAPCodeSuccess  = 3 // EAP Success
    EAPCodeFailure  = 4 // EAP Failure
)
```

### 5. VLAN (802.1Q)

**Fichier** : `pkg/analyzer/vlan.go`

#### Description
Protocole IEEE 802.1Q pour la segmentation des réseaux. Zandoli détecte automatiquement les VLANs dans les paquets capturés.

#### Détection
- **Tag 802.1Q** : Présent dans l'en-tête Ethernet
- **VLAN ID** : 12 bits (1-4094)
- **Priority** : 3 bits (0-7)

#### Champs Extraits
- **VLAN ID** : Identifiant du VLAN
- **Priority** : Priorité du paquet
- **CFI** : Canonical Format Indicator

#### Exemple d'Affichage
```
VLANs detected: [1, 10, 20, 100]
Primary VLAN: 1 (most frequent)
VLAN Stats:
  - VLAN 1: 85 packets
  - VLAN 10: 12 packets
  - VLAN 20: 8 packets
  - VLAN 100: 3 packets
```

## Protocoles Layer 3 Détectés

### 6. DHCP (Dynamic Host Configuration Protocol)

**Fichier** : `pkg/analyzer/dhcp.go`

#### Description
Protocole pour l'attribution automatique d'adresses IP. Zandoli analyse les messages DHCP pour identifier les serveurs et clients.

#### Détection
- **Ports** : UDP 67 (serveur), UDP 68 (client)

#### Champs Extraits
- **Client IP** (Option 50) : Adresse IP du client
- **Server IP** (Option 54) : Adresse IP du serveur
- **Hostname** (Option 12) : Nom d'hôte du client
- **Vendor Class** (Option 60) : Classe du constructeur
- **Lease Time** (Option 51) : Durée de bail

### 7. ARP (Address Resolution Protocol)

**Fichier** : `pkg/analyzer/arp_passive.go`

#### Description
Protocole pour la résolution d'adresses IP vers MAC. Zandoli analyse les paquets ARP pour établir les correspondances.

#### Détection
- **EtherType** : 0x0806

#### Champs Extraits
- **Sender IP** : Adresse IP de l'expéditeur
- **Sender MAC** : Adresse MAC de l'expéditeur
- **Target IP** : Adresse IP cible
- **Target MAC** : Adresse MAC cible
- **Operation** : Request/Reply

### 8. mDNS (Multicast DNS)

**Fichier** : `pkg/analyzer/mdns.go`

#### Description
Protocole pour la résolution de noms dans les réseaux locaux. Zandoli détecte les annonces mDNS pour identifier les services.

#### Détection
- **Port** : UDP 5353
- **Multicast** : 224.0.0.251

#### Champs Extraits
- **Hostname** : Nom d'hôte annoncé
- **Services** : Services disponibles
- **IPv4/IPv6** : Adresses IP annoncées

### 9. NetBIOS Name Service

**Fichier** : `pkg/analyzer/netbios.go`

#### Description
Protocole Microsoft pour la résolution de noms. Zandoli analyse les paquets NBNS pour identifier les équipements Windows.

#### Détection
- **Port** : UDP 137

#### Champs Extraits
- **Hostname** : Nom NetBIOS
- **Service Type** : Type de service
- **MAC Address** : Adresse MAC

### 10. LLMNR (Link-Local Multicast Name Resolution)

**Fichier** : `pkg/analyzer/llmnr.go`

#### Description
Protocole Microsoft pour la résolution de noms dans les réseaux locaux. Alternative à mDNS.

#### Détection
- **Port** : UDP 5355
- **Multicast** : 224.0.0.252

#### Champs Extraits
- **Hostname** : Nom d'hôte recherché
- **IPv4/IPv6** : Adresses IP

### 11. SMB (Server Message Block)

**Fichier** : `pkg/analyzer/smb.go`

#### Description
Protocole Microsoft pour le partage de fichiers et d'imprimantes. Zandoli détecte les connexions SMB.

#### Détection
- **Ports** : TCP 445 (SMB), TCP 139 (NetBIOS Session)

#### Champs Extraits
- **Client/Server** : Rôle dans la connexion
- **Port** : Port utilisé (445 ou 139)

## Corrélation MAC↔IP

### Logique de Corrélation

Les informations L2 sont corrélées avec les adresses IP via la correspondance MAC :

1. **Extraction MAC** : Depuis les paquets L2 (CDP, LLDP, STP)
2. **Recherche IP** : Association avec les IPs observées sur la même MAC
3. **Validation** : Vérification de la cohérence des données
4. **Fusion** : Intégration dans la structure Host

### Exemple de Corrélation
```
MAC: aa:bb:cc:dd:ee:ff
├── IPs associées: 192.168.1.1, 2001:db8::1
├── CDP: Router-01 (Cisco 2960)
├── LLDP: Switch-02 (Cisco IOS)
└── STP: Non-root bridge
```

## Priorité des Protocoles L2

### Hiérarchie de Confiance
1. **CDP** : Priorité maximale (Cisco propriétaire)
2. **LLDP** : Priorité élevée (Standard IEEE)
3. **STP** : Priorité élevée (Indicateur d'infrastructure)
4. **802.1X** : Priorité moyenne (Indicateur d'authentification)

### Inférence de Rôle

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

## Détection des VLANs

### Sources de VLANs
- **802.1Q Tags** : Détection automatique des VLANs
- **CDP Native VLAN** : VLAN natif du port
- **LLDP Management VLAN** : VLAN de gestion
- **STP VLAN Context** : Contexte VLAN des BPDU

### Exemple de Détection
```
VLANs detected: [1, 10, 20, 100]
Primary VLAN: 1 (most frequent)
VLAN Stats:
  - VLAN 1: 85 packets
  - VLAN 10: 12 packets
  - VLAN 20: 8 packets
  - VLAN 100: 3 packets
```

## Limitations et Bonnes Pratiques

### Limitations
- **CDP** : Uniquement sur équipements Cisco
- **LLDP** : Nécessite l'activation sur les équipements
- **STP** : Peut être désactivé sur certains ports
- **802.1X** : Dépend de la configuration d'authentification

### Bonnes Pratiques
1. **Durée d'écoute** : Minimum 60 secondes pour capturer les annonces
2. **Interface** : Utiliser une interface avec vue sur le trafic inter-VLAN
3. **Filtres** : Éviter les filtres trop restrictifs
4. **VLANs** : S'assurer de capturer le trafic sur tous les VLANs

### Dépannage
- **Pas de CDP** : Vérifier que les équipements Cisco ont CDP activé
- **Pas de LLDP** : Activer LLDP sur les équipements non-Cisco
- **VLANs manqués** : Vérifier la configuration du port miroir
- **Informations partielles** : Augmenter la durée d'écoute

## Exemples de Sortie

### Rapport HTML
```html
<div class="l2-details">
  <h3>Détails L2</h3>
  <div class="protocol-info">
    <span class="badge cdp">CDP</span>
    <div class="info">
      <strong>Device ID:</strong> Router-01<br>
      <strong>Platform:</strong> Cisco 2960<br>
      <strong>Version:</strong> 15.2(4)S7<br>
      <strong>Capabilities:</strong> Router, Switch, IGMP
    </div>
  </div>
</div>
```

### Export JSON
```json
{
  "l2": {
    "vlans": [1, 10, 20],
    "eapol": true,
    "stp": true,
    "lldp": false,
    "cdp": true
  },
  "cdp": {
    "device_id": "Router-01",
    "platform": "Cisco 2960",
    "version": "15.2(4)S7",
    "capabilities": 142,
    "capabilitiesDecoded": ["Router", "Switch", "IGMP"],
    "native_vlan": 1,
    "addresses": ["192.168.1.1"]
  }
}
```

### Export CSV
```
MAC;Vendor;VLANs;L2Flags;IP;IPv6;...
aa:bb:cc:dd:ee:ff;Cisco Systems;1,10,20;CDP,STP,EAPOL;192.168.1.1;2001:db8::1;...
```

## Intégration avec le Pipeline

### Étape 1 : Capture
- **Paquets L2** : Détection des EtherTypes spécifiques
- **VLANs** : Extraction des tags 802.1Q
- **MACs** : Source et destination des paquets

### Étape 2 : Parsing
- **CDP** : Parsing des TLV Cisco
- **LLDP** : Parsing des TLV standardisés
- **STP** : Parsing des BPDU
- **802.1X** : Parsing des frames EAPOL

### Étape 3 : Corrélation
- **Association MAC↔IP** : Via les tables ARP/NDP
- **Validation** : Cohérence des données
- **Fusion** : Intégration dans Host

### Étape 4 : Export
- **Formats multiples** : HTML, CSV, JSON
- **Filtrage** : Affichage conditionnel
- **Présentation** : Badges et icônes

---

**Voir aussi** : [Pipeline](PIPELINE.md) | [Modèle de Données](DATA_MODEL.md) | [Formats d'Export](EXPORTS.md) | [Dépannage](TROUBLESHOOTING.md)