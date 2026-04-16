# Formats d'Export Zandoli

> 📊 **Schémas visuels** : Consultez [schemas/exports.md](schemas/exports.md) pour des diagrammes détaillés des formats d'export.

## Vue d'ensemble

Zandoli génère des rapports dans plusieurs formats pour répondre aux différents besoins d'analyse et d'intégration. Chaque format est optimisé pour un usage spécifique.

## Formats Supportés

| Format | Extension | Usage Principal | Avantages |
|--------|-----------|-----------------|-----------|
| **HTML** | `.html` | Analyse interactive | Filtres, recherche, badges visuels |
| **CSV** | `.csv` | Analyse tabulaire | Compatible Excel, traitement de données |
| **JSON** | `.json` | Intégration API | Structure hiérarchique, métadonnées |
| **Markdown** | `.md` | Documentation | Lisibilité, versioning |
| **XML** | `.xml` | Intégration enterprise | Standardisé, validation |
| **IPSet** | `.ipset` | Outils réseau | Compatible iptables, firewalls |

## Rapport HTML

**Fichier** : `pkg/exporter/html_exporter.go`

### Structure Générale
```html
<!DOCTYPE html>
<html>
<head>
    <title>Rapport Zandoli - Scan 2025-01-30</title>
    <meta charset="UTF-8">
    <style>/* CSS intégré */</style>
</head>
<body>
    <header>
        <h1>Rapport Zandoli</h1>
        <div class="summary">42 hôtes découverts</div>
    </header>
    
    <nav class="filters">
        <!-- Filtres interactifs -->
    </nav>
    
    <main>
        <section class="hosts-table">
            <!-- Tableau des hôtes -->
        </section>
        
        <section class="subnets">
            <!-- Cartographie des sous-réseaux -->
        </section>
        
        <section class="anomalies">
            <!-- Détection d'anomalies -->
        </section>
    </main>
</body>
</html>
```

### Fonctionnalités Interactives

#### Filtres
- **Par rôle** : client, serveur, réseau
- **Par VLAN** : Sélection multiple
- **Par vendor** : Filtrage par constructeur
- **Par protocoles** : CDP, LLDP, STP, etc.
- **Par IP** : Recherche textuelle

#### Recherche
- **Texte libre** : Recherche dans tous les champs
- **Regex** : Recherche par expression régulière
- **Sauvegarde** : Filtres sauvegardés en localStorage

#### Badges Visuels
```html
<span class="badge role-client">Client</span>
<span class="badge role-server">Serveur</span>
<span class="badge role-reseau">Réseau</span>
<span class="badge protocol-cdp">CDP</span>
<span class="badge protocol-lldp">LLDP</span>
<span class="badge protocol-stp">STP</span>
<span class="badge protocol-eapol">802.1X</span>
```

#### Tableau des Hôtes
| Colonne | Description | Tri |
|---------|-------------|-----|
| **IP** | Adresse principale | IP |
| **MAC** | Adresse MAC | MAC |
| **Vendor** | Constructeur | Alphabétique |
| **Rôle** | Rôle inféré | Alphabétique |
| **Confiance** | Score de confiance | Numérique |
| **VLANs** | VLANs observés | Numérique |
| **L2** | Protocoles L2 | Alphabétique |
| **Services** | Ports TCP/UDP | Numérique |
| **Détails** | Informations L2 | - |

### Sections Spécialisées

#### Vue d'Ensemble
- **Statistiques globales** : Nombre d'hôtes, VLANs, anomalies
- **Topologie** : Graphique des connexions
- **Timeline** : Évolution dans le temps

#### Détails L2
```html
<div class="l2-details">
    <h3>Détails L2</h3>
    <div class="protocol-info">
        <span class="badge cdp">CDP</span>
        <div class="info">
            <strong>Device ID:</strong> Router-01<br>
            <strong>Platform:</strong> Cisco 2960<br>
            <strong>Version:</strong> 15.2(4)S7
        </div>
    </div>
</div>
```

#### Anomalies
- **Types** : IP dupliquée, MAC multiple IP, etc.
- **Sévérité** : Badges colorés (low/medium/high)
- **Contexte** : VLAN, timestamp, détails

## Export CSV

**Fichier** : `pkg/exporter/csv_exporter.go`

### Configuration
- **Délimiteur** : Point-virgule (`;`)
- **Encodage** : UTF-8
- **Échappement** : Guillemets doubles pour valeurs contenant le délimiteur

### En-têtes
```csv
MAC;Vendor;VLANs;L2Flags;IP;IPv6;UDP_Services;TCP_Services;Protocols;OS
```

### Exemple de Ligne
```csv
aa:bb:cc:dd:ee:ff;Cisco Systems;1,10,20;CDP,STP,EAPOL;192.168.1.1;2001:db8::1;53,161;22,23,80,443;CDP,OSPF,BGP;Router-01;reseau;100;2025-01-30T10:30:00Z;2025-01-30T10:35:00Z
```

### Champs Spécialisés

#### VLANs
- **Format** : Liste séparée par virgules
- **Exemple** : `1,10,20`
- **Vide** : `—`

#### L2Flags
- **Valeurs** : CDP, LLDP, STP, EAPOL
- **Format** : Liste séparée par virgules
- **Exemple** : `CDP,STP,EAPOL`

#### Services
- **UDP_Services** : Ports UDP triés
- **TCP_Services** : Ports TCP triés
- **Format** : Liste séparée par virgules
- **Exemple** : `22,80,443,3389`

#### Protocoles
- **Format** : Liste séparée par virgules
- **Exemple** : `CDP,OSPF,BGP,DHCP`

### Compatibilité Excel
- **Encodage** : UTF-8 avec BOM
- **Séparateur** : Point-virgule (standard français)
- **Dates** : Format ISO 8601
- **Guillemets** : Échappement automatique

## Export JSON

**Fichier** : `pkg/exporter/json_exporter.go`

### Structure Principale
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

### Objet Host Complet
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
  "hostname": "Router-01",
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
  },
  "cdp": {
    "device_id": "Router-01",
    "platform": "Cisco 2960",
    "version": "15.2(4)S7",
    "capabilities": 142,
    "capabilitiesDecoded": ["Router", "Switch", "IGMP"],
    "native_vlan": 1,
    "addresses": ["192.168.1.1"]
  },
  "anomalies": []
}
```

### Objet Subnet
```json
{
  "cidr": "192.168.1.0/24",
  "source": "dhcp",
  "hosts": ["192.168.1.1", "192.168.1.100"],
  "countHosts": 2,
  "vlans": [1, 10]
}
```

### Objet Anomaly
```json
{
  "type": "ip_duplicate_v4",
  "severity": "medium",
  "key": "ip:192.168.1.200/vlan:null",
  "scope": "global",
  "description": "IPv4 duplicate detected",
  "parameters": {
    "ip": "192.168.1.200",
    "vlan": 0,
    "macs": ["11:22:33:44:55:66", "aa:bb:cc:dd:ee:ff"],
    "count": 2
  }
}
```

### Métadonnées
- **Version** : Version du format d'export
- **GeneratedAt** : Timestamp de génération
- **Count** : Nombre d'hôtes exportés
- **Source** : Mode d'exécution (passive/active/combined)

## Export Markdown

**Fichier** : `pkg/exporter/markdown_exporter.go`

### Structure
```markdown
# Rapport Zandoli - Scan 2025-01-30

## Résumé
- **Hôtes découverts** : 42
- **VLANs** : 5
- **Anomalies** : 3
- **Durée** : 2m 30s

## Hôtes par Rôle

### Réseau (15 hôtes)
| IP | MAC | Vendor | Hostname | VLANs | L2 |
|----|-----|--------|----------|-------|----|
| 192.168.1.1 | aa:bb:cc:dd:ee:ff | Cisco Systems | Router-01 | 1,10,20 | CDP,STP |

### Serveurs (8 hôtes)
| IP | MAC | Vendor | Hostname | Services |
|----|-----|--------|----------|----------|
| 192.168.1.10 | 11:22:33:44:55:66 | Dell | Server-01 | 22,80,443 |

### Clients (19 hôtes)
| IP | MAC | Vendor | Hostname | OS |
|----|-----|--------|----------|----|
| 192.168.1.100 | 22:33:44:55:66:77 | Apple | MacBook-Pro | macOS |

## Sous-réseaux

### 192.168.1.0/24
- **Source** : DHCP
- **Hôtes** : 25
- **VLANs** : 1, 10

### 192.168.10.0/24
- **Source** : Computed
- **Hôtes** : 8
- **VLANs** : 10

## Anomalies

### Medium Severity
- **IP Duplicate** : 192.168.1.200 sur 2 MACs différents
- **MAC Multiple IP** : aa:bb:cc:dd:ee:ff avec 3 IPs

### Low Severity
- **Duplicate Hostname** : "LAPTOP-01" sur 2 équipements
```

### Fonctionnalités
- **Tableaux** : Formatage Markdown standard
- **Badges** : Emoji pour les rôles et protocoles
- **Liens** : Références internes
- **Code** : Blocs de code pour les détails techniques

## Export XML

**Fichier** : `pkg/exporter/xml_exporter.go`

### Structure
```xml
<?xml version="1.0" encoding="UTF-8"?>
<zandoli-report xmlns="http://zandoli.net/schema/v2"
                version="2.0"
                generatedAt="2025-01-30T10:30:00Z">
    
    <summary>
        <hosts count="42"/>
        <subnets count="5"/>
        <anomalies count="3"/>
    </summary>
    
    <hosts>
        <host>
            <ip>192.168.1.1</ip>
            <ipv6>2001:db8::1</ipv6>
            <mac>aa:bb:cc:dd:ee:ff</mac>
            <vendor>Cisco Systems</vendor>
            <role confidence="100">reseau</role>
            <protocols>
                <protocol>CDP</protocol>
                <protocol>OSPF</protocol>
                <protocol>BGP</protocol>
            </protocols>
            <vlans>
                <vlan id="1" primary="true"/>
                <vlan id="10"/>
                <vlan id="20"/>
            </vlans>
            <l2>
                <cdp detected="true">
                    <device-id>Router-01</device-id>
                    <platform>Cisco 2960</platform>
                    <version>15.2(4)S7</version>
                </cdp>
                <lldp detected="false"/>
                <stp detected="true"/>
                <eapol detected="true"/>
            </l2>
            <services>
                <tcp>
                    <port>22</port>
                    <port>23</port>
                    <port>80</port>
                    <port>443</port>
                </tcp>
                <udp>
                    <port>161</port>
                    <port>162</port>
                </udp>
            </services>
        </host>
    </hosts>
    
    <subnets>
        <subnet cidr="192.168.1.0/24" source="dhcp">
            <hosts count="25"/>
            <vlans>
                <vlan>1</vlan>
                <vlan>10</vlan>
            </vlans>
        </subnet>
    </subnets>
    
    <anomalies>
        <anomaly type="ip_duplicate_v4" severity="medium">
            <key>ip:192.168.1.200/vlan:null</key>
            <scope>global</scope>
            <description>IPv4 duplicate detected</description>
            <parameters>
                <ip>192.168.1.200</ip>
                <vlan>0</vlan>
                <macs count="2">
                    <mac>11:22:33:44:55:66</mac>
                    <mac>aa:bb:cc:dd:ee:ff</mac>
                </macs>
            </parameters>
        </anomaly>
    </anomalies>
</zandoli-report>
```

### Schéma XML
- **Namespace** : `http://zandoli.net/schema/v2`
- **Validation** : XSD disponible
- **Attributs** : Métadonnées (type, version, count)
- **Éléments** : Données structurées

## Export IPSet

**Fichier** : `pkg/exporter/ipset_exporter.go`

### Format
```
# IPSet export for iptables/firewalls
# Generated by Zandoli on 2025-01-30T10:30:00Z

# Network infrastructure hosts
192.168.1.1
192.168.1.10
192.168.1.100

# DHCP servers
192.168.1.1

# DNS servers
192.168.1.1
192.168.1.10
```

### Usage
```bash
# Import into iptables
ipset restore < hosts.ipset

# Use in firewall rules
iptables -A INPUT -m set --match-set zandoli-hosts src -j ACCEPT
```

## Configuration des Exports

### Sélection des Formats
```bash
# Format unique
./zandoli --pcap file.pcap --formats html

# Formats multiples
./zandoli --pcap file.pcap --formats html,csv,json

# Tous les formats
./zandoli --pcap file.pcap --formats html,csv,json,markdown,xml,ipset
```

### Répertoire de Sortie
```bash
# Répertoire personnalisé
./zandoli --pcap file.pcap --output-dir /tmp/results --formats html,csv
```

### Structure des Fichiers
```
output/scan_20250130-103000/
├── report.html          # Rapport HTML principal
├── hosts.csv            # Export CSV des hôtes
├── hosts.json           # Export JSON des hôtes
├── report.md            # Rapport Markdown
├── hosts.xml            # Export XML des hôtes
├── subnets.json         # Sous-réseaux JSON
├── anomalies.json       # Anomalies JSON
├── hosts.ipset          # Export IPSet
└── log.txt              # Logs de l'exécution
```

## Optimisations et Performance

### Génération Parallèle
- **Workers** : Génération simultanée des formats
- **Cache** : Réutilisation des données parsées
- **Streaming** : Écriture par chunks

### Compression
- **Gzip** : Compression automatique des gros fichiers
- **Minification** : HTML/CSS/JS minifiés
- **Optimisation** : Images et ressources optimisées

### Validation
- **JSON** : Validation de la structure
- **XML** : Validation XSD
- **CSV** : Vérification de l'encodage

---

**Voir aussi** : [CLI](CLI.md) | [Modèle de Données](DATA_MODEL.md) | [Pipeline](PIPELINE.md) | [Dépannage](TROUBLESHOOTING.md)