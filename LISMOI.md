# Zandoli Alpha – Analyseur de Réseau Passif/Actif

> 📖 **[English version](README.md)**

Zandoli est un analyseur de réseau avancé qui combine l'écoute passive et le scan actif pour découvrir et cartographier les équipements réseau. Il analyse les fichiers PCAP ou écoute en temps réel, extrait les informations Layer 2 (CDP, LLDP, STP, 802.1X) et Layer 3, puis génère des rapports HTML, CSV et JSON détaillés.

## ⚠️ Avertissement / Disclaimer

**Ce logiciel est fourni à des fins d'audit, de test et de recherche en sécurité.**

- **Autorisation requise** : n'utilise cet outil que sur des systèmes, réseaux ou captures pour lesquels tu disposes d'une autorisation explicite. Toute utilisation non autorisée peut être illégale.

- **Conformité** : respecte les lois et politiques applicables (protection des données, confidentialité, conditions d'utilisation, règles internes).

- **Données & confidentialité** : les analyses peuvent révéler des informations sensibles (adresses IP, identifiants de machines, métadonnées). Tu es seul responsable de la protection, du stockage et de la suppression de ces données conformément à la réglementation (ex. RGPD).

- **Aucune garantie** : le logiciel est fourni "en l'état", sans garantie d'exactitude ou d'adéquation à un usage particulier. Les auteurs et contributeurs ne pourront être tenus responsables de tout dommage direct ou indirect résultant de son utilisation.

- **Tiers & marques** : les marques citées appartiennent à leurs propriétaires. Les dépendances tierces restent soumises à leurs licences respectives.

- **Contributions** : en contribuant, tu acceptes que tes apports soient publiés sous la licence du projet.

**En utilisant ce logiciel, tu reconnais avoir lu et accepté cet avertissement.**

---

## 🎯 Objectif

Zandoli permet aux administrateurs réseau et aux professionnels de la sécurité de :
- **Découvrir** tous les équipements connectés au réseau
- **Identifier** les rôles des équipements (routeurs, commutateurs, serveurs, clients)
- **Analyser** les protocoles et services actifs
- **Cartographier** la topologie réseau avec les VLANs
- **Détecter** les anomalies et comportements suspects

## 🚀 Installation & Build

### Prérequis
- Go ≥ 1.24.2
- Linux/Unix (testé sur Kali Linux)
- Privilèges root pour l'écoute réseau (optionnel)

### Build
```bash
git clone <repository-url>
cd zandoli_private-main
go mod download
go build -o build/zandoli cmd/zandoli/main.go
```

### Installation rapide
```bash
# Cloner et compiler
git clone <repository-url> && cd zandoli_private-main
go build -o /usr/local/bin/zandoli cmd/zandoli/main.go

# Vérifier l'installation
zandoli --help
```

## ⚡ Utilisation Rapide

### 1. Analyse PCAP (recommandé pour débuter)
```bash
# Analyser un fichier PCAP avec tous les formats
./build/zandoli --pcap testdata/traffic_lab.pcap

# Résultats dans output/scan_YYYYMMDD-HHMMSS/
```

### 2. Écoute passive (30 secondes)
```bash
# Écoute passive sur interface eth0
sudo ./build/zandoli --passive --passive-duration 30 --interface eth0

# Avec enregistrement PCAP
sudo ./build/zandoli --passive --passive-duration 60 --record-pcap
```

### 3. Scan combiné (passif + actif)
```bash
# Écoute 30s puis scan ARP des hôtes inconnus
sudo ./build/zandoli --combined --passive-duration 30 --interface eth0
```

## 📊 Formats de Sortie

| Format | Fichier | Description |
|--------|---------|-------------|
| **HTML** | `report.html` | Rapport interactif avec filtres, recherche, badges |
| **CSV** | `hosts.csv` | Export tabulaire (délimiteur `;`) |
| **JSON** | `hosts.json` | Données structurées pour intégration |
| **Markdown** | `report.md` | Documentation textuelle |
| **XML** | `hosts.xml` | Format XML standardisé |

## 🔧 Options Principales

### Modes d'exécution
```bash
--passive              # Mode passif uniquement (écoute)
--active               # Mode actif uniquement (ARP/SYN)
--combined             # Mode combiné (passif puis actif)
--pcap <fichier>       # Analyse PCAP offline
--SYN                  # Scan SYN sur hôtes non identifiés
```

### Configuration réseau
```bash
--interface <iface>    # Interface réseau (défaut: eth0)
--passive-duration <s> # Durée écoute passive (secondes)
--ttl <n>              # TTL pour paquets actifs
--blacklist <ips>      # IPs/sous-réseaux à exclure
```

### Formats et sortie
```bash
--formats html,csv,json    # Formats d'export
--output-dir <dir>         # Répertoire de sortie
--oui-file <fichier>       # Fichier OUI pour vendor lookup
--record-pcap              # Enregistrer l'écoute en PCAP
```

### Logging
```bash
--verbose             # Logs détaillés
--quiet               # Logs réduits
--paranoid            # Aucun log stdout
--summary             # Afficher résumé en fin
```

## 📋 Table des Matières

### Documentation Utilisateur
- [**CLI & Options**](docs/CLI.md) - Référence complète des commandes
- [**Pipeline de Traitement**](docs/PIPELINE.md) - Étapes détaillées du processus
- [**Formats d'Export**](docs/EXPORTS.md) - HTML, CSV, JSON détaillés
- [**Protocoles L2**](docs/L2_PROTOCOLS.md) - CDP, LLDP, STP, 802.1X
- [**Logging**](docs/LOGGING.md) - Configuration et rotation des logs

### Documentation Technique
- [**Architecture**](docs/ARCHITECTURE.md) - Modules et flux de données
- [**Modèle de Données**](docs/DATA_MODEL.md) - Structures et types
- [**Dépannage**](docs/TROUBLESHOOTING.md) - Erreurs courantes et solutions
- [**Sécurité**](docs/SECURITY.md) - Considérations et bonnes pratiques

### Documentation Développeur
- [**Contribution**](CONTRIBUTING.md) - Guide pour contribuer au projet
- [**Glossaire**](docs/GLOSSARY.md) - Termes techniques et acronymes
- [**Changelog**](CHANGELOG.md) - Historique des versions

## 🎯 Exemples de Rapports

### Rapport HTML
Le rapport HTML généré contient :
- **Vue d'ensemble** : statistiques globales, topologie VLAN
- **Hôtes découverts** : tableau interactif avec filtres par rôle, VLAN, vendor
- **Détails L2** : informations CDP/LLDP/STP/802.1X
- **Services** : ports TCP/UDP ouverts par hôte
- **Anomalies** : détection automatique de comportements suspects
- **Sous-réseaux** : cartographie des segments réseau

### Export CSV
Format tabulaire avec colonnes :
```
MAC;Vendor;VLANs;L2Flags;IP;IPv6;UDP_Services;TCP_Services;Protocols
```

### Export JSON
Structure hiérarchique complète avec métadonnées :
```json
{
  "version": "Alpha",
  "generatedAt": "2025-01-30T10:30:00Z",
  "count": 42,
  "hosts": [...],
  "subnets": [...]
}
```

## ⚠️ Notes & Limites

- **Privilèges** : L'écoute réseau nécessite des droits root
- **Performance** : Optimisé pour réseaux < 1000 hôtes simultanés
- **PCAP** : Support des formats .pcap et .pcapng
- **VLANs** : Détection automatique via 802.1Q tags
- **IPv6** : Support complet IPv4/IPv6 dual-stack

## 📄 Licence

Ce projet est sous licence **Apache License 2.0** — voir le fichier [`LICENSE`](./LICENSE) pour les détails.

_Les contributions sont les bienvenues ; consultez [`CONTRIBUTING.md`](./CONTRIBUTING.md) et [`DCO.md`](./DCO.md)._

## 🤝 Contribution

Voir [CONTRIBUTING.md](CONTRIBUTING.md) pour les guidelines de contribution.

## 📞 Support

- **Documentation** : [docs/](docs/)
- **Issues** : Reportez les problèmes via les issues GitHub


---

**Voir aussi** : [Architecture](docs/ARCHITECTURE.md) | [CLI Reference](docs/CLI.md) | [Pipeline](docs/PIPELINE.md) | [Formats d'Export](docs/EXPORTS.md)

