# Architecture Zandoli

> 📊 **Schémas visuels** : Consultez [schemas/architecture.md](schemas/architecture.md) pour des diagrammes détaillés de l'architecture.

## Vue d'ensemble

Zandoli suit une architecture modulaire en couches, séparant clairement la logique métier (`pkg/`) de la configuration et utilitaires (`internal/`). Le pipeline de traitement suit un modèle producer-consumer avec des canaux Go pour la concurrence.

## Modules Principaux

### 1. Orchestrateur (`pkg/orchestrator/`)
**Responsabilité** : Coordination du pipeline complet
- **Fichiers** : 
  - `orchestrator.go` : Structure principale Orchestrator
  - `run_pipeline.go` : Exécution du pipeline
  - `orchestrator_factory.go` : Factory pour créer les orchestrateurs
- **Rôle** : Point d'entrée, gestion des modes (passif/actif/combiné)
- **Interfaces** : `ActiveScanFunc` pour injection de dépendances

### 2. Sniffer (`pkg/sniffer/`)
**Responsabilité** : Capture et parsing des paquets
- **Fichiers** : 
  - `pcap_sniffer.go` : Lecture PCAP offline
  - `live_sniffer.go` : Écoute live avec BPF
  - `packet_source.go` : Interface PacketSource
  - `pcap_open.go` : Fonctions d'ouverture PCAP
  - `pcap_progress.go` : Gestion du progrès de lecture
  - `perf.go` : Métriques de performance
  - `statistics.go` : Statistiques de capture
- **Fonctionnalités** :
  - Lecture PCAP offline avec barre de progression
  - Écoute live avec BPF et timeout configurable
  - Parsing Ethernet/IP/TCP/UDP
  - Détection VLAN 802.1Q
  - Enregistrement PCAP optionnel

### 3. Analyseur (`pkg/analyzer/`)
**Responsabilité** : Découverte et analyse des protocoles
- **Fichiers principaux** :
  - `analyze.go` : Stack d'analyse complet
  - `dispatcher.go` : Routage des paquets vers parseurs spécialisés
  - `aggregator.go` : Agrégation et corrélation des données
  - `role_inference.go` : Inférence des rôles d'équipements
  - `priority_matrix.go` : Gestion des priorités et conflits
  - `results.go` : Gestion des résultats
  - `parsed_record.go` : Structure ParsedRecord

**Parseurs spécialisés** :
- `cdp.go` : Cisco Discovery Protocol
- `lldp.go` : Link Layer Discovery Protocol
- `stp.go` : Spanning Tree Protocol
- `8021x.go` : Authentification 802.1X/EAPOL
- `dhcp.go` : DHCP et attribution d'IP
- `arp_passive.go` : ARP passif
- `tcp.go` : Analyse TCP et fingerprinting OS
- `mdns.go` : Multicast DNS
- `netbios.go` : NetBIOS Name Service
- `llmnr.go` : Link-Local Multicast Name Resolution
- `igmp.go` : Internet Group Management Protocol
- `ndp.go` : Neighbor Discovery Protocol
- `smb.go` : Server Message Block
- `ssdp.go` : Simple Service Discovery Protocol
- `os.go` : Détection d'OS par TCP fingerprinting
- `category.go` : Classification des équipements
- `anomaly.go` : Détection d'anomalies
- `subnet.go` : Gestion des sous-réseaux
- `topology.go` : Analyse topologique
- `vlan.go` : Gestion des VLAN
- `register.go` : Enregistrement des parseurs
- `tcp_consolidator.go` : Consolidation TCP

### 4. Scanner (`pkg/scanner/`)
**Responsabilité** : Scans actifs ARP et SYN
- **Fichiers** : 
  - `arp_scanner.go` : Scan ARP avec régulation
  - `syn_scanner.go` : Scan SYN TCP
  - `run_active_scan.go` : Coordination des scans actifs
  - `arp_listener.go` : Écoute des réponses ARP
  - `blacklist.go` : Gestion des exclusions
- **Fonctionnalités** :
  - Scan ARP avec régulation de débit
  - Scan SYN TCP sur ports configurables
  - Mode stealth avec randomisation
  - Blacklist et exclusions
  - Mode ciblé basé sur les résultats passifs

### 5. Modèle (`pkg/model/`)
**Responsabilité** : Structures de données partagées
- **Fichiers** :
  - `types.go` : Structures principales (Host, Subnet, Anomaly)
  - `strength.go` : Gestion des priorités d'association
- **Types clés** :
  - `Host` : Hôte découvert avec métadonnées
  - `CDPInfo`, `LLDPInfo`, `STPInfo` : Détails protocoles L2
  - `Anomaly` : Détection d'anomalies
  - `Subnet` : Sous-réseaux découverts
  - `TCPOptions` : Options TCP pour fingerprinting OS

### 6. Exportateur (`pkg/exporter/`)
**Responsabilité** : Génération des rapports
- **Formats supportés** :
  - `html_exporter.go` : Rapport HTML interactif
  - `csv_exporter.go` : Export CSV (délimiteur `;`)
  - `json_exporter.go` : Export JSON structuré
  - `markdown_exporter.go` : Export Markdown
  - `xml_exporter.go` : Export XML
  - `ipset_exporter.go` : Export pour outils réseau

### 7. Utilitaires (`pkg/utils/`)
**Responsabilité** : Fonctions communes
- **Fichiers** :
  - `ip.go` : Manipulation IP et détection privées/publiques
  - `slices.go` : Helpers pour slices (contains, merge)
  - `parse.go` : Parsing et validation
  - `network.go` : Utilitaires réseau
  - `interface.go` : Gestion des interfaces
  - `validation.go` : Validation des données
  - `pcap_writer.go` : Écriture de fichiers PCAP
  - `bpf_filter.go` : Filtres BPF
  - `oui_loader.go` : Chargement des données OUI
  - `oui_network.go` : Résolution OUI et vendors

### 8. Interface Utilisateur (`pkg/ui/`)
**Responsabilité** : Affichage et interactions
- **Fichiers** : 
  - `progress.go` : Barres de progression
  - `summary.go` : Résumés CLI
- **Fonctionnalités** : Barres de progression, résumés CLI

### 9. Fusion (`pkg/fusion/`)
**Responsabilité** : Fusion des données passives et actives
- **Fichiers** :
  - `fusion.go` : Logique de fusion
  - `merge.go` : Fusion des données d'hôtes

## Configuration et Logging

### Configuration (`internal/config/`)
- **Format** : YAML avec valeurs par défaut
- **Override** : Flags CLI écrasent la config
- **Validation** : Vérification des paramètres

### Logging (`internal/logger/`)
- **Framework** : zerolog
- **Sorties** : Console + fichier `output/log.txt`
- **Niveaux** : Debug, Info, Warn, Error

### OUI Database (`internal/oui/`)
- **Fichiers** :
  - `loader.go` : Chargement des données OUI
  - `oui_data.go` : Données OUI embarquées
  - `oui_embedded.txt` : Base de données OUI

### Validation (`internal/validation/`)
- **Fichiers** :
  - `validation.go` : Validation des entrées

## Pipeline de Données

### Étapes du Pipeline

1. **Capture** : PCAP ou interface live
2. **Parsing** : Décodage Ethernet/IP/TCP/UDP
3. **Routage** : Dispatch vers parseurs spécialisés
4. **Agrégation** : Fusion des données par hôte
5. **Corrélation** : Association IP↔MAC avec priorités
6. **Inférence** : Détermination des rôles
7. **Export** : Génération des rapports

## Gestion de la Concurrence

### Canaux Go
- **PacketEvent** : Canal principal pour les paquets
- **ParsedRecord** : Canal pour les données parsées
- **Host** : Canal pour les hôtes finalisés

### Goroutines
- **1 goroutine** : Capture des paquets
- **N goroutines** : Parsing parallèle par protocole
- **1 goroutine** : Agrégation et corrélation
- **1 goroutine** : Export des résultats

## Points d'Extension

### Nouveaux Parseurs
1. Créer un fichier dans `pkg/analyzer/`
2. Implémenter la fonction de parsing
3. Enregistrer dans le dispatcher
4. Ajouter les tests unitaires

### Nouveaux Formats d'Export
1. Créer un fichier dans `pkg/exporter/`
2. Implémenter la fonction d'export
3. Ajouter le format dans la validation
4. Mettre à jour la documentation

### Nouveaux Scans Actifs
1. Étendre `pkg/scanner/`
2. Implémenter la régulation de débit
3. Ajouter la configuration
4. Intégrer dans l'orchestrateur

## Séparation des Responsabilités

### `internal/` (Configuration & Utilitaires)
- ❌ **Aucune logique métier**
- ✅ Configuration, logging, validation
- ✅ Pas d'export vers `pkg/`

### `pkg/` (Logique Métier)
- ✅ **Code réutilisable et modulaire**
- ✅ Peut utiliser `internal/` (config, logger)
- ✅ Pas de dépendances latérales non justifiées

### Points d'Attention
- **Circular imports** : Interdits entre packages `pkg/`
- **Global state** : Évité sauf pour contrôles explicites
- **Error handling** : Propagation systématique
- **Testing** : Couverture > 80% recommandée

---

**Voir aussi** : [Pipeline](PIPELINE.md) | [Modèle de Données](DATA_MODEL.md) | [CLI](CLI.md) | [Contribution](../CONTRIBUTING.md)