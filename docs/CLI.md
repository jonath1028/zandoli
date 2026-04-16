# Référence CLI Zandoli

> 📊 **Schémas visuels** : Consultez [schemas/configuration.md](schemas/configuration.md) pour des diagrammes détaillés de la configuration.

## Vue d'ensemble

Zandoli propose une interface en ligne de commande riche avec de nombreuses options pour configurer le comportement du scanner. Les options peuvent être définies via des flags CLI ou un fichier de configuration YAML.

## Syntaxe Générale

```bash
zandoli [OPTIONS]
```

## Options Principales

### Mode d'Exécution

#### `--passive`
**Type** : Booléen  
**Défaut** : `false`  
**Description** : Exécute uniquement le mode passif (écoute du trafic)

```bash
# Écoute passive uniquement
./zandoli --passive --passive-duration 60
```

#### `--active`
**Type** : Booléen  
**Défaut** : `false`  
**Description** : Exécute uniquement le mode actif (ARP/SYN)

```bash
# Scan actif uniquement
./zandoli --active --interface eth0
```

#### `--combined`
**Type** : Booléen  
**Défaut** : `false`  
**Description** : Exécute d'abord le mode passif, puis le mode actif

```bash
# Mode combiné (recommandé)
./zandoli --combined --passive-duration 30 --interface eth0
```

#### `--pcap <fichier>`
**Type** : String  
**Défaut** : `""`  
**Description** : Analyse un fichier PCAP (désactive le mode actif)

```bash
# Analyse PCAP
./zandoli --pcap testdata/traffic_lab.pcap --formats html,csv,json
```

#### `--SYN`
**Type** : Booléen  
**Défaut** : `false`  
**Description** : Active le scan SYN sur les hôtes non identifiés

```bash
# Avec scan SYN
./zandoli --combined --SYN --syn-ports 80,443,22
```

### Configuration Réseau

#### `--interface <iface>`
**Type** : String  
**Défaut** : `eth0` (depuis config)  
**Description** : Interface réseau à utiliser

```bash
# Interface spécifique
./zandoli --passive --interface wlan0
```

#### `--passive-duration <secondes>`
**Type** : Entier  
**Défaut** : `0` (depuis config)  
**Description** : Durée de l'écoute passive en secondes

```bash
# Écoute pendant 2 minutes
./zandoli --passive --passive-duration 120
```

#### `--blacklist <ips>`
**Type** : String (liste séparée par virgules)  
**Défaut** : `""`  
**Description** : IPs ou sous-réseaux à exclure

```bash
# Exclure des plages
./zandoli --active --blacklist "192.168.1.1,10.0.0.0/8,172.16.0.0/12"
```

### Configuration du Scan Actif

#### `--ttl <n>`
**Type** : Entier  
**Défaut** : `64` (depuis config)  
**Description** : TTL pour les paquets de scan actif

```bash
# TTL personnalisé
./zandoli --active --ttl 128
```

#### `--arp-max-per-sec <n>`
**Type** : Entier  
**Défaut** : `3` (depuis config)  
**Description** : Nombre maximum de requêtes ARP par seconde

```bash
# Scan ARP plus agressif
./zandoli --active --arp-max-per-sec 10
```

#### `--arp-burst <n>`
**Type** : Entier  
**Défaut** : `10` (depuis config)  
**Description** : Nombre maximum de requêtes ARP par rafale

```bash
# Rafales plus importantes
./zandoli --active --arp-burst 20
```

#### `--burst-min-delay <ms>`
**Type** : Entier  
**Défaut** : `0` (depuis config)  
**Description** : Délai minimum entre les rafales ARP (ms)

```bash
# Délais entre rafales
./zandoli --active --burst-min-delay 100 --burst-max-delay 500
```

#### `--burst-max-delay <ms>`
**Type** : Entier  
**Défaut** : `0` (depuis config)  
**Description** : Délai maximum entre les rafales ARP (ms)

#### `--syn-timeout <ms>`
**Type** : Entier  
**Défaut** : `0` (depuis config)  
**Description** : Timeout pour chaque tentative SYN (ms)

```bash
# Timeout SYN personnalisé
./zandoli --active --SYN --syn-timeout 5000
```

#### `--syn-ports <ports>`
**Type** : String (liste séparée par virgules)  
**Défaut** : `""` (depuis config)  
**Description** : Ports TCP à scanner avec SYN

```bash
# Ports spécifiques
./zandoli --active --SYN --syn-ports "22,80,443,3389,5900"
```

### Formats de Sortie

#### `--formats <formats>`
**Type** : String (liste séparée par virgules)  
**Défaut** : `""` (depuis config)  
**Description** : Formats d'export (json, csv, html, markdown, xml)

```bash
# Tous les formats
./zandoli --pcap file.pcap --formats html,csv,json,markdown,xml

# Format unique
./zandoli --passive --formats html
```

**Formats supportés** :
- `html` : Rapport HTML interactif
- `csv` : Export CSV (délimiteur `;`)
- `json` : Export JSON structuré
- `markdown` : Documentation Markdown
- `xml` : Export XML standardisé

#### `--output-dir <répertoire>`
**Type** : String  
**Défaut** : `output`  
**Description** : Répertoire pour les fichiers de sortie

```bash
# Répertoire personnalisé
./zandoli --pcap file.pcap --output-dir /tmp/zandoli_results
```

#### `--oui-file <fichier>`
**Type** : String  
**Défaut** : `""` (depuis config)  
**Description** : Fichier OUI pour la résolution des vendors

```bash
# Fichier OUI personnalisé
./zandoli --passive --oui-file /path/to/oui.txt
```

#### `--record-pcap`
**Type** : Booléen  
**Défaut** : `false`  
**Description** : Enregistre l'écoute live dans un fichier PCAP

```bash
# Enregistrer l'écoute
./zandoli --passive --record-pcap --passive-duration 300
```

### Logging et Verbosité

#### `--verbose`
**Type** : Booléen  
**Défaut** : `false`  
**Description** : Active les logs détaillés

```bash
# Logs détaillés
./zandoli --passive --verbose
```

#### `--quiet`
**Type** : Booléen  
**Défaut** : `false`  
**Description** : Réduit la verbosité des logs

```bash
# Logs réduits
./zandoli --active --quiet
```

#### `--paranoid`
**Type** : Booléen  
**Défaut** : `false`  
**Description** : Supprime tous les logs stdout

```bash
# Mode silencieux
./zandoli --passive --paranoid
```

#### `--summary`
**Type** : Booléen  
**Défaut** : `false`  
**Description** : Affiche un résumé en fin d'exécution

```bash
# Avec résumé
./zandoli --combined --summary
```

### Configuration

#### `--config <fichier>`
**Type** : String  
**Défaut** : `config.yaml`  
**Description** : Fichier de configuration YAML

```bash
# Configuration personnalisée
./zandoli --config my_config.yaml --passive
```

### Utilitaires

#### `--help`
**Type** : Booléen  
**Description** : Affiche l'aide et quitte

```bash
./zandoli --help
```

#### `--demo`
**Type** : Booléen  
**Description** : Affiche une démo des barres de progression

```bash
./zandoli --demo
```

## Exemples d'Utilisation

### Analyse PCAP Basique
```bash
# Analyse simple avec rapport HTML
./zandoli --pcap testdata/traffic_lab.pcap --formats html

# Analyse complète avec tous les formats
./zandoli --pcap testdata/traffic_lab.pcap --formats html,csv,json --summary
```

### Écoute Passive
```bash
# Écoute courte avec enregistrement
sudo ./zandoli --passive --passive-duration 30 --record-pcap --interface eth0

# Écoute longue avec logs détaillés
sudo ./zandoli --passive --passive-duration 300 --verbose --interface eth0
```

### Scan Actif
```bash
# Scan ARP simple
sudo ./zandoli --active --interface eth0

# Scan ARP avec mode stealth
sudo ./zandoli --active --interface eth0

# Scan avec SYN sur ports spécifiques
sudo ./zandoli --active --SYN --syn-ports "22,80,443" --interface eth0
```

### Mode Combiné (Recommandé)
```bash
# Scan combiné standard
sudo ./zandoli --combined --passive-duration 60 --interface eth0 --formats html,csv

# Scan combiné avec exclusions
sudo ./zandoli --combined --passive-duration 30 --blacklist "192.168.1.1,10.0.0.0/8" --interface eth0

# Scan combiné complet
sudo ./zandoli --combined --passive-duration 60 --SYN --syn-ports "22,80,443,3389" --formats html,csv,json --summary --interface eth0
```

### Configuration Avancée
```bash
# Avec fichier de configuration personnalisé
./zandoli --config my_config.yaml --passive

# Override de configuration via CLI
./zandoli --config my_config.yaml --passive-duration 120 --verbose --formats html
```

## Fichier de Configuration

Les options peuvent également être définies dans un fichier YAML (`config.yaml` par défaut) :

```yaml
interface: "eth0"
logging:
  verbose: false
  quiet: false
  paranoid: false
scan:
  ttl: 64
  arp_max_per_sec: 3
  arp_burst: 10
  burst_min_delay_ms: 0
  burst_max_delay_ms: 0
  syn_timeout_ms: 0
  syn_ports: []
  blacklist: []
  passive_duration_seconds: 0
  targeted: false
mode:
  passive: false
  active: false
  combined: false
  pcap: ""
  syn: false
output:
  base_dir: "output"
  record_pcap: false
  formats: []
  oui_file: ""
  allow_public_subnets: false
```

## Priorité des Options

1. **Flags CLI** (priorité maximale)
2. **Fichier de configuration YAML**
3. **Valeurs par défaut** (priorité minimale)

Les flags CLI écrasent toujours les valeurs du fichier de configuration.

## Validation des Options

### Validation des Formats
```bash
# ✅ Formats valides
./zandoli --formats html,csv,json

# ❌ Format invalide
./zandoli --formats html,invalid_format
# Erreur: Format invalide 'invalid_format'
```

### Validation des Ports SYN
```bash
# ✅ Ports valides
./zandoli --syn-ports "22,80,443"

# ❌ Ports invalides
./zandoli --syn-ports "22,99999,80"
# Erreur: Port invalide '99999'
```

### Validation des Interfaces
```bash
# ✅ Interface existante
./zandoli --interface eth0

# ❌ Interface inexistante
./zandoli --interface nonexistent
# Erreur: Interface 'nonexistent' non trouvée
```

## Codes de Sortie

- **0** : Succès
- **1** : Erreur générale (configuration, permissions, etc.)
- **2** : Erreur de validation des paramètres

## Variables d'Environnement

Aucune variable d'environnement n'est actuellement utilisée par Zandoli.

## Limitations

### Privilèges Requis
- **Écoute réseau** : Nécessite des droits root
- **Scan actif** : Nécessite des droits root
- **Lecture PCAP** : Droits de lecture standard

### Formats de Fichiers
- **PCAP** : Support .pcap et .pcapng
- **Configuration** : YAML uniquement
- **OUI** : Format texte standard

### Performance
- **Débit** : ~10K paquets/seconde
- **Mémoire** : ~100MB pour 1000 hôtes
- **CPU** : Parsing intensif sur gros PCAP

---

**Voir aussi** : [Pipeline](PIPELINE.md) | [Formats d'Export](EXPORTS.md) | [Dépannage](TROUBLESHOOTING.md) | [Architecture](ARCHITECTURE.md)