# Schémas des Formats d'Export Zandoli

## Vue d'ensemble des Exports

```mermaid
graph TB
    subgraph "Données Sources"
        HOSTS[Hosts Découverts]
        SUBNETS[Sous-réseaux]
        ANOMALIES[Anomalies]
        STATS[Statistiques]
    end
    
    subgraph "Formats d'Export"
        JSON[JSON Export]
        HTML[HTML Export]
        CSV[CSV Export]
        XML[XML Export]
        MARKDOWN[Markdown Export]
        IPSET[IPSet Export]
    end
    
    subgraph "Fichiers Générés"
        HOSTS_JSON[hosts.json]
        SUBNETS_JSON[subnets.json]
        ANOMALIES_JSON[anomalies.json]
        REPORT_HTML[report.html]
        HOSTS_CSV[hosts.csv]
        SUBNETS_CSV[subnets.csv]
        HOSTS_XML[hosts.xml]
        REPORT_MD[report.md]
        HOSTS_IPSET[hosts.ipset]
    end
    
    HOSTS --> JSON
    HOSTS --> HTML
    HOSTS --> CSV
    HOSTS --> XML
    HOSTS --> MARKDOWN
    HOSTS --> IPSET
    
    SUBNETS --> JSON
    SUBNETS --> CSV
    
    ANOMALIES --> JSON
    
    STATS --> HTML
    STATS --> MARKDOWN
    
    JSON --> HOSTS_JSON
    JSON --> SUBNETS_JSON
    JSON --> ANOMALIES_JSON
    
    HTML --> REPORT_HTML
    
    CSV --> HOSTS_CSV
    CSV --> SUBNETS_CSV
    
    XML --> HOSTS_XML
    
    MARKDOWN --> REPORT_MD
    
    IPSET --> HOSTS_IPSET
```

## Structure JSON

```mermaid
classDiagram
    class JSONHost {
        +string ip
        +string ipv6
        +string macStr
        +string vendor
        +string role
        +int roleConfidence
        +[]string roleSignals
        +[]string protocols
        +string info
        +string hostname
        +int ttl
        +string osGuess
        +uint8 osScore
        +[]string osSignals
        +int windowSize
        +TCPOptions tcpOptions
        +[]int ports
        +[]int vlans
        +map[int]int vlanStats
        +int primaryVlan
        +uint64 packetCount
        +uint64 byteCount
        +[]string securityFeatures
        +[]string ips
        +[]IPObservation ipsAll
        +map[string][]string protocolsByIP
        +L2Signals l2Signals
        +CDPInfo cdp
        +LLDPInfo lldp
        +STPInfo stp
        +[]Anomaly anomalies
        +time.Time firstSeen
        +time.Time lastSeen
    }
    
    class JSONSubnet {
        +string network
        +string gateway
        +int hostCount
        +[]string hosts
        +map[string]int roleDistribution
        +map[string]int vendorDistribution
        +[]string anomalies
    }
    
    class JSONAnomaly {
        +string type
        +string description
        +string severity
        +string key
        +string scope
        +map[string]interface{} details
    }
    
    JSONHost --> JSONAnomaly
    JSONSubnet --> JSONHost
```

## Structure HTML

```mermaid
graph TD
    subgraph "Template HTML"
        HEADER[En-tête HTML]
        NAVIGATION[Navigation]
        CONTENT[Contenu Principal]
        FOOTER[Pied de page]
    end
    
    subgraph "Sections Principales"
        SUMMARY[Résumé Global]
        HOSTS_TABLE[Tableau des Hôtes]
        SUBNETS_TABLE[Tableau des Sous-réseaux]
        ANOMALIES_TABLE[Tableau des Anomalies]
        STATS[Statistiques]
    end
    
    subgraph "Fonctionnalités Interactives"
        FILTERS[Filtres]
        SEARCH[Recherche]
        SORT[Triage]
        EXPAND[Détails Expandables]
    end
    
    subgraph "Styles et Scripts"
        CSS[Feuilles de Style]
        JS[JavaScript]
        CHARTS[Graphiques]
    end
    
    HEADER --> NAVIGATION
    NAVIGATION --> CONTENT
    CONTENT --> FOOTER
    
    CONTENT --> SUMMARY
    CONTENT --> HOSTS_TABLE
    CONTENT --> SUBNETS_TABLE
    CONTENT --> ANOMALIES_TABLE
    CONTENT --> STATS
    
    HOSTS_TABLE --> FILTERS
    HOSTS_TABLE --> SEARCH
    HOSTS_TABLE --> SORT
    HOSTS_TABLE --> EXPAND
    
    HEADER --> CSS
    FOOTER --> JS
    STATS --> CHARTS
```

## Structure CSV

```mermaid
graph TD
    subgraph "Colonnes CSV"
        MAC[MAC Address]
        VENDOR[Vendor]
        VLANS[VLANs]
        L2_FLAGS[L2 Flags]
        IP[IP Address]
        IPV6[IPv6 Address]
        UDP_SERVICES[UDP Services]
        TCP_SERVICES[TCP Services]
        PROTOCOLS[Protocols]
        OS[Operating System]
    end
    
    subgraph "Formatage"
        DELIMITER[Délimiteur ;]
        QUOTES[Guillemets]
        ESCAPING[Échappement]
        ENCODING[Encodage UTF-8]
    end
    
    subgraph "Fichiers CSV"
        HOSTS_CSV[hosts.csv]
        SUBNETS_CSV[subnets.csv]
        ANOMALIES_CSV[anomalies.csv]
    end
    
    MAC --> DELIMITER
    VENDOR --> DELIMITER
    VLANS --> DELIMITER
    L2_FLAGS --> DELIMITER
    IP --> DELIMITER
    IPV6 --> DELIMITER
    UDP_SERVICES --> DELIMITER
    TCP_SERVICES --> DELIMITER
    PROTOCOLS --> DELIMITER
    OS --> DELIMITER
    
    DELIMITER --> QUOTES
    QUOTES --> ESCAPING
    ESCAPING --> ENCODING
    
    ENCODING --> HOSTS_CSV
    ENCODING --> SUBNETS_CSV
    ENCODING --> ANOMALIES_CSV
```

## Flux de Génération des Exports

```mermaid
sequenceDiagram
    participant O as Orchestrator
    participant E as Exporter
    participant J as JSON Exporter
    participant H as HTML Exporter
    participant C as CSV Exporter
    participant X as XML Exporter
    participant M as Markdown Exporter
    participant I as IPSet Exporter
    
    O->>E: Demande d'export
    E->>J: Export JSON
    E->>H: Export HTML
    E->>C: Export CSV
    E->>X: Export XML
    E->>M: Export Markdown
    E->>I: Export IPSet
    
    J->>J: Sérialisation JSON
    H->>H: Génération HTML
    C->>C: Formatage CSV
    X->>X: Génération XML
    M->>M: Génération Markdown
    I->>I: Génération IPSet
    
    J->>E: Fichiers JSON
    H->>E: Fichier HTML
    C->>E: Fichiers CSV
    X->>E: Fichier XML
    M->>E: Fichier Markdown
    I->>E: Fichier IPSet
    
    E->>O: Confirmation export
```

## Sélection des IPs pour l'Export

```mermaid
flowchart TD
    subgraph "Entrée"
        HOST_IPS[Toutes les IPs du Host]
    end
    
    subgraph "Filtrage"
        EXCLUDE_CHECK[Vérification Exclusions]
        IPV4_FILTER[Filtre IPv4]
        IPV6_FILTER[Filtre IPv6]
    end
    
    subgraph "Priorisation IPv4"
        RFC1918_CHECK[Vérification RFC1918]
        APIPA_CHECK[Vérification APIPA]
        PUBLIC_CHECK[Vérification Publique]
    end
    
    subgraph "Priorisation IPv6"
        GLOBAL_CHECK[Vérification Globale]
        ULA_CHECK[Vérification ULA]
    end
    
    subgraph "Sortie"
        PRIMARY_IPV4[IP Principale IPv4]
        PRIMARY_IPV6[IP Principale IPv6]
        OTHER_IPV4[Autres IPv4]
        OTHER_IPV6[Autres IPv6]
    end
    
    HOST_IPS --> EXCLUDE_CHECK
    EXCLUDE_CHECK --> IPV4_FILTER
    EXCLUDE_CHECK --> IPV6_FILTER
    
    IPV4_FILTER --> RFC1918_CHECK
    RFC1918_CHECK --> APIPA_CHECK
    APIPA_CHECK --> PUBLIC_CHECK
    
    IPV6_FILTER --> GLOBAL_CHECK
    GLOBAL_CHECK --> ULA_CHECK
    
    RFC1918_CHECK --> PRIMARY_IPV4
    APIPA_CHECK --> PRIMARY_IPV4
    PUBLIC_CHECK --> PRIMARY_IPV4
    
    GLOBAL_CHECK --> PRIMARY_IPV6
    ULA_CHECK --> PRIMARY_IPV6
    
    PRIMARY_IPV4 --> OTHER_IPV4
    PRIMARY_IPV6 --> OTHER_IPV6
```

## Template HTML - Structure Détaillée

```mermaid
graph TD
    subgraph "En-tête HTML"
        DOCTYPE[DOCTYPE html]
        HTML_TAG[html lang="fr"]
        HEAD[head]
        META[Meta tags]
        TITLE[Titre]
        CSS_LINKS[Liens CSS]
    end
    
    subgraph "Corps Principal"
        BODY[body]
        HEADER[header]
        NAV[nav]
        MAIN[main]
        FOOTER[footer]
    end
    
    subgraph "Contenu Principal"
        SUMMARY_SECTION[Section Résumé]
        HOSTS_SECTION[Section Hôtes]
        SUBNETS_SECTION[Section Sous-réseaux]
        ANOMALIES_SECTION[Section Anomalies]
        STATS_SECTION[Section Statistiques]
    end
    
    subgraph "Composants Interactifs"
        FILTER_PANEL[Panneau Filtres]
        SEARCH_BOX[Boîte Recherche]
        SORT_CONTROLS[Contrôles Tri]
        DETAIL_MODAL[Modal Détails]
    end
    
    DOCTYPE --> HTML_TAG
    HTML_TAG --> HEAD
    HTML_TAG --> BODY
    
    HEAD --> META
    HEAD --> TITLE
    HEAD --> CSS_LINKS
    
    BODY --> HEADER
    BODY --> NAV
    BODY --> MAIN
    BODY --> FOOTER
    
    MAIN --> SUMMARY_SECTION
    MAIN --> HOSTS_SECTION
    MAIN --> SUBNETS_SECTION
    MAIN --> ANOMALIES_SECTION
    MAIN --> STATS_SECTION
    
    HOSTS_SECTION --> FILTER_PANEL
    HOSTS_SECTION --> SEARCH_BOX
    HOSTS_SECTION --> SORT_CONTROLS
    HOSTS_SECTION --> DETAIL_MODAL
```

## Gestion des Erreurs d'Export

```mermaid
graph TD
    subgraph "Types d'Erreurs"
        FILE_ERROR[Erreur Fichier]
        PERMISSION_ERROR[Erreur Permission]
        DISK_ERROR[Erreur Disque]
        ENCODING_ERROR[Erreur Encodage]
    end
    
    subgraph "Gestion"
        ERROR_DETECTION[Détection Erreur]
        ERROR_LOGGING[Logging Erreur]
        ERROR_RECOVERY[Récupération]
        ERROR_REPORTING[Rapport Erreur]
    end
    
    subgraph "Actions"
        RETRY[Réessayer]
        SKIP[Ignorer]
        ABORT[Abandonner]
        FALLBACK[Mode Dégradé]
    end
    
    FILE_ERROR --> ERROR_DETECTION
    PERMISSION_ERROR --> ERROR_DETECTION
    DISK_ERROR --> ERROR_DETECTION
    ENCODING_ERROR --> ERROR_DETECTION
    
    ERROR_DETECTION --> ERROR_LOGGING
    ERROR_LOGGING --> ERROR_RECOVERY
    ERROR_RECOVERY --> ERROR_REPORTING
    
    ERROR_RECOVERY --> RETRY
    ERROR_RECOVERY --> SKIP
    ERROR_RECOVERY --> ABORT
    ERROR_RECOVERY --> FALLBACK
```

## Métriques d'Export

```mermaid
graph TB
    subgraph "Métriques Temps"
        EXPORT_TIME[Temps Export Total]
        JSON_TIME[Temps Export JSON]
        HTML_TIME[Temps Export HTML]
        CSV_TIME[Temps Export CSV]
    end
    
    subgraph "Métriques Taille"
        JSON_SIZE[Taille Fichiers JSON]
        HTML_SIZE[Taille Fichier HTML]
        CSV_SIZE[Taille Fichiers CSV]
        TOTAL_SIZE[Taille Totale]
    end
    
    subgraph "Métriques Performance"
        HOSTS_COUNT[Nombre Hôtes Exportés]
        SUBNETS_COUNT[Nombre Sous-réseaux]
        ANOMALIES_COUNT[Nombre Anomalies]
        SUCCESS_RATE[Taux de Succès]
    end
    
    EXPORT_TIME --> DASHBOARD[Dashboard Métriques]
    JSON_TIME --> DASHBOARD
    HTML_TIME --> DASHBOARD
    CSV_TIME --> DASHBOARD
    
    JSON_SIZE --> DASHBOARD
    HTML_SIZE --> DASHBOARD
    CSV_SIZE --> DASHBOARD
    TOTAL_SIZE --> DASHBOARD
    
    HOSTS_COUNT --> DASHBOARD
    SUBNETS_COUNT --> DASHBOARD
    ANOMALIES_COUNT --> DASHBOARD
    SUCCESS_RATE --> DASHBOARD
```

## Configuration des Exports

```mermaid
graph TD
    subgraph "Configuration YAML"
        OUTPUT_CONFIG[output:]
        BASE_DIR[base_dir]
        FORMATS[formats]
        RECORD_PCAP[record_pcap]
        OUI_FILE[oui_file]
        ALLOW_PUBLIC[allow_public_subnets]
    end
    
    subgraph "Formats Disponibles"
        JSON_FORMAT[json]
        HTML_FORMAT[html]
        CSV_FORMAT[csv]
        XML_FORMAT[xml]
        MARKDOWN_FORMAT[markdown]
        IPSET_FORMAT[ipset]
    end
    
    subgraph "Validation"
        FORMAT_VALIDATION[Validation Formats]
        PATH_VALIDATION[Validation Chemins]
        PERMISSION_CHECK[Vérification Permissions]
    end
    
    OUTPUT_CONFIG --> BASE_DIR
    OUTPUT_CONFIG --> FORMATS
    OUTPUT_CONFIG --> RECORD_PCAP
    OUTPUT_CONFIG --> OUI_FILE
    OUTPUT_CONFIG --> ALLOW_PUBLIC
    
    FORMATS --> JSON_FORMAT
    FORMATS --> HTML_FORMAT
    FORMATS --> CSV_FORMAT
    FORMATS --> XML_FORMAT
    FORMATS --> MARKDOWN_FORMAT
    FORMATS --> IPSET_FORMAT
    
    FORMATS --> FORMAT_VALIDATION
    BASE_DIR --> PATH_VALIDATION
    PATH_VALIDATION --> PERMISSION_CHECK
```
