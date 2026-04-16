# Schémas de Configuration Zandoli

## Vue d'ensemble de la Configuration

```mermaid
graph TB
    subgraph "Sources de Configuration"
        YAML_FILE[config.yaml]
        CLI_FLAGS[Flags CLI]
        DEFAULTS[Valeurs par Défaut]
    end
    
    subgraph "Structure Config"
        CONFIG[Config Struct]
        LOGGING[Logging]
        SCAN[Scan Settings]
        MODE[Mode]
        OUTPUT[Output Paths]
        CLI_FLAGS_STRUCT[CLI Flags]
    end
    
    subgraph "Validation"
        VALIDATION[Validation]
        ERROR_HANDLING[Gestion Erreurs]
    end
    
    YAML_FILE --> CONFIG
    CLI_FLAGS --> CONFIG
    DEFAULTS --> CONFIG
    
    CONFIG --> LOGGING
    CONFIG --> SCAN
    CONFIG --> MODE
    CONFIG --> OUTPUT
    CONFIG --> CLI_FLAGS_STRUCT
    
    CONFIG --> VALIDATION
    VALIDATION --> ERROR_HANDLING
```

## Structure de Configuration Complète

```mermaid
classDiagram
    class Config {
        +string Interface
        +Logging Logging
        +ScanSettings Scan
        +Mode Mode
        +OutputPaths Output
        +CLIFlags CLI
    }
    
    class Logging {
        +bool Verbose
        +bool Quiet
        +bool Paranoid
    }
    
    class ScanSettings {
        +int TTL
        +int ARPMaxPerSec
        +int ARPBurst
        +int BurstMinDelayMs
        +int BurstMaxDelayMs
        +int SYNTimeoutMs
        +[]int SYNPorts
        +[]string Blacklist
        +int PassiveDurationSeconds
        +bool Targeted
        +bool EnableMetrics
        +int MetricsSampleRate
        +int ParallelWorkers
        +int StealthMaxPerSecondMin
        +int StealthMaxPerSecondMax
        +int StealthMaxBurstPerWindowMin
        +int StealthMaxBurstPerWindowMax
        +int StealthBurstWindowSecondsMin
        +int StealthBurstWindowSecondsMax
        +int StealthMicroburstMin
        +int StealthMicroburstMax
        +int StealthPauseMinMs
        +int StealthPauseMaxMs
        +int SYNMicroburstMin
        +int SYNMicroburstMax
        +int SYNPauseMinMs
        +int SYNPauseMaxMs
        +int SYNJitterMinMs
        +int SYNJitterMaxMs
    }
    
    class Mode {
        +bool Passive
        +bool Active
        +bool Combined
        +string PcapFile
        +bool SYN
    }
    
    class OutputPaths {
        +string BaseDir
        +bool RecordPCAP
        +[]string Formats
        +string OUIFile
        +bool AllowPublicSubnets
    }
    
    class CLIFlags {
        +bool Summary
    }
    
    Config --> Logging
    Config --> ScanSettings
    Config --> Mode
    Config --> OutputPaths
    Config --> CLIFlags
```

## Modes d'Exécution

```mermaid
stateDiagram-v2
    [*] --> ModeSelection
    
    ModeSelection --> Passive : --passive
    ModeSelection --> Active : --active
    ModeSelection --> Combined : --combined
    ModeSelection --> PCAP : --pcap file
    
    Passive --> LiveSniffing
    Active --> ARPScanning
    Active --> SYNScanning : --SYN
    Combined --> LiveSniffing
    Combined --> ARPScanning
    PCAP --> FileProcessing
    
    LiveSniffing --> Analysis
    ARPScanning --> Analysis
    SYNScanning --> Analysis
    FileProcessing --> Analysis
    
    Analysis --> Export
    Export --> [*]
    
    note right of Passive : Écoute uniquement
    note right of Active : Scan ARP/SYN
    note right of Combined : Passif puis actif
    note right of PCAP : Analyse offline
```

## Configuration des Scans

```mermaid
graph TD
    subgraph "Paramètres ARP"
        ARP_MAX_PER_SEC[arp_max_per_sec: 3]
        ARP_BURST[arp_burst: 10]
        BURST_MIN_DELAY[burst_min_delay_ms: 100]
        BURST_MAX_DELAY[burst_max_delay_ms: 500]
    end
    
    subgraph "Paramètres SYN"
        SYN_TIMEOUT[syn_timeout_ms: 1000]
        SYN_PORTS[syn_ports: [80,443,22]]
        SYN_ENABLED[SYN: false]
    end
    
    subgraph "Paramètres Généraux"
        TTL_VALUE[ttl: 64]
        BLACKLIST[blacklist: []]
        TARGETED[targeted: false]
        PASSIVE_DURATION[passive_duration_seconds: 0]
    end
    
    subgraph "Paramètres Stealth"
        STEALTH_MIN[stealth_max_per_second_min: 1]
        STEALTH_MAX[stealth_max_per_second_max: 5]
        STEALTH_BURST_MIN[stealth_max_burst_per_window_min: 2]
        STEALTH_BURST_MAX[stealth_max_burst_per_window_max: 8]
    end
    
    ARP_MAX_PER_SEC --> SCAN_CONFIG
    ARP_BURST --> SCAN_CONFIG
    BURST_MIN_DELAY --> SCAN_CONFIG
    BURST_MAX_DELAY --> SCAN_CONFIG
    SYN_TIMEOUT --> SCAN_CONFIG
    SYN_PORTS --> SCAN_CONFIG
    SYN_ENABLED --> SCAN_CONFIG
    TTL_VALUE --> SCAN_CONFIG
    BLACKLIST --> SCAN_CONFIG
    TARGETED --> SCAN_CONFIG
    PASSIVE_DURATION --> SCAN_CONFIG
    STEALTH_MIN --> SCAN_CONFIG
    STEALTH_MAX --> SCAN_CONFIG
    STEALTH_BURST_MIN --> SCAN_CONFIG
    STEALTH_BURST_MAX --> SCAN_CONFIG
    
    SCAN_CONFIG[Configuration Scan]
```

## Configuration des Logs

```mermaid
graph TD
    subgraph "Niveaux de Log"
        VERBOSE[verbose: false]
        QUIET[quiet: false]
        PARANOID[paranoid: false]
    end
    
    subgraph "Comportements"
        VERBOSE_BEHAVIOR[Logs détaillés]
        QUIET_BEHAVIOR[Logs minimaux]
        PARANOID_BEHAVIOR[Pas de stdout]
    end
    
    subgraph "Fichiers de Log"
        LOG_FILE[output/log.txt]
        ERROR_LOG[output/error.log]
        DEBUG_LOG[output/debug.log]
    end
    
    VERBOSE --> VERBOSE_BEHAVIOR
    QUIET --> QUIET_BEHAVIOR
    PARANOID --> PARANOID_BEHAVIOR
    
    VERBOSE_BEHAVIOR --> LOG_FILE
    QUIET_BEHAVIOR --> LOG_FILE
    PARANOID_BEHAVIOR --> ERROR_LOG
    
    LOG_FILE --> DEBUG_LOG
```

## Configuration des Exports

```mermaid
graph TD
    subgraph "Répertoire de Sortie"
        BASE_DIR[base_dir: "output"]
    end
    
    subgraph "Formats Disponibles"
        JSON_FORMAT[json]
        HTML_FORMAT[html]
        CSV_FORMAT[csv]
        XML_FORMAT[xml]
        MARKDOWN_FORMAT[markdown]
        IPSET_FORMAT[ipset]
    end
    
    subgraph "Options Supplémentaires"
        RECORD_PCAP[record_pcap: false]
        OUI_FILE[oui_file: ""]
        ALLOW_PUBLIC[allow_public_subnets: false]
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
    
    BASE_DIR --> JSON_FORMAT
    BASE_DIR --> HTML_FORMAT
    BASE_DIR --> CSV_FORMAT
    BASE_DIR --> XML_FORMAT
    BASE_DIR --> MARKDOWN_FORMAT
    BASE_DIR --> IPSET_FORMAT
    
    JSON_FORMAT --> HOSTS_JSON
    JSON_FORMAT --> SUBNETS_JSON
    JSON_FORMAT --> ANOMALIES_JSON
    
    HTML_FORMAT --> REPORT_HTML
    
    CSV_FORMAT --> HOSTS_CSV
    CSV_FORMAT --> SUBNETS_CSV
    
    XML_FORMAT --> HOSTS_XML
    
    MARKDOWN_FORMAT --> REPORT_MD
    
    IPSET_FORMAT --> HOSTS_IPSET
    
    RECORD_PCAP --> BASE_DIR
    OUI_FILE --> BASE_DIR
    ALLOW_PUBLIC --> BASE_DIR
```

## Priorité de Configuration

```mermaid
graph TD
    subgraph "Ordre de Priorité"
        CLI_FLAGS[1. Flags CLI - Priorité Max]
        YAML_CONFIG[2. config.yaml - Priorité Moyenne]
        DEFAULTS[3. Valeurs par Défaut - Priorité Min]
    end
    
    subgraph "Exemples de Surcharge"
        INTERFACE_FLAG[--interface eth1]
        VERBOSE_FLAG[--verbose]
        ARP_FLAG[--arp-max-per-sec 5]
        FORMATS_FLAG[--formats json,html]
    end
    
    subgraph "Résultat Final"
        FINAL_CONFIG[Configuration Finale]
    end
    
    CLI_FLAGS --> INTERFACE_FLAG
    CLI_FLAGS --> VERBOSE_FLAG
    CLI_FLAGS --> ARP_FLAG
    CLI_FLAGS --> FORMATS_FLAG
    
    INTERFACE_FLAG --> FINAL_CONFIG
    VERBOSE_FLAG --> FINAL_CONFIG
    ARP_FLAG --> FINAL_CONFIG
    FORMATS_FLAG --> FINAL_CONFIG
    
    YAML_CONFIG --> FINAL_CONFIG
    DEFAULTS --> FINAL_CONFIG
```

## Validation de Configuration

```mermaid
flowchart TD
    subgraph "Validation Entrée"
        YAML_SYNTAX[Syntaxe YAML]
        REQUIRED_FIELDS[Champs Requis]
        TYPE_VALIDATION[Validation Types]
    end
    
    subgraph "Validation Logique"
        MODE_CONFLICTS[Conflits Modes]
        PORT_RANGES[Plages de Ports]
        IP_FORMATS[Formats IP]
        PATH_VALIDATION[Validation Chemins]
    end
    
    subgraph "Validation Système"
        PERMISSIONS[Permissions Fichiers]
        INTERFACE_EXISTS[Interface Existe]
        DISK_SPACE[Espace Disque]
    end
    
    subgraph "Résultat"
        VALID_CONFIG[Configuration Valide]
        ERROR_MESSAGES[Messages d'Erreur]
    end
    
    YAML_SYNTAX --> MODE_CONFLICTS
    REQUIRED_FIELDS --> PORT_RANGES
    TYPE_VALIDATION --> IP_FORMATS
    IP_FORMATS --> PATH_VALIDATION
    
    MODE_CONFLICTS --> PERMISSIONS
    PORT_RANGES --> INTERFACE_EXISTS
    PATH_VALIDATION --> DISK_SPACE
    
    PERMISSIONS --> VALID_CONFIG
    INTERFACE_EXISTS --> VALID_CONFIG
    DISK_SPACE --> VALID_CONFIG
    
    PERMISSIONS --> ERROR_MESSAGES
    INTERFACE_EXISTS --> ERROR_MESSAGES
    DISK_SPACE --> ERROR_MESSAGES
```

## Configuration par Environnement

```mermaid
graph TD
    subgraph "Environnements"
        DEVELOPMENT[Développement]
        TESTING[Test]
        PRODUCTION[Production]
    end
    
    subgraph "Configurations Spécifiques"
        DEV_CONFIG[config.dev.yaml]
        TEST_CONFIG[config.test.yaml]
        PROD_CONFIG[config.prod.yaml]
    end
    
    subgraph "Paramètres par Environnement"
        DEV_PARAMS[Verbose: true<br/>Metrics: true<br/>Stealth: false]
        TEST_PARAMS[Quiet: true<br/>Metrics: false<br/>Stealth: true]
        PROD_PARAMS[Paranoid: true<br/>Metrics: true<br/>Stealth: true]
    end
    
    DEVELOPMENT --> DEV_CONFIG
    TESTING --> TEST_CONFIG
    PRODUCTION --> PROD_CONFIG
    
    DEV_CONFIG --> DEV_PARAMS
    TEST_CONFIG --> TEST_PARAMS
    PROD_CONFIG --> PROD_PARAMS
```

## Gestion des Erreurs de Configuration

```mermaid
graph TD
    subgraph "Types d'Erreurs"
        YAML_ERROR[Erreur Syntaxe YAML]
        FILE_ERROR[Fichier Inaccessible]
        VALIDATION_ERROR[Erreur Validation]
        PERMISSION_ERROR[Erreur Permission]
    end
    
    subgraph "Gestion"
        ERROR_DETECTION[Détection Erreur]
        ERROR_LOGGING[Logging Erreur]
        ERROR_RECOVERY[Récupération]
        ERROR_REPORTING[Rapport Erreur]
    end
    
    subgraph "Actions"
        USE_DEFAULTS[Utiliser Défauts]
        PROMPT_USER[Demander Utilisateur]
        EXIT_ERROR[Sortir avec Erreur]
        RETRY[Réessayer]
    end
    
    YAML_ERROR --> ERROR_DETECTION
    FILE_ERROR --> ERROR_DETECTION
    VALIDATION_ERROR --> ERROR_DETECTION
    PERMISSION_ERROR --> ERROR_DETECTION
    
    ERROR_DETECTION --> ERROR_LOGGING
    ERROR_LOGGING --> ERROR_RECOVERY
    ERROR_RECOVERY --> ERROR_REPORTING
    
    ERROR_RECOVERY --> USE_DEFAULTS
    ERROR_RECOVERY --> PROMPT_USER
    ERROR_RECOVERY --> EXIT_ERROR
    ERROR_RECOVERY --> RETRY
```

## Configuration des Métriques

```mermaid
graph TD
    subgraph "Paramètres Métriques"
        ENABLE_METRICS[enable_metrics: false]
        SAMPLE_RATE[metrics_sample_rate: 0]
        PARALLEL_WORKERS[parallel_workers: 0]
    end
    
    subgraph "Types de Métriques"
        PACKET_METRICS[Métriques Paquets]
        PERFORMANCE_METRICS[Métriques Performance]
        MEMORY_METRICS[Métriques Mémoire]
        CPU_METRICS[Métriques CPU]
    end
    
    subgraph "Collecte"
        METRICS_COLLECTOR[Collecteur Métriques]
        METRICS_STORAGE[Stockage Métriques]
        METRICS_EXPORT[Export Métriques]
    end
    
    ENABLE_METRICS --> METRICS_COLLECTOR
    SAMPLE_RATE --> METRICS_COLLECTOR
    PARALLEL_WORKERS --> METRICS_COLLECTOR
    
    METRICS_COLLECTOR --> PACKET_METRICS
    METRICS_COLLECTOR --> PERFORMANCE_METRICS
    METRICS_COLLECTOR --> MEMORY_METRICS
    METRICS_COLLECTOR --> CPU_METRICS
    
    PACKET_METRICS --> METRICS_STORAGE
    PERFORMANCE_METRICS --> METRICS_STORAGE
    MEMORY_METRICS --> METRICS_STORAGE
    CPU_METRICS --> METRICS_STORAGE
    
    METRICS_STORAGE --> METRICS_EXPORT
```
