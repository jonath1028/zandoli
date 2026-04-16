# Schémas du Pipeline de Traitement Zandoli

## Vue d'ensemble du Pipeline

```mermaid
flowchart TD
    subgraph "1. Capture"
        PCAP[Fichier PCAP]
        LIVE[Interface Live]
        BPF[Filtre BPF]
        VLAN[Detection VLAN]
    end
    
    subgraph "2. Parsing Initial"
        ETHERNET[Parsing Ethernet]
        IP[Parsing IP]
        TCP[Parsing TCP/UDP]
    end
    
    subgraph "3. Dispatch"
        DISPATCH[Dispatcher]
        CDP_ROUTE[Route CDP]
        LLDP_ROUTE[Route LLDP]
        STP_ROUTE[Route STP]
        DHCP_ROUTE[Route DHCP]
        ARP_ROUTE[Route ARP]
        MDNS_ROUTE[Route mDNS]
        TCP_ROUTE[Route TCP]
    end
    
    subgraph "4. Analyse Spécialisée"
        CDP_PARSE[Parseur CDP]
        LLDP_PARSE[Parseur LLDP]
        STP_PARSE[Parseur STP]
        DHCP_PARSE[Parseur DHCP]
        ARP_PARSE[Parseur ARP]
        MDNS_PARSE[Parseur mDNS]
        TCP_PARSE[Parseur TCP]
    end
    
    subgraph "5. Agrégation"
        AGGREGATOR[Aggregator]
        CORRELATION[Corrélation IP↔MAC]
        PRIORITY[Gestion Priorités]
        CONFLICT[Resolution Conflits]
    end
    
    subgraph "6. Inférence"
        ROLE_INFERENCE[Role Inference]
        L2_SIGNALS[Signaux L2]
        BEHAVIOR[Signaux Comportementaux]
        CONFIDENCE[Calcul Confiance]
    end
    
    subgraph "7. Export"
        JSON_EXPORT[JSON Export]
        HTML_EXPORT[HTML Export]
        CSV_EXPORT[CSV Export]
    end
    
    PCAP --> ETHERNET
    LIVE --> BPF
    BPF --> ETHERNET
    ETHERNET --> IP
    IP --> TCP
    TCP --> DISPATCH
    
    DISPATCH --> CDP_ROUTE
    DISPATCH --> LLDP_ROUTE
    DISPATCH --> STP_ROUTE
    DISPATCH --> DHCP_ROUTE
    DISPATCH --> ARP_ROUTE
    DISPATCH --> MDNS_ROUTE
    DISPATCH --> TCP_ROUTE
    
    CDP_ROUTE --> CDP_PARSE
    LLDP_ROUTE --> LLDP_PARSE
    STP_ROUTE --> STP_PARSE
    DHCP_ROUTE --> DHCP_PARSE
    ARP_ROUTE --> ARP_PARSE
    MDNS_ROUTE --> MDNS_PARSE
    TCP_ROUTE --> TCP_PARSE
    
    CDP_PARSE --> AGGREGATOR
    LLDP_PARSE --> AGGREGATOR
    STP_PARSE --> AGGREGATOR
    DHCP_PARSE --> AGGREGATOR
    ARP_PARSE --> AGGREGATOR
    MDNS_PARSE --> AGGREGATOR
    TCP_PARSE --> AGGREGATOR
    
    AGGREGATOR --> CORRELATION
    CORRELATION --> PRIORITY
    PRIORITY --> CONFLICT
    CONFLICT --> ROLE_INFERENCE
    
    ROLE_INFERENCE --> L2_SIGNALS
    ROLE_INFERENCE --> BEHAVIOR
    L2_SIGNALS --> CONFIDENCE
    BEHAVIOR --> CONFIDENCE
    
    CONFIDENCE --> JSON_EXPORT
    CONFIDENCE --> HTML_EXPORT
    CONFIDENCE --> CSV_EXPORT
```

## Flux de Données Détaillé

```mermaid
sequenceDiagram
    participant S as Sniffer
    participant D as Dispatcher
    participant P as Parseurs
    participant A as Aggregator
    participant R as Role Inference
    participant E as Exporter
    
    S->>D: PacketEvent
    D->>P: Routage par protocole
    P->>A: ParsedRecord
    A->>A: Corrélation IP↔MAC
    A->>A: Gestion priorités
    A->>R: Host enrichi
    R->>R: Analyse signaux L2
    R->>R: Analyse comportement
    R->>R: Calcul confiance
    R->>E: Host final
    E->>E: Génération rapports
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

## Gestion de la Concurrence

```mermaid
graph TB
    subgraph "Goroutines"
        MAIN[Main Thread]
        CAPTURE[Capture Thread]
        ANALYSIS[Analysis Thread]
        EXPORT[Export Thread]
    end
    
    subgraph "Canaux"
        PACKET_CHAN[Packet Channel]
        RESULT_CHAN[Result Channel]
        ERROR_CHAN[Error Channel]
        DONE_CHAN[Done Channel]
    end
    
    subgraph "Synchronisation"
        WG[WaitGroup]
        MUTEX[Mutex]
        CTX[Context]
    end
    
    MAIN --> CAPTURE
    CAPTURE --> PACKET_CHAN
    PACKET_CHAN --> ANALYSIS
    ANALYSIS --> RESULT_CHAN
    RESULT_CHAN --> EXPORT
    
    CAPTURE --> ERROR_CHAN
    ANALYSIS --> ERROR_CHAN
    ERROR_CHAN --> MAIN
    
    MAIN --> WG
    CAPTURE --> WG
    ANALYSIS --> WG
    EXPORT --> WG
    
    WG --> DONE_CHAN
    DONE_CHAN --> MAIN
```

## Pipeline de Parsing

```mermaid
flowchart LR
    subgraph "Parsing Ethernet"
        ETH_HEADER[En-tête Ethernet]
        ETH_TYPE[EtherType]
        VLAN_TAG[VLAN Tag 802.1Q]
    end
    
    subgraph "Parsing IP"
        IP_HEADER[En-tête IP]
        IP_VERSION[Version IPv4/IPv6]
        IP_TTL[TTL/Hop Limit]
        IP_PROTO[Protocole]
    end
    
    subgraph "Parsing Transport"
        TCP_HEADER[En-tête TCP]
        UDP_HEADER[En-tête UDP]
        TCP_OPTIONS[Options TCP]
        PORTS[Ports Source/Dest]
    end
    
    subgraph "Parsing Application"
        PAYLOAD[Payload]
        PROTOCOL_ID[Identification Protocole]
        TLV_PARSING[Parsing TLV]
    end
    
    ETH_HEADER --> ETH_TYPE
    ETH_TYPE --> VLAN_TAG
    VLAN_TAG --> IP_HEADER
    IP_HEADER --> IP_VERSION
    IP_VERSION --> IP_TTL
    IP_TTL --> IP_PROTO
    IP_PROTO --> TCP_HEADER
    IP_PROTO --> UDP_HEADER
    TCP_HEADER --> TCP_OPTIONS
    TCP_OPTIONS --> PORTS
    UDP_HEADER --> PORTS
    PORTS --> PAYLOAD
    PAYLOAD --> PROTOCOL_ID
    PROTOCOL_ID --> TLV_PARSING
```

## Dispatch des Protocoles

```mermaid
graph TD
    subgraph "Critères de Routage"
        PORT[Port TCP/UDP]
        ETHERTYPE[EtherType]
        PROTOCOL[Protocole IP]
        PAYLOAD[Contenu Payload]
    end
    
    subgraph "Protocoles L2"
        CDP[CDP - Port 2000]
        LLDP[LLDP - EtherType 0x88CC]
        STP[STP - EtherType 0x42/0x26]
        EAPOL[EAPOL - EtherType 0x888E]
    end
    
    subgraph "Protocoles L3+"
        DHCP[DHCp - UDP 67/68]
        ARP[ARP - EtherType 0x0806]
        MDNS[mDNS - UDP 5353]
        TCP_SCAN[TCP - Ports configurés]
    end
    
    PORT --> CDP
    PORT --> DHCP
    PORT --> MDNS
    PORT --> TCP_SCAN
    
    ETHERTYPE --> LLDP
    ETHERTYPE --> STP
    ETHERTYPE --> EAPOL
    ETHERTYPE --> ARP
    
    PROTOCOL --> TCP_SCAN
    
    PAYLOAD --> CDP
    PAYLOAD --> LLDP
    PAYLOAD --> STP
```

## Agrégation et Corrélation

```mermaid
flowchart TD
    subgraph "Entrées"
        PR1[ParsedRecord 1]
        PR2[ParsedRecord 2]
        PR3[ParsedRecord N]
    end
    
    subgraph "Corrélation"
        IP_MATCH[Correspondance IP]
        MAC_MATCH[Correspondance MAC]
        VLAN_MATCH[Correspondance VLAN]
    end
    
    subgraph "Gestion Conflits"
        PRIORITY_CHECK[Vérification Priorité]
        CONFLICT_RESOLUTION[Résolution Conflit]
        DATA_MERGE[Fusion Données]
    end
    
    subgraph "Sortie"
        HOST[Host Unifié]
    end
    
    PR1 --> IP_MATCH
    PR2 --> MAC_MATCH
    PR3 --> VLAN_MATCH
    
    IP_MATCH --> PRIORITY_CHECK
    MAC_MATCH --> PRIORITY_CHECK
    VLAN_MATCH --> PRIORITY_CHECK
    
    PRIORITY_CHECK --> CONFLICT_RESOLUTION
    CONFLICT_RESOLUTION --> DATA_MERGE
    DATA_MERGE --> HOST
```

## Inférence de Rôle

```mermaid
flowchart TD
    subgraph "Signaux d'Entrée"
        L2_SIGNALS[Signaux L2]
        BEHAVIOR_SIGNALS[Signaux Comportementaux]
        OUI_INFO[Information OUI]
    end
    
    subgraph "Analyse L2"
        CDP_ANALYSIS[Analyse CDP]
        LLDP_ANALYSIS[Analyse LLDP]
        STP_ANALYSIS[Analyse STP]
        EAPOL_ANALYSIS[Analyse EAPOL]
    end
    
    subgraph "Analyse Comportement"
        CLIENT_PATTERNS[Patterns Client]
        SERVER_PATTERNS[Patterns Serveur]
        NETWORK_PATTERNS[Patterns Réseau]
    end
    
    subgraph "Classification"
        ROLE_ASSIGNMENT[Assignation Rôle]
        CONFIDENCE_CALC[Calcul Confiance]
        CONFLICT_DETECTION[Détection Conflits]
    end
    
    L2_SIGNALS --> CDP_ANALYSIS
    L2_SIGNALS --> LLDP_ANALYSIS
    L2_SIGNALS --> STP_ANALYSIS
    L2_SIGNALS --> EAPOL_ANALYSIS
    
    BEHAVIOR_SIGNALS --> CLIENT_PATTERNS
    BEHAVIOR_SIGNALS --> SERVER_PATTERNS
    BEHAVIOR_SIGNALS --> NETWORK_PATTERNS
    
    CDP_ANALYSIS --> ROLE_ASSIGNMENT
    LLDP_ANALYSIS --> ROLE_ASSIGNMENT
    STP_ANALYSIS --> ROLE_ASSIGNMENT
    EAPOL_ANALYSIS --> ROLE_ASSIGNMENT
    
    CLIENT_PATTERNS --> ROLE_ASSIGNMENT
    SERVER_PATTERNS --> ROLE_ASSIGNMENT
    NETWORK_PATTERNS --> ROLE_ASSIGNMENT
    
    OUI_INFO --> ROLE_ASSIGNMENT
    
    ROLE_ASSIGNMENT --> CONFIDENCE_CALC
    CONFIDENCE_CALC --> CONFLICT_DETECTION
```

## Gestion des Erreurs

```mermaid
graph TD
    subgraph "Types d'Erreurs"
        PARSE_ERROR[Erreur Parsing]
        NETWORK_ERROR[Erreur Réseau]
        CONFIG_ERROR[Erreur Configuration]
        IO_ERROR[Erreur I/O]
    end
    
    subgraph "Gestion"
        ERROR_CHANNEL[Canal d'Erreurs]
        ERROR_LOGGING[Logging Erreurs]
        ERROR_RECOVERY[Récupération]
        ERROR_REPORTING[Rapport Erreurs]
    end
    
    subgraph "Impact"
        CONTINUE[Continuer]
        RETRY[Réessayer]
        ABORT[Abandonner]
        FALLBACK[Mode Dégradé]
    end
    
    PARSE_ERROR --> ERROR_CHANNEL
    NETWORK_ERROR --> ERROR_CHANNEL
    CONFIG_ERROR --> ERROR_CHANNEL
    IO_ERROR --> ERROR_CHANNEL
    
    ERROR_CHANNEL --> ERROR_LOGGING
    ERROR_LOGGING --> ERROR_RECOVERY
    ERROR_RECOVERY --> ERROR_REPORTING
    
    ERROR_RECOVERY --> CONTINUE
    ERROR_RECOVERY --> RETRY
    ERROR_RECOVERY --> ABORT
    ERROR_RECOVERY --> FALLBACK
```

## Métriques et Performance

```mermaid
graph TB
    subgraph "Métriques Capture"
        PACKETS_PER_SEC[Paquets/seconde]
        BYTES_PER_SEC[Octets/seconde]
        DROPPED_PACKETS[Paquets perdus]
        BUFFER_USAGE[Utilisation buffer]
    end
    
    subgraph "Métriques Analyse"
        PARSE_TIME[Temps parsing]
        CORRELATION_TIME[Temps corrélation]
        MEMORY_USAGE[Utilisation mémoire]
        CPU_USAGE[Utilisation CPU]
    end
    
    subgraph "Métriques Export"
        EXPORT_TIME[Temps export]
        FILE_SIZE[Taille fichiers]
        COMPRESSION_RATIO[Taux compression]
    end
    
    PACKETS_PER_SEC --> DASHBOARD[Dashboard]
    BYTES_PER_SEC --> DASHBOARD
    DROPPED_PACKETS --> DASHBOARD
    BUFFER_USAGE --> DASHBOARD
    
    PARSE_TIME --> DASHBOARD
    CORRELATION_TIME --> DASHBOARD
    MEMORY_USAGE --> DASHBOARD
    CPU_USAGE --> DASHBOARD
    
    EXPORT_TIME --> DASHBOARD
    FILE_SIZE --> DASHBOARD
    COMPRESSION_RATIO --> DASHBOARD
```
