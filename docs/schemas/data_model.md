# Schémas du Modèle de Données Zandoli

## Structure Host - Vue d'ensemble

```mermaid
classDiagram
    class Host {
        +net.IP IP
        +net.IP IPv6Primary
        +[]net.IP IPs
        +net.HardwareAddr MAC
        +string MACStr
        +string Vendor
        +string Role
        +int RoleConfidence
        +[]string RoleSignals
        +bool RoleConflict
        +string Category
        +[]string Protocols
        +string Info
        +string Hostname
        +string Source
        +bool OnlyARP
        +int TTL
        +uint8 TTLAvg
        +string OSGuess
        +uint8 OSScore
        +[]string OSSignals
        +int WindowSize
        +[]string TCPOpts
        +TCPOptions TCPOptions
        +[]int Ports
        +[]int VLANs
        +map[int]int VLANStats
        +int PrimaryVLAN
        +uint64 PacketCount
        +uint64 ByteCount
        +[]string SecurityFeatures
        +[]IPObservation IPsAll
        +map[string][]string ProtocolsByIP
        +L2Signals L2Signals
        +CDPInfo CDP
        +LLDPInfo LLDP
        +STPInfo STP
        +[]Anomaly Anomalies
        +time.Time FirstSeen
        +time.Time LastSeen
    }
```

## Relations entre Entités

```mermaid
erDiagram
    Host ||--o{ IPObservation : "a plusieurs"
    Host ||--o{ Anomaly : "peut avoir"
    Host ||--|| L2Signals : "possède"
    Host ||--o| CDPInfo : "peut avoir"
    Host ||--o| LLDPInfo : "peut avoir"
    Host ||--o| STPInfo : "peut avoir"
    Host ||--o| TCPOptions : "peut avoir"
    
    IPObservation {
        string IP
        string Source
        int Strength
        time.Time FirstSeen
        time.Time LastSeen
    }
    
    Anomaly {
        string Type
        string Description
        string Severity
        string Key
        string Scope
        map[string]interface{} Details
    }
    
    L2Signals {
        bool EAPOL
        bool STP
        bool LLDP
        bool CDP
        []int VLANs
    }
    
    CDPInfo {
        string DeviceID
        string PortID
        string Platform
        string Version
        uint32 Capabilities
        int NativeVLAN
        []string Addresses
        []string DecodedCaps
    }
    
    LLDPInfo {
        string ChassisID
        string PortID
        string SysName
        string SysDescr
        []string MgmtAddrs
        []string Capabilities
    }
    
    STPInfo {
        string RootBridgeID
        string BridgeID
        int RootPathCost
        string PortID
        int MessageAge
        int MaxAge
        int HelloTime
        int ForwardDelay
    }
    
    TCPOptions {
        int MSS
        int WSCALE
        bool SACKPermitted
        bool Timestamp
        int NOPCount
        []string Order
        []int MSSSamples
        []int WScaleSamples
        int TCPFPConfidence
    }
```

## Flux de Données - PacketEvent vers Host

```mermaid
flowchart TD
    subgraph "Capture"
        PE[PacketEvent]
    end
    
    subgraph "Parsing"
        PR[ParsedRecord]
    end
    
    subgraph "Agrégation"
        H[Host]
    end
    
    subgraph "Enrichissement"
        L2[L2Signals]
        CDP[CDPInfo]
        LLDP[LLDPInfo]
        STP[STPInfo]
        TCP[TCPOptions]
        ANOM[Anomalies]
    end
    
    PE --> PR
    PR --> H
    H --> L2
    H --> CDP
    H --> LLDP
    H --> STP
    H --> TCP
    H --> ANOM
    
    style PE fill:#e1f5fe
    style PR fill:#f3e5f5
    style H fill:#e8f5e8
    style L2 fill:#fff3e0
    style CDP fill:#fff3e0
    style LLDP fill:#fff3e0
    style STP fill:#fff3e0
    style TCP fill:#fff3e0
    style ANOM fill:#ffebee
```

## Classification des Rôles

```mermaid
graph TD
    subgraph "Signaux L2 - Priorité Absolue"
        CDP_SIG[CDP]
        LLDP_SIG[LLDP]
        STP_SIG[STP]
        EAPOL_SIG[EAPOL]
    end
    
    subgraph "Signaux Comportementaux"
        HTTP_CLIENT[Requêtes HTTP]
        DNS_CLIENT[DNS Queries]
        CONN_OUT[Connexions Sortantes]
        HTTP_SERVER[Réponses HTTP]
        DNS_SERVER[DNS Responses]
        SERVICES[Services TCP/UDP]
    end
    
    subgraph "Classification"
        CLIENT[Client]
        SERVER[Serveur]
        NETWORK[Réseau/Infrastructure]
        UNKNOWN[Inconnu]
    end
    
    CDP_SIG --> NETWORK
    LLDP_SIG --> NETWORK
    STP_SIG --> NETWORK
    EAPOL_SIG --> NETWORK
    
    HTTP_CLIENT --> CLIENT
    DNS_CLIENT --> CLIENT
    CONN_OUT --> CLIENT
    
    HTTP_SERVER --> SERVER
    DNS_SERVER --> SERVER
    SERVICES --> SERVER
    
    CLIENT --> UNKNOWN
    SERVER --> UNKNOWN
    NETWORK --> UNKNOWN
```

## Gestion des Conflits IP↔MAC

```mermaid
stateDiagram-v2
    [*] --> NouvelleObservation
    
    NouvelleObservation --> ExisteDeja : IP/MAC déjà vu
    NouvelleObservation --> NouvelleAssociation : Première fois
    
    ExisteDeja --> ConflitDetecte : Association différente
    ExisteDeja --> Renforcement : Même association
    
    ConflitDetecte --> EvaluationPriorite : Vérifier priorité
    EvaluationPriorite --> Remplacement : Priorité plus forte
    EvaluationPriorite --> Rejet : Priorité plus faible
    
    NouvelleAssociation --> Enregistrement
    Renforcement --> Enregistrement
    Remplacement --> Enregistrement
    Rejet --> [*]
    Enregistrement --> [*]
```

## Matrice de Priorité des Protocoles

```mermaid
graph TB
    subgraph "Priorité Haute"
        CDP_PRIO[CDP - 100]
        LLDP_PRIO[LLDP - 90]
        STP_PRIO[STP - 80]
        EAPOL_PRIO[EAPOL - 70]
    end
    
    subgraph "Priorité Moyenne"
        DHCP_PRIO[DHCP - 60]
        ARP_PRIO[ARP - 50]
        MDNS_PRIO[mDNS - 40]
    end
    
    subgraph "Priorité Basse"
        TCP_PRIO[TCP - 30]
        UDP_PRIO[UDP - 20]
        OTHER_PRIO[Autres - 10]
    end
    
    CDP_PRIO --> CONFLIT_RESOLUTION
    LLDP_PRIO --> CONFLIT_RESOLUTION
    STP_PRIO --> CONFLIT_RESOLUTION
    EAPOL_PRIO --> CONFLIT_RESOLUTION
    DHCP_PRIO --> CONFLIT_RESOLUTION
    ARP_PRIO --> CONFLIT_RESOLUTION
    MDNS_PRIO --> CONFLIT_RESOLUTION
    TCP_PRIO --> CONFLIT_RESOLUTION
    UDP_PRIO --> CONFLIT_RESOLUTION
    OTHER_PRIO --> CONFLIT_RESOLUTION
    
    CONFLIT_RESOLUTION[Resolution des Conflits]
```

## Structure des Anomalies

```mermaid
classDiagram
    class Anomaly {
        +string Type
        +string Description
        +string Severity
        +string Key
        +string Scope
        +map[string]interface{} Details
    }
    
    class AnomalyTypes {
        <<enumeration>>
        MultipleDHCPServers
        SuspiciousTTL
        UnusualPorts
        MACAnomalies
    }
    
    class AnomalySeverity {
        <<enumeration>>
        High
        Medium
        Low
    }
    
    Anomaly --> AnomalyTypes
    Anomaly --> AnomalySeverity
```

## Sérialisation JSON

```mermaid
graph LR
    subgraph "Structures Go"
        HOST_GO[Host]
        L2_GO[L2Signals]
        CDP_GO[CDPInfo]
        LLDP_GO[LLDPInfo]
        STP_GO[STPInfo]
        TCP_GO[TCPOptions]
        ANOM_GO[Anomaly]
    end
    
    subgraph "JSON Export"
        HOST_JSON[JSONHost]
        L2_JSON[L2Signals]
        CDP_JSON[CDPInfo]
        LLDP_JSON[LLDPInfo]
        STP_JSON[STPInfo]
        TCP_JSON[TCPOptions]
        ANOM_JSON[Anomaly]
    end
    
    HOST_GO --> HOST_JSON
    L2_GO --> L2_JSON
    CDP_GO --> CDP_JSON
    LLDP_GO --> LLDP_JSON
    STP_GO --> STP_JSON
    TCP_GO --> TCP_JSON
    ANOM_GO --> ANOM_JSON
    
    style HOST_GO fill:#e8f5e8
    style HOST_JSON fill:#e1f5fe
```

## Gestion des VLANs

```mermaid
graph TD
    subgraph "Détection VLAN"
        PACKET[Paquet avec VLAN Tag]
        VLAN_ID[VLAN ID Extraction]
        VLAN_STATS[VLAN Statistics]
    end
    
    subgraph "Association Host"
        HOST_VLANS[Host.VLANs]
        PRIMARY_VLAN[PrimaryVLAN]
        VLAN_COUNT[VLANStats]
    end
    
    PACKET --> VLAN_ID
    VLAN_ID --> VLAN_STATS
    VLAN_STATS --> HOST_VLANS
    HOST_VLANS --> PRIMARY_VLAN
    HOST_VLANS --> VLAN_COUNT
```

## Métriques et Statistiques

```mermaid
classDiagram
    class HostMetrics {
        +uint64 PacketCount
        +uint64 ByteCount
        +time.Time FirstSeen
        +time.Time LastSeen
        +uint8 TTLAvg
        +int WindowSize
    }
    
    class VLANStats {
        +map[int]int VLANStats
        +int PrimaryVLAN
    }
    
    class ProtocolStats {
        +[]string Protocols
        +map[string][]string ProtocolsByIP
    }
    
    HostMetrics --> VLANStats
    HostMetrics --> ProtocolStats
```
