# Zandoli Data Model Schemas

## Host Structure - Overview

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

## Entity Relationships

```mermaid
erDiagram
    Host ||--o{ IPObservation : "has many"
    Host ||--o{ Anomaly : "may have"
    Host ||--|| L2Signals : "has"
    Host ||--o| CDPInfo : "may have"
    Host ||--o| LLDPInfo : "may have"
    Host ||--o| STPInfo : "may have"
    Host ||--o| TCPOptions : "may have"
    
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

## Data Flow - PacketEvent to Host

```mermaid
flowchart TD
    subgraph "Capture"
        PE[PacketEvent]
    end
    
    subgraph "Parsing"
        PR[ParsedRecord]
    end
    
    subgraph "Aggregation"
        H[Host]
    end
    
    subgraph "Enrichment"
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

## Role Classification

```mermaid
graph TD
    subgraph "L2 Signals - Absolute Priority"
        CDP_SIG[CDP]
        LLDP_SIG[LLDP]
        STP_SIG[STP]
        EAPOL_SIG[EAPOL]
    end
    
    subgraph "Behavioral Signals"
        HTTP_CLIENT[HTTP Requests]
        DNS_CLIENT[DNS Queries]
        CONN_OUT[Outbound Connections]
        HTTP_SERVER[HTTP Responses]
        DNS_SERVER[DNS Responses]
        SERVICES[TCP/UDP Services]
    end
    
    subgraph "Classification"
        CLIENT[Client]
        SERVER[Server]
        NETWORK[Network/Infrastructure]
        UNKNOWN[Unknown]
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

## IP↔MAC Conflict Management

```mermaid
stateDiagram-v2
    [*] --> NewObservation
    
    NewObservation --> AlreadyExists : IP/MAC already seen
    NewObservation --> NewAssociation : First time
    
    AlreadyExists --> ConflictDetected : Different association
    AlreadyExists --> Reinforcement : Same association
    
    ConflictDetected --> PriorityEvaluation : Check priority
    PriorityEvaluation --> Replacement : Higher priority
    PriorityEvaluation --> Rejection : Lower priority
    
    NewAssociation --> Recording
    Reinforcement --> Recording
    Replacement --> Recording
    Rejection --> [*]
    Recording --> [*]
```

## Protocol Priority Matrix

```mermaid
graph TB
    subgraph "High Priority"
        CDP_PRIO[CDP - 100]
        LLDP_PRIO[LLDP - 90]
        STP_PRIO[STP - 80]
        EAPOL_PRIO[EAPOL - 70]
    end
    
    subgraph "Medium Priority"
        DHCP_PRIO[DHCP - 60]
        ARP_PRIO[ARP - 50]
        MDNS_PRIO[mDNS - 40]
    end
    
    subgraph "Low Priority"
        TCP_PRIO[TCP - 30]
        UDP_PRIO[UDP - 20]
        OTHER_PRIO[Others - 10]
    end
    
    CDP_PRIO --> CONFLICT_RESOLUTION
    LLDP_PRIO --> CONFLICT_RESOLUTION
    STP_PRIO --> CONFLICT_RESOLUTION
    EAPOL_PRIO --> CONFLICT_RESOLUTION
    DHCP_PRIO --> CONFLICT_RESOLUTION
    ARP_PRIO --> CONFLICT_RESOLUTION
    MDNS_PRIO --> CONFLICT_RESOLUTION
    TCP_PRIO --> CONFLICT_RESOLUTION
    UDP_PRIO --> CONFLICT_RESOLUTION
    OTHER_PRIO --> CONFLICT_RESOLUTION
    
    CONFLICT_RESOLUTION[Conflict Resolution]
```

## Anomaly Structure

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

## JSON Serialization

```mermaid
graph LR
    subgraph "Go Structures"
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

## VLAN Management

```mermaid
graph TD
    subgraph "VLAN Detection"
        PACKET[Packet with VLAN Tag]
        VLAN_ID[VLAN ID Extraction]
        VLAN_STATS[VLAN Statistics]
    end
    
    subgraph "Host Association"
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

## Metrics and Statistics

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
