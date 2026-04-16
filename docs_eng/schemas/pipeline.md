# Zandoli Processing Pipeline Schemas

## Pipeline Overview

```mermaid
flowchart TD
    subgraph "1. Capture"
        PCAP[PCAP File]
        LIVE[Live Interface]
        BPF[BPF Filter]
        VLAN[VLAN Detection]
    end
    
    subgraph "2. Initial Parsing"
        ETHERNET[Ethernet Parsing]
        IP[IP Parsing]
        TCP[TCP/UDP Parsing]
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
    
    subgraph "4. Specialized Analysis"
        CDP_PARSE[CDP Parser]
        LLDP_PARSE[LLDP Parser]
        STP_PARSE[STP Parser]
        DHCP_PARSE[DHCP Parser]
        ARP_PARSE[ARP Parser]
        MDNS_PARSE[mDNS Parser]
        TCP_PARSE[TCP Parser]
    end
    
    subgraph "5. Aggregation"
        AGGREGATOR[Aggregator]
        CORRELATION[IP↔MAC Correlation]
        PRIORITY[Priority Management]
        CONFLICT[Conflict Resolution]
    end
    
    subgraph "6. Inference"
        ROLE_INFERENCE[Role Inference]
        L2_SIGNALS[L2 Signals]
        BEHAVIOR[Behavioral Signals]
        CONFIDENCE[Confidence Calculation]
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

## Detailed Data Flow

```mermaid
sequenceDiagram
    participant S as Sniffer
    participant D as Dispatcher
    participant P as Parsers
    participant A as Aggregator
    participant R as Role Inference
    participant E as Exporter
    
    S->>D: PacketEvent
    D->>P: Route by protocol
    P->>A: ParsedRecord
    A->>A: IP↔MAC correlation
    A->>A: Priority management
    A->>R: Enriched host
    R->>R: Analyze L2 signals
    R->>R: Analyze behavior
    R->>R: Calculate confidence
    R->>E: Final host
    E->>E: Generate reports
```

## Execution Modes

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
    
    note right of Passive : Listen only
    note right of Active : ARP/SYN scan
    note right of Combined : Passive then active
    note right of PCAP : Offline analysis
```

## Concurrency Management

```mermaid
graph TB
    subgraph "Goroutines"
        MAIN[Main Thread]
        CAPTURE[Capture Thread]
        ANALYSIS[Analysis Thread]
        EXPORT[Export Thread]
    end
    
    subgraph "Channels"
        PACKET_CHAN[Packet Channel]
        RESULT_CHAN[Result Channel]
        ERROR_CHAN[Error Channel]
        DONE_CHAN[Done Channel]
    end
    
    subgraph "Synchronization"
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

## Parsing Pipeline

```mermaid
flowchart LR
    subgraph "Ethernet Parsing"
        ETH_HEADER[Ethernet Header]
        ETH_TYPE[EtherType]
        VLAN_TAG[VLAN Tag 802.1Q]
    end
    
    subgraph "IP Parsing"
        IP_HEADER[IP Header]
        IP_VERSION[IPv4/IPv6 Version]
        IP_TTL[TTL/Hop Limit]
        IP_PROTO[Protocol]
    end
    
    subgraph "Transport Parsing"
        TCP_HEADER[TCP Header]
        UDP_HEADER[UDP Header]
        TCP_OPTIONS[TCP Options]
        PORTS[Source/Dest Ports]
    end
    
    subgraph "Application Parsing"
        PAYLOAD[Payload]
        PROTOCOL_ID[Protocol Identification]
        TLV_PARSING[TLV Parsing]
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

## Protocol Dispatch

```mermaid
graph TD
    subgraph "Routing Criteria"
        PORT[TCP/UDP Port]
        ETHERTYPE[EtherType]
        PROTOCOL[IP Protocol]
        PAYLOAD[Payload Content]
    end
    
    subgraph "L2 Protocols"
        CDP[CDP - Port 2000]
        LLDP[LLDP - EtherType 0x88CC]
        STP[STP - EtherType 0x42/0x26]
        EAPOL[EAPOL - EtherType 0x888E]
    end
    
    subgraph "L3+ Protocols"
        DHCP[DHCP - UDP 67/68]
        ARP[ARP - EtherType 0x0806]
        MDNS[mDNS - UDP 5353]
        TCP_SCAN[TCP - Configured ports]
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

## Aggregation and Correlation

```mermaid
flowchart TD
    subgraph "Inputs"
        PR1[ParsedRecord 1]
        PR2[ParsedRecord 2]
        PR3[ParsedRecord N]
    end
    
    subgraph "Correlation"
        IP_MATCH[IP Match]
        MAC_MATCH[MAC Match]
        VLAN_MATCH[VLAN Match]
    end
    
    subgraph "Conflict Management"
        PRIORITY_CHECK[Priority Check]
        CONFLICT_RESOLUTION[Conflict Resolution]
        DATA_MERGE[Data Merge]
    end
    
    subgraph "Output"
        HOST[Unified Host]
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

## Role Inference

```mermaid
flowchart TD
    subgraph "Input Signals"
        L2_SIGNALS[L2 Signals]
        BEHAVIOR_SIGNALS[Behavioral Signals]
        OUI_INFO[OUI Information]
    end
    
    subgraph "L2 Analysis"
        CDP_ANALYSIS[CDP Analysis]
        LLDP_ANALYSIS[LLDP Analysis]
        STP_ANALYSIS[STP Analysis]
        EAPOL_ANALYSIS[EAPOL Analysis]
    end
    
    subgraph "Behavior Analysis"
        CLIENT_PATTERNS[Client Patterns]
        SERVER_PATTERNS[Server Patterns]
        NETWORK_PATTERNS[Network Patterns]
    end
    
    subgraph "Classification"
        ROLE_ASSIGNMENT[Role Assignment]
        CONFIDENCE_CALC[Confidence Calculation]
        CONFLICT_DETECTION[Conflict Detection]
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

## Error Management

```mermaid
graph TD
    subgraph "Error Types"
        PARSE_ERROR[Parsing Error]
        NETWORK_ERROR[Network Error]
        CONFIG_ERROR[Configuration Error]
        IO_ERROR[I/O Error]
    end
    
    subgraph "Management"
        ERROR_CHANNEL[Error Channel]
        ERROR_LOGGING[Error Logging]
        ERROR_RECOVERY[Recovery]
        ERROR_REPORTING[Error Reporting]
    end
    
    subgraph "Impact"
        CONTINUE[Continue]
        RETRY[Retry]
        ABORT[Abort]
        FALLBACK[Degraded Mode]
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

## Metrics and Performance

```mermaid
graph TB
    subgraph "Capture Metrics"
        PACKETS_PER_SEC[Packets/second]
        BYTES_PER_SEC[Bytes/second]
        DROPPED_PACKETS[Dropped packets]
        BUFFER_USAGE[Buffer usage]
    end
    
    subgraph "Analysis Metrics"
        PARSE_TIME[Parsing time]
        CORRELATION_TIME[Correlation time]
        MEMORY_USAGE[Memory usage]
        CPU_USAGE[CPU usage]
    end
    
    subgraph "Export Metrics"
        EXPORT_TIME[Export time]
        FILE_SIZE[File size]
        COMPRESSION_RATIO[Compression ratio]
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
