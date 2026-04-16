# Schémas des Protocoles Supportés par Zandoli

## Vue d'ensemble des Protocoles

```mermaid
graph TB
    subgraph "Layer 2 Protocols"
        CDP[CDP<br/>Cisco Discovery Protocol]
        LLDP[LLDP<br/>Link Layer Discovery Protocol]
        STP[STP<br/>Spanning Tree Protocol]
        EAPOL[EAPOL<br/>EAP over LAN]
    end
    
    subgraph "Layer 3 Protocols"
        ARP[ARP<br/>Address Resolution Protocol]
        DHCP[DHCp<br/>Dynamic Host Configuration Protocol]
        ICMP[ICMP<br/>Internet Control Message Protocol]
    end
    
    subgraph "Application Protocols"
        MDNS[mDNS<br/>Multicast DNS]
        NBNS[NBNS<br/>NetBIOS Name Service]
        SSDP[SSDP<br/>Simple Service Discovery Protocol]
        SMB[SMB<br/>Server Message Block]
    end
    
    subgraph "Transport Protocols"
        TCP[TCP<br/>Transmission Control Protocol]
        UDP[UDP<br/>User Datagram Protocol]
    end
    
    CDP --> TCP
    LLDP --> UDP
    STP --> UDP
    EAPOL --> UDP
    ARP --> ETHERNET
    DHCP --> UDP
    ICMP --> IP
    MDNS --> UDP
    NBNS --> UDP
    SSDP --> UDP
    SMB --> TCP
```

## CDP (Cisco Discovery Protocol)

```mermaid
graph TD
    subgraph "Structure CDP"
        CDP_HEADER[En-tête CDP]
        CDP_TLV[TLV Fields]
    end
    
    subgraph "TLV Types"
        DEVICE_ID[Device ID - 0x01]
        PORT_ID[Port ID - 0x03]
        CAPABILITIES[Capabilities - 0x04]
        VERSION[Version - 0x05]
        PLATFORM[Platform - 0x06]
        NATIVE_VLAN[Native VLAN - 0x0A]
        MGMT_ADDR[Management Addresses - 0x10]
    end
    
    subgraph "Extraction"
        DEVICE_NAME[Nom Device]
        PORT_NAME[Nom Port]
        CAPS_DECODED[Capacités Décodées]
        SW_VERSION[Version Software]
        HARDWARE[Matériel]
        VLAN_ID[ID VLAN]
        IP_ADDRS[Adresses IP]
    end
    
    CDP_HEADER --> CDP_TLV
    CDP_TLV --> DEVICE_ID
    CDP_TLV --> PORT_ID
    CDP_TLV --> CAPABILITIES
    CDP_TLV --> VERSION
    CDP_TLV --> PLATFORM
    CDP_TLV --> NATIVE_VLAN
    CDP_TLV --> MGMT_ADDR
    
    DEVICE_ID --> DEVICE_NAME
    PORT_ID --> PORT_NAME
    CAPABILITIES --> CAPS_DECODED
    VERSION --> SW_VERSION
    PLATFORM --> HARDWARE
    NATIVE_VLAN --> VLAN_ID
    MGMT_ADDR --> IP_ADDRS
```

## LLDP (Link Layer Discovery Protocol)

```mermaid
graph TD
    subgraph "Structure LLDP"
        LLDP_HEADER[En-tête LLDP]
        LLDP_TLV[TLV Fields]
    end
    
    subgraph "TLV Types"
        CHASSIS_ID[Chassis ID - 0x01]
        PORT_ID[Port ID - 0x02]
        TTL[TTL - 0x03]
        PORT_DESC[Port Description - 0x04]
        SYS_NAME[System Name - 0x05]
        SYS_DESC[System Description - 0x06]
        SYS_CAPS[System Capabilities - 0x07]
        MGMT_ADDR[Management Address - 0x08]
    end
    
    subgraph "Extraction"
        CHASSIS_MAC[MAC Chassis]
        PORT_NAME[Nom Port]
        TTL_VALUE[Valeur TTL]
        PORT_INFO[Info Port]
        SYSTEM_NAME[Nom Système]
        SYSTEM_DESC[Description Système]
        CAPABILITIES[Capacités]
        MGMT_IP[IP Management]
    end
    
    LLDP_HEADER --> LLDP_TLV
    LLDP_TLV --> CHASSIS_ID
    LLDP_TLV --> PORT_ID
    LLDP_TLV --> TTL
    LLDP_TLV --> PORT_DESC
    LLDP_TLV --> SYS_NAME
    LLDP_TLV --> SYS_DESC
    LLDP_TLV --> SYS_CAPS
    LLDP_TLV --> MGMT_ADDR
    
    CHASSIS_ID --> CHASSIS_MAC
    PORT_ID --> PORT_NAME
    TTL --> TTL_VALUE
    PORT_DESC --> PORT_INFO
    SYS_NAME --> SYSTEM_NAME
    SYS_DESC --> SYSTEM_DESC
    SYS_CAPS --> CAPABILITIES
    MGMT_ADDR --> MGMT_IP
```

## STP (Spanning Tree Protocol)

```mermaid
graph TD
    subgraph "Structure STP"
        STP_HEADER[En-tête STP]
        STP_FIELDS[Champs STP]
    end
    
    subgraph "Champs STP"
        PROTOCOL_ID[Protocol ID - 0x0000]
        VERSION[Version - 0x00]
        BPDU_TYPE[BPDU Type - 0x00]
        FLAGS[Flags]
        ROOT_ID[Root Bridge ID]
        ROOT_PATH_COST[Root Path Cost]
        BRIDGE_ID[Bridge ID]
        PORT_ID[Port ID]
        MESSAGE_AGE[Message Age]
        MAX_AGE[Max Age]
        HELLO_TIME[Hello Time]
        FORWARD_DELAY[Forward Delay]
    end
    
    subgraph "Extraction"
        ROOT_BRIDGE[Pont Racine]
        BRIDGE_INFO[Info Pont]
        PORT_INFO[Info Port]
        TIMING[Paramètres Timing]
    end
    
    STP_HEADER --> STP_FIELDS
    STP_FIELDS --> PROTOCOL_ID
    STP_FIELDS --> VERSION
    STP_FIELDS --> BPDU_TYPE
    STP_FIELDS --> FLAGS
    STP_FIELDS --> ROOT_ID
    STP_FIELDS --> ROOT_PATH_COST
    STP_FIELDS --> BRIDGE_ID
    STP_FIELDS --> PORT_ID
    STP_FIELDS --> MESSAGE_AGE
    STP_FIELDS --> MAX_AGE
    STP_FIELDS --> HELLO_TIME
    STP_FIELDS --> FORWARD_DELAY
    
    ROOT_ID --> ROOT_BRIDGE
    BRIDGE_ID --> BRIDGE_INFO
    PORT_ID --> PORT_INFO
    MESSAGE_AGE --> TIMING
    MAX_AGE --> TIMING
    HELLO_TIME --> TIMING
    FORWARD_DELAY --> TIMING
```

## DHCP (Dynamic Host Configuration Protocol)

```mermaid
graph TD
    subgraph "Structure DHCP"
        DHCP_HEADER[En-tête DHCP]
        DHCP_OPTIONS[Options DHCP]
    end
    
    subgraph "Champs DHCP"
        OP[Opcode - 1=Request, 2=Reply]
        HTYPE[HType - Hardware Type]
        HLEN[HLen - Hardware Length]
        HOPS[Hops]
        XID[Transaction ID]
        SECS[Seconds]
        FLAGS[Flags]
        CIADDR[Client IP Address]
        YIADDR[Your IP Address]
        SIADDR[Server IP Address]
        GIADDR[Gateway IP Address]
        CHADDR[Client Hardware Address]
        SNAME[Server Name]
        FILE[Boot Filename]
        OPTIONS[Options]
    end
    
    subgraph "Options Importantes"
        OPT_53[Option 53 - Message Type]
        OPT_54[Option 54 - Server Identifier]
        OPT_61[Option 61 - Client Identifier]
        OPT_12[Option 12 - Host Name]
        OPT_60[Option 60 - Vendor Class]
    end
    
    subgraph "Extraction"
        MSG_TYPE[Type Message]
        CLIENT_MAC[MAC Client]
        CLIENT_IP[IP Client]
        SERVER_IP[IP Serveur]
        HOSTNAME[Nom Hôte]
        VENDOR_CLASS[Classe Vendor]
    end
    
    DHCP_HEADER --> DHCP_OPTIONS
    DHCP_OPTIONS --> OPT_53
    DHCP_OPTIONS --> OPT_54
    DHCP_OPTIONS --> OPT_61
    DHCP_OPTIONS --> OPT_12
    DHCP_OPTIONS --> OPT_60
    
    OPT_53 --> MSG_TYPE
    CHADDR --> CLIENT_MAC
    YIADDR --> CLIENT_IP
    SIADDR --> SERVER_IP
    OPT_12 --> HOSTNAME
    OPT_60 --> VENDOR_CLASS
```

## ARP (Address Resolution Protocol)

```mermaid
graph TD
    subgraph "Structure ARP"
        ARP_HEADER[En-tête ARP]
        ARP_FIELDS[Champs ARP]
    end
    
    subgraph "Champs ARP"
        HTYPE[Hardware Type - 0x0001 Ethernet]
        PTYPE[Protocol Type - 0x0800 IPv4]
        HLEN[Hardware Length - 6]
        PLEN[Protocol Length - 4]
        OPER[Operation - 1=Request, 2=Reply]
        SHA[Sender Hardware Address]
        SPA[Sender Protocol Address]
        THA[Target Hardware Address]
        TPA[Target Protocol Address]
    end
    
    subgraph "Extraction"
        SRC_MAC[MAC Source]
        SRC_IP[IP Source]
        DST_MAC[MAC Destination]
        DST_IP[IP Destination]
        OPERATION[Opération]
    end
    
    ARP_HEADER --> ARP_FIELDS
    ARP_FIELDS --> HTYPE
    ARP_FIELDS --> PTYPE
    ARP_FIELDS --> HLEN
    ARP_FIELDS --> PLEN
    ARP_FIELDS --> OPER
    ARP_FIELDS --> SHA
    ARP_FIELDS --> SPA
    ARP_FIELDS --> THA
    ARP_FIELDS --> TPA
    
    SHA --> SRC_MAC
    SPA --> SRC_IP
    THA --> DST_MAC
    TPA --> DST_IP
    OPER --> OPERATION
```

## mDNS (Multicast DNS)

```mermaid
graph TD
    subgraph "Structure mDNS"
        MDNS_HEADER[En-tête mDNS]
        MDNS_QUESTIONS[Questions]
        MDNS_ANSWERS[Réponses]
    end
    
    subgraph "Champs mDNS"
        TRANSACTION_ID[Transaction ID]
        FLAGS[Flags]
        QUESTIONS_COUNT[Questions Count]
        ANSWERS_COUNT[Answers Count]
        AUTHORITY_COUNT[Authority Count]
        ADDITIONAL_COUNT[Additional Count]
    end
    
    subgraph "Types d'Enregistrements"
        A_RECORD[A Record - IPv4]
        AAAA_RECORD[AAAA Record - IPv6]
        PTR_RECORD[PTR Record - Reverse]
        SRV_RECORD[SRV Record - Service]
        TXT_RECORD[TXT Record - Text]
    end
    
    subgraph "Extraction"
        HOSTNAME[Nom Hôte]
        IPV4_ADDR[Adresse IPv4]
        IPV6_ADDR[Adresse IPv6]
        SERVICE_INFO[Info Service]
        TEXT_INFO[Info Texte]
    end
    
    MDNS_HEADER --> MDNS_QUESTIONS
    MDNS_HEADER --> MDNS_ANSWERS
    MDNS_QUESTIONS --> A_RECORD
    MDNS_QUESTIONS --> AAAA_RECORD
    MDNS_ANSWERS --> PTR_RECORD
    MDNS_ANSWERS --> SRV_RECORD
    MDNS_ANSWERS --> TXT_RECORD
    
    A_RECORD --> HOSTNAME
    A_RECORD --> IPV4_ADDR
    AAAA_RECORD --> IPV6_ADDR
    SRV_RECORD --> SERVICE_INFO
    TXT_RECORD --> TEXT_INFO
```

## TCP Fingerprinting

```mermaid
graph TD
    subgraph "Structure TCP"
        TCP_HEADER[En-tête TCP]
        TCP_OPTIONS[Options TCP]
    end
    
    subgraph "Champs TCP"
        SRC_PORT[Port Source]
        DST_PORT[Port Destination]
        SEQ_NUM[Sequence Number]
        ACK_NUM[Acknowledgment Number]
        HEADER_LEN[Header Length]
        FLAGS[Flags]
        WINDOW_SIZE[Window Size]
        CHECKSUM[Checksum]
        URGENT_PTR[Urgent Pointer]
    end
    
    subgraph "Options TCP"
        MSS[Maximum Segment Size]
        WSCALE[Window Scale]
        SACK_PERM[SACK Permitted]
        TIMESTAMP[Timestamp]
        NOP[NOP]
        ORDER[Order of Options]
    end
    
    subgraph "Fingerprinting"
        OS_GUESS[OS Guess]
        OS_CONFIDENCE[OS Confidence]
        TCP_SIGNATURE[TCP Signature]
        OPTION_PATTERN[Option Pattern]
    end
    
    TCP_HEADER --> TCP_OPTIONS
    TCP_OPTIONS --> MSS
    TCP_OPTIONS --> WSCALE
    TCP_OPTIONS --> SACK_PERM
    TCP_OPTIONS --> TIMESTAMP
    TCP_OPTIONS --> NOP
    TCP_OPTIONS --> ORDER
    
    MSS --> OS_GUESS
    WSCALE --> OS_CONFIDENCE
    SACK_PERM --> TCP_SIGNATURE
    TIMESTAMP --> OPTION_PATTERN
    ORDER --> OPTION_PATTERN
    WINDOW_SIZE --> OS_GUESS
```

## Flux de Parsing par Protocole

```mermaid
flowchart TD
    subgraph "Entrée"
        PACKET[Paquet Réseau]
    end
    
    subgraph "Parsing Ethernet"
        ETH_PARSE[Parsing Ethernet]
        VLAN_CHECK[Vérification VLAN]
    end
    
    subgraph "Routage Protocole"
        PROTO_DETECT[Détection Protocole]
        CDP_ROUTE[Route CDP]
        LLDP_ROUTE[Route LLDP]
        STP_ROUTE[Route STP]
        DHCP_ROUTE[Route DHCP]
        ARP_ROUTE[Route ARP]
        MDNS_ROUTE[Route mDNS]
        TCP_ROUTE[Route TCP]
    end
    
    subgraph "Parsing Spécialisé"
        CDP_PARSE[Parse CDP]
        LLDP_PARSE[Parse LLDP]
        STP_PARSE[Parse STP]
        DHCP_PARSE[Parse DHCP]
        ARP_PARSE[Parse ARP]
        MDNS_PARSE[Parse mDNS]
        TCP_PARSE[Parse TCP]
    end
    
    subgraph "Sortie"
        PARSED_RECORD[ParsedRecord]
    end
    
    PACKET --> ETH_PARSE
    ETH_PARSE --> VLAN_CHECK
    VLAN_CHECK --> PROTO_DETECT
    
    PROTO_DETECT --> CDP_ROUTE
    PROTO_DETECT --> LLDP_ROUTE
    PROTO_DETECT --> STP_ROUTE
    PROTO_DETECT --> DHCP_ROUTE
    PROTO_DETECT --> ARP_ROUTE
    PROTO_DETECT --> MDNS_ROUTE
    PROTO_DETECT --> TCP_ROUTE
    
    CDP_ROUTE --> CDP_PARSE
    LLDP_ROUTE --> LLDP_PARSE
    STP_ROUTE --> STP_PARSE
    DHCP_ROUTE --> DHCP_PARSE
    ARP_ROUTE --> ARP_PARSE
    MDNS_ROUTE --> MDNS_PARSE
    TCP_ROUTE --> TCP_PARSE
    
    CDP_PARSE --> PARSED_RECORD
    LLDP_PARSE --> PARSED_RECORD
    STP_PARSE --> PARSED_RECORD
    DHCP_PARSE --> PARSED_RECORD
    ARP_PARSE --> PARSED_RECORD
    MDNS_PARSE --> PARSED_RECORD
    TCP_PARSE --> PARSED_RECORD
```

## Priorités des Protocoles

```mermaid
graph TB
    subgraph "Priorité Haute - Signaux L2"
        CDP_PRIO[CDP - Priorité 100]
        LLDP_PRIO[LLDP - Priorité 90]
        STP_PRIO[STP - Priorité 80]
        EAPOL_PRIO[EAPOL - Priorité 70]
    end
    
    subgraph "Priorité Moyenne - Protocoles Réseau"
        DHCP_PRIO[DHCp - Priorité 60]
        ARP_PRIO[ARP - Priorité 50]
        MDNS_PRIO[mDNS - Priorité 40]
    end
    
    subgraph "Priorité Basse - Transport"
        TCP_PRIO[TCP - Priorité 30]
        UDP_PRIO[UDP - Priorité 20]
        OTHER_PRIO[Autres - Priorité 10]
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
    
    CONFLICT_RESOLUTION[Resolution des Conflits IP↔MAC]
```

## Détection des Anomalies par Protocole

```mermaid
graph TD
    subgraph "Anomalies DHCP"
        MULTIPLE_DHCP[Multiple DHCP Servers]
        SUSPICIOUS_DHCP[Suspicious DHCP Behavior]
    end
    
    subgraph "Anomalies ARP"
        ARP_SPOOFING[ARP Spoofing Attempts]
        ARP_STORM[ARP Storm Detection]
    end
    
    subgraph "Anomalies TCP"
        SUSPICIOUS_TTL[Suspicious TTL Values]
        UNUSUAL_PORTS[Unusual Port Combinations]
    end
    
    subgraph "Anomalies MAC"
        BROADCAST_MAC[Broadcast MAC Address]
        MULTICAST_MAC[Multicast MAC Address]
        LOCAL_MAC[Locally Administered MAC]
    end
    
    MULTIPLE_DHCP --> ANOMALY_DETECTION
    SUSPICIOUS_DHCP --> ANOMALY_DETECTION
    ARP_SPOOFING --> ANOMALY_DETECTION
    ARP_STORM --> ANOMALY_DETECTION
    SUSPICIOUS_TTL --> ANOMALY_DETECTION
    UNUSUAL_PORTS --> ANOMALY_DETECTION
    BROADCAST_MAC --> ANOMALY_DETECTION
    MULTICAST_MAC --> ANOMALY_DETECTION
    LOCAL_MAC --> ANOMALY_DETECTION
    
    ANOMALY_DETECTION[Détection d'Anomalies]
```
