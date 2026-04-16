# Zandoli Export Format Schemas

## Export Overview

```mermaid
graph TB
    subgraph "Source Data"
        HOSTS[Discovered Hosts]
        SUBNETS[Subnets]
        ANOMALIES[Anomalies]
        STATS[Statistics]
    end
    
    subgraph "Export Formats"
        JSON[JSON Export]
        HTML[HTML Export]
        CSV[CSV Export]
        XML[XML Export]
        MARKDOWN[Markdown Export]
        IPSET[IPSet Export]
    end
    
    subgraph "Generated Files"
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

## JSON Structure

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

## HTML Structure

```mermaid
graph TD
    subgraph "HTML Template"
        HEADER[HTML Header]
        NAVIGATION[Navigation]
        CONTENT[Main Content]
        FOOTER[Footer]
    end
    
    subgraph "Main Sections"
        SUMMARY[Global Summary]
        HOSTS_TABLE[Hosts Table]
        SUBNETS_TABLE[Subnets Table]
        ANOMALIES_TABLE[Anomalies Table]
        STATS[Statistics]
    end
    
    subgraph "Interactive Features"
        FILTERS[Filters]
        SEARCH[Search]
        SORT[Sorting]
        EXPAND[Expandable Details]
    end
    
    subgraph "Styles and Scripts"
        CSS[Style Sheets]
        JS[JavaScript]
        CHARTS[Charts]
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

## CSV Structure

```mermaid
graph TD
    subgraph "CSV Columns"
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
    
    subgraph "Formatting"
        DELIMITER[Delimiter ;]
        QUOTES[Quotes]
        ESCAPING[Escaping]
        ENCODING[UTF-8 Encoding]
    end
    
    subgraph "CSV Files"
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

## Export Generation Flow

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
    
    O->>E: Export request
    E->>J: JSON export
    E->>H: HTML export
    E->>C: CSV export
    E->>X: XML export
    E->>M: Markdown export
    E->>I: IPSet export
    
    J->>J: JSON serialization
    H->>H: HTML generation
    C->>C: CSV formatting
    X->>X: XML generation
    M->>M: Markdown generation
    I->>I: IPSet generation
    
    J->>E: JSON files
    H->>E: HTML file
    C->>E: CSV files
    X->>E: XML file
    M->>E: Markdown file
    I->>E: IPSet file
    
    E->>O: Export confirmation
```

## IP Selection for Export

```mermaid
flowchart TD
    subgraph "Input"
        HOST_IPS[All Host IPs]
    end
    
    subgraph "Filtering"
        EXCLUDE_CHECK[Exclusion Check]
        IPV4_FILTER[IPv4 Filter]
        IPV6_FILTER[IPv6 Filter]
    end
    
    subgraph "IPv4 Prioritization"
        RFC1918_CHECK[RFC1918 Check]
        APIPA_CHECK[APIPA Check]
        PUBLIC_CHECK[Public Check]
    end
    
    subgraph "IPv6 Prioritization"
        GLOBAL_CHECK[Global Check]
        ULA_CHECK[ULA Check]
    end
    
    subgraph "Output"
        PRIMARY_IPV4[Primary IPv4]
        PRIMARY_IPV6[Primary IPv6]
        OTHER_IPV4[Other IPv4]
        OTHER_IPV6[Other IPv6]
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

## HTML Template - Detailed Structure

```mermaid
graph TD
    subgraph "HTML Header"
        DOCTYPE[DOCTYPE html]
        HTML_TAG[html lang="en"]
        HEAD[head]
        META[Meta tags]
        TITLE[Title]
        CSS_LINKS[CSS Links]
    end
    
    subgraph "Main Body"
        BODY[body]
        HEADER[header]
        NAV[nav]
        MAIN[main]
        FOOTER[footer]
    end
    
    subgraph "Main Content"
        SUMMARY_SECTION[Summary Section]
        HOSTS_SECTION[Hosts Section]
        SUBNETS_SECTION[Subnets Section]
        ANOMALIES_SECTION[Anomalies Section]
        STATS_SECTION[Statistics Section]
    end
    
    subgraph "Interactive Components"
        FILTER_PANEL[Filter Panel]
        SEARCH_BOX[Search Box]
        SORT_CONTROLS[Sort Controls]
        DETAIL_MODAL[Detail Modal]
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

## Export Error Handling

```mermaid
graph TD
    subgraph "Error Types"
        FILE_ERROR[File Error]
        PERMISSION_ERROR[Permission Error]
        DISK_ERROR[Disk Error]
        ENCODING_ERROR[Encoding Error]
    end
    
    subgraph "Management"
        ERROR_DETECTION[Error Detection]
        ERROR_LOGGING[Error Logging]
        ERROR_RECOVERY[Recovery]
        ERROR_REPORTING[Error Reporting]
    end
    
    subgraph "Actions"
        RETRY[Retry]
        SKIP[Skip]
        ABORT[Abort]
        FALLBACK[Degraded Mode]
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

## Export Metrics

```mermaid
graph TB
    subgraph "Time Metrics"
        EXPORT_TIME[Total Export Time]
        JSON_TIME[JSON Export Time]
        HTML_TIME[HTML Export Time]
        CSV_TIME[CSV Export Time]
    end
    
    subgraph "Size Metrics"
        JSON_SIZE[JSON Files Size]
        HTML_SIZE[HTML File Size]
        CSV_SIZE[CSV Files Size]
        TOTAL_SIZE[Total Size]
    end
    
    subgraph "Performance Metrics"
        HOSTS_COUNT[Exported Hosts Count]
        SUBNETS_COUNT[Subnets Count]
        ANOMALIES_COUNT[Anomalies Count]
        SUCCESS_RATE[Success Rate]
    end
    
    EXPORT_TIME --> DASHBOARD[Metrics Dashboard]
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

## Export Configuration

```mermaid
graph TD
    subgraph "YAML Configuration"
        OUTPUT_CONFIG[output:]
        BASE_DIR[base_dir]
        FORMATS[formats]
        RECORD_PCAP[record_pcap]
        OUI_FILE[oui_file]
        ALLOW_PUBLIC[allow_public_subnets]
    end
    
    subgraph "Available Formats"
        JSON_FORMAT[json]
        HTML_FORMAT[html]
        CSV_FORMAT[csv]
        XML_FORMAT[xml]
        MARKDOWN_FORMAT[markdown]
        IPSET_FORMAT[ipset]
    end
    
    subgraph "Validation"
        FORMAT_VALIDATION[Format Validation]
        PATH_VALIDATION[Path Validation]
        PERMISSION_CHECK[Permission Check]
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
