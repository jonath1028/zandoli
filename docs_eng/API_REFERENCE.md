# Zandoli API Reference

> Documentation automatically generated from source code

## Overview

Zandoli is a passive/active network analyzer that combines traffic listening and active scanning to discover and map network devices. It analyzes PCAP files or listens in real-time, extracts Layer 2 and Layer 3 information, then generates detailed reports.

## Package Architecture

### `cmd/zandoli`

**Main entry point**: `cmd/zandoli/main.go`

**Exported functions**:
- `main()`: Application entry point
- `RunZandoli(cfg *config.Config, outputDir string) error`: Executes complete scan pipeline

**Available CLI flags**:

#### Execution modes
- `--passive`: Passive mode only (listening)
- `--active`: Active mode only (ARP, SYN)
- `--combined`: Combined mode (passive then active)
- `--pcap <file>`: Offline PCAP file analysis
- `--SYN`: Enable SYN scan on unidentified hosts

#### Network configuration
- `--interface <iface>`: Network interface (default: config.yaml)
- `--passive-duration <s>`: Passive listening duration in seconds
- `--ttl <n>`: TTL for active packets
- `--blacklist <ips>`: IPs/subnets to exclude (comma-separated)

#### Active scanning
- `--arp-max-per-sec <n>`: Max ARP requests per second
- `--arp-burst <n>`: Max ARP requests per burst
- `--burst-min-delay <ms>`: Min delay between bursts (ms)
- `--burst-max-delay <ms>`: Max delay between bursts (ms)
- `--syn-timeout <ms>`: Timeout per SYN packet (ms)
- `--syn-ports <p1,p2>`: TCP ports for SYN scan (comma-separated)

#### Output formats
- `--formats <f1,f2>`: Export formats (json, csv, html, markdown, xml)
- `--output-dir <dir>`: Output directory
- `--oui-file <file>`: OUI.txt file for vendor lookup
- `--record-pcap`: Record live sniffing into PCAP file

#### Logging
- `--verbose`: Detailed logs
- `--quiet`: Reduced logs
- `--paranoid`: No stdout logs
- `--summary`: Display summary at end

#### Other
- `--config <file>`: YAML config file (default: config.yaml)
- `--help`: Display help message
- `--demo`: Progress bar demo (no scan)

---

### `internal/config`

**Package**: `internal/config`

**Exported structures**:

```go
type Config struct {
    Interface string
    Logging   Logging
    Scan      ScanSettings
    Mode      Mode
    Output    OutputPaths
    CLI       CLIFlags
}

type Logging struct {
    Verbose  bool
    Quiet    bool
    Paranoid bool
}

type ScanSettings struct {
    TTL                    int
    ARPMaxPerSec           int
    ARPBurst               int
    BurstMinDelayMs        int
    BurstMaxDelayMs        int
    SYNTimeoutMs           int
    SYNPorts               []int
    Blacklist              []string
    PassiveDurationSeconds int
    Targeted               bool
    EnableMetrics          bool
    MetricsSampleRate      int
    ParallelWorkers        int
    // Stealth Hybrid Regulation parameters
    StealthMaxPerSecondMin       int
    StealthMaxPerSecondMax       int
    StealthMaxBurstPerWindowMin  int
    StealthMaxBurstPerWindowMax  int
    StealthBurstWindowSecondsMin int
    StealthBurstWindowSecondsMax int
    StealthMicroburstMin         int
    StealthMicroburstMax         int
    StealthPauseMinMs            int
    StealthPauseMaxMs            int
    SYNMicroburstMin             int
    SYNMicroburstMax             int
    SYNPauseMinMs                int
    SYNPauseMaxMs                int
    SYNJitterMinMs               int
    SYNJitterMaxMs               int
}

type Mode struct {
    Passive  bool
    Active   bool
    Combined bool
    PcapFile string
    SYN      bool
}

type OutputPaths struct {
    BaseDir            string
    RecordPCAP         bool
    Formats            []string
    OUIFile            string
    AllowPublicSubnets bool
}
```

**Exported functions**:
- `Load(path string) (*Config, error)`: Loads YAML configuration
- `(m Mode) ActiveLike() bool`: Returns true for Active or Combined modes

**Default values**:
- Interface: `eth0`
- TTL: `64`
- ARPMaxPerSec: `3`
- ARPBurst: `10`
- BaseDir: `output`

---

### `internal/logger`

**Package**: `internal/logger`

**Exported structures**:
```go
type Logger struct {
    zerolog.Logger
}
```

**Exported functions**:
- `New(folder string, cfg *config.Config) (*Logger, error)`: Creates new logger

**Behavior**:
- Test mode (`folder == "" || folder == "test"`): stdout only
- Paranoid mode: files only, never stdout
- Verbose mode: console + files
- Default/quiet mode: files only

**Log levels**:
- Quiet: `WarnLevel`
- Verbose: `DebugLevel`
- Default: `InfoLevel`

---

### `internal/validation`

**Package**: `internal/validation`

**Exported functions**:
- `ValidateFlags(interfaceName string, synPorts []int, blacklist []string, passiveDuration int) []error`
- `ValidatePorts(portsStr string) ([]int, error)`
- `ValidateFormats(formats []string) error`

**Supported formats**: `json`, `csv`, `html`, `markdown`, `xml`

**Validations applied**:
- Network interface: system existence
- SYN ports: 1-65535
- IP/CIDR blacklist: valid format
- Passive duration: positive value

---

### `internal/oui`

**Package**: `internal/oui`

**Exported structures**:
```go
type Map struct {
    ByPref map[string]string
    Source string // "embedded" or file path
}
```

**Exported functions**:
- `New() *Map`: Creates new OUI map
- `(m *Map) Load(path string) error`: Loads external OUI file
- `(m *Map) LoadEmbedded() error`: Loads embedded OUI data
- `(m *Map) VendorFromMAC(mac string) string`: Returns MAC vendor

**Accepted format**: `AA:BB:CC<TAB/SPACE>Vendor Name`

---

### `pkg/model`

**Package**: `pkg/model`

**Main structures**:

```go
type Host struct {
    IP               net.IP
    IPv6Primary      net.IP
    IPs              []net.IP
    MAC              net.HardwareAddr
    MACStr           string
    Vendor           string
    Role             string
    RoleConfidence   int
    RoleSignals      []string
    RoleConflict     bool
    Protocols        []string
    Info             string
    TTL              int
    OSGuess          string
    OSScore          uint8
    OSSignals        []string
    WindowSize       int
    TCPOptions       *TCPOptions
    FirstSeen        time.Time
    LastSeen         time.Time
    Anomalies        []Anomaly
    Ports            []int
    Source           string
    OnlyARP          bool
    TTLAvg           uint8
    Category         string
    Hostname         string
    VLANs            []int
    VLANStats        map[int]int
    PrimaryVLAN      int
    PacketCount      uint64
    ByteCount        uint64
    SecurityFeatures []string
    CDP              *CDPInfo
    LLDP             *LLDPInfo
    STP              *STPInfo
    RoleInfo         *RoleInfo
    IPsAll           []IPObservation
    ProtocolsByIP    map[string][]string
    L2Signals        L2SignalsInfo
    Services         ServicesInfo
}

type TCPOptions struct {
    MSS             int
    WSCALE          int
    SACKPermitted   bool
    Timestamp       bool
    NOPCount        int
    Order           []string
    MSSSamples      []int
    WScaleSamples   []int
    TCPFPConfidence int
}

type CDPInfo struct {
    DeviceID            string
    PortID              string
    Platform            string
    Version             string
    Capabilities        uint32
    NativeVLAN          int
    Addresses           []string
    DecodedCaps         []string
    CapabilitiesDecoded []string
}

type LLDPInfo struct {
    ChassisID    string
    PortID       string
    SysName      string
    SysDescr     string
    MgmtAddrs    []string
    Capabilities []string
}

type STPInfo struct {
    RootBridgeID string
    RootPathCost uint32
    BridgeID     string
    PortID       uint16
    HelloTime    uint16
    MaxAge       uint16
    ForwardDelay uint16
    MessageAge   uint16
    IsRoot       bool
}

type Anomaly struct {
    Type        string
    Severity    string
    Key         string
    Parameters  map[string]interface{}
    Scope       string
    Description string
}

type Subnet struct {
    CIDR       string
    Source     string
    Hosts      []string
    CountHosts int
    VLANs      []int
}
```

**Anomaly constants**:
- `AnomArpStorm`: "ARP storm detected"
- `AnomMultiIP`: "Multiple IPs per MAC detected"
- `AnomAbnormalTTL`: "Abnormal TTL values detected"
- `AnomBroadcastDestinations`: "Multiple broadcast destinations detected"
- `AnomMultipleDHCPServers`: "Multiple DHCP servers detected"
- `AnomSuspiciousTTL`: "Suspicious TTL values detected"
- `AnomUnusualPorts`: "Unusual port combinations detected"
- `AnomMACAnomalies`: "MAC address anomalies detected"

**Exported functions**:
- `StrengthPriority(strength string) int`: Returns numeric priority (high=3, medium=2, low=1)
- `NewAnomaly(anomalyType, severity, description string, parameters map[string]interface{}) Anomaly`
- `NewIPDuplicateV4Anomaly(ip string, vlanID int, macs []string) Anomaly`
- `(h *Host) AddPort(port int)`
- `(h *Host) AddVLAN(vlan int)`
- `(h *Host) AddIP(ip net.IP)`
- `(h *Host) GetIPv4s() []net.IP`
- `(h *Host) GetIPv6s() []net.IP`

---

### `pkg/sniffer`

**Package**: `pkg/sniffer`

**Exported structures**:
```go
type LiveSniffer struct {
    // Real-time capture from network interface
}

type PcapSniffer struct {
    // Offline PCAP file reading
}
```

**Exported functions**:
- `NewLiveSniffer(cfg *config.Config, packetChan chan model.PacketEvent, log *logger.Logger, outputDir string) *LiveSniffer`
- `NewPcapSniffer(path string, packetChan chan model.PacketEvent, log *logger.Logger, showUI bool) *PcapSniffer`
- `(ls *LiveSniffer) Start(ctx context.Context) error`
- `(ps *PcapSniffer) Start(ctx context.Context) error`

**Supported PCAP formats**: `.pcap`, `.pcapng`

---

### `pkg/scanner`

**Package**: `pkg/scanner`

**Exported functions**:
- `RunActiveScan(ctx context.Context, cfg *config.Config, log *logger.Logger) []*model.Host`
- `RunActiveScanWithTargets(ctx context.Context, cfg *config.Config, log *logger.Logger, passiveHosts []*model.Host) []*model.Host`
- `ScanARP(ctx context.Context, cfg *config.Config, log *logger.Logger) []*model.Host`
- `ScanARPWithTargets(ctx context.Context, cfg *config.Config, log *logger.Logger, targets []net.IP) []*model.Host`
- `ScanSYNFromPipeline(ctx context.Context, cfg *config.Config, targets []*model.Host, log *logger.Logger) []*model.Host`
- `ScanSYNFromActive(ctx context.Context, cfg *config.Config, log *logger.Logger, targets []*model.Host) []*model.Host`
- `IsBlacklisted(ip net.IP, blacklist []string) bool`

**Scan methods**:
- **ARP**: /24 local scan or specific targets
- **SYN**: TCP scan with OS fingerprinting

---

### `pkg/analyzer`

**Package**: `pkg/analyzer`

**Detected protocols** (`Parse*Packet` functions):
- **CDP**: Cisco Discovery Protocol
- **LLDP**: Link Layer Discovery Protocol
- **STP**: Spanning Tree Protocol
- **802.1X/EAPOL**: Network authentication
- **ARP**: Address Resolution Protocol
- **DHCP**: Dynamic Host Configuration Protocol
- **mDNS**: Multicast DNS (port 5353/udp)
- **LLMNR**: Link-Local Multicast Name Resolution (port 5355/udp)
- **NetBIOS**: NetBIOS Name Service (port 137/udp)
- **SSDP**: Simple Service Discovery Protocol (port 1900/udp)
- **SMB**: Server Message Block
- **IGMP**: Internet Group Management Protocol
- **NDP**: Neighbor Discovery Protocol (IPv6)
- **TCP**: Transmission Control Protocol
- **VLAN**: 802.1Q tagging

**Exported functions**:
- `AnalyzeWithCustomOptions(ctx context.Context, packetChan chan model.PacketEvent, scanID string, log *logger.Logger, opts *Options)`
- `GetResults() []*model.Host`
- `ComputeActiveSubnets(hosts []*model.Host) []model.Subnet`
- `GuessOS(ttl int, win int, opts []string) (string, int)` (DEPRECATED)
- `GuessOSWeighted(host *model.Host) OSResult`
- `MergeRole(oldRole, newRole string) string`
- `NormalizeRole(role string) string`

**OS detection**:
Based on TTL, Window Size and TCP options. Detected families: Windows, Linux, BSD, Other.

**Role inference**:
- `client`: Standard client host
- `server`: Server (ports 80, 443, 445, 3389, 22, 25, 110, 143)
- `reseau`: Network equipment (CDP, LLDP, STP)

---

### `pkg/exporter`

**Package**: `pkg/exporter`

**Exported functions**:

#### JSON
- `ExportAll(hosts []*model.Host, path string, log *logger.Logger) error`
- `ExportSubnets(subnets []model.Subnet, path string, log *logger.Logger) error`

#### CSV
- `ExportCSV(hosts []*model.Host, path string, log *logger.Logger) error`

#### HTML
- `ExportHTMLWithOptions(hosts []*model.Host, subnets []model.Subnet, path string, log *logger.Logger, allowPublicSubnets bool) error`

#### XML
- `ExportXML(hosts []*model.Host, path string, log *logger.Logger) error`

#### Markdown
- `ExportMarkdown(hosts []*model.Host, subnets []model.Subnet, path string, log *logger.Logger) error`

#### IP Sets
- `ExportIPSets(hosts []*model.Host, outputDir string, log *logger.Logger) error`

**Output formats**:
- **JSON**: `hosts.json`, complete structure with metadata
- **CSV**: `hosts.csv`, delimiter `;`, columns: MAC, Vendor, VLANs, L2Flags, IP, IPv6, UDP_Services, TCP_Services, Protocols, OS
- **HTML**: `report.html`, interactive report with filters and search
- **XML**: `hosts.xml`, standardized XML format
- **Markdown**: `report.md`, text documentation
- **IP Sets**: `private_ips.txt`, `public_ips.txt`

---

### `pkg/fusion`

**Package**: `pkg/fusion`

**Exported functions**:
- `MergeResults(passive, active []*model.Host) []*model.Host`: Merges passive and active results
- `MergeHosts(passive, active []*model.Host) []*model.Host` (DEPRECATED, use MergeResults)

**Merge logic**:
- Unique key: IP + MAC
- Priorities: FirstSeen (min), LastSeen (max)
- Roles: reseau > server > client
- Source: "combined" after merge

---

### `pkg/orchestrator`

**Package**: `pkg/orchestrator`

**Exported structures**:
```go
type Orchestrator struct {
    Config          *config.Config
    Log             *logger.Logger
    OutputPath      string
    ActiveScanFunc  func(context.Context, *config.Config, *logger.Logger) []*model.Host
}
```

**Exported functions**:
- `NewOrchestrator(cfg *config.Config, log *logger.Logger, outputPath string) *Orchestrator`
- `(o *Orchestrator) Run() error`
- `RunDemoProgressBars()`

**Execution pipeline**:
1. OUI loading (embedded or external)
2. Passive/active/combined/PCAP mode
3. Packet analysis
4. Results merging
5. Optional SYN scan
6. Multi-format export
7. Optional CLI summary

---

### `pkg/ui`

**Package**: `pkg/ui`

**Exported functions**:
- `PrintProgressBar(name string, total int, displayType string, eta string, stepDelay time.Duration) func(int)`
- `PrintScanSummary(scanID string, all []*model.Host, passive []*model.Host, active []*model.Host, outputDir string)`

**Progress bar types**:
- `time`: Display in seconds
- `count`: Display in units with ETA

---

### `pkg/utils`

**Package**: `pkg/utils`

**Exported functions**:

#### Slices
- `ContainsString(hay []string, needle string) bool`
- `MergeIntUnique(a, b []int) []int`
- `MergeStrUnique(a, b []string) []string`

#### Parsing
- `ParseInfoParts(info string) map[string]string`

#### IP
- `IsExcludedIPv4(ip net.IP) bool`
- `IsExcludedIPv6(ip net.IP) bool`
- `IsExcludedIPv4Str(ip string) bool`
- `IsExcludedIPv6Str(ip string) bool`
- `IsPrivateIPv4(ip net.IP) bool`

**Excluded ranges**:
- IPv4: `127.0.0.0/8` (loopback), `224.0.0.0/4` (multicast), `0.0.0.0/8` (reserved), `255.255.255.255` (broadcast)
- IPv6: `fe80::/10` (link-local)

**RFC1918 private ranges**:
- `10.0.0.0/8`
- `172.16.0.0/12`
- `192.168.0.0/16`

---

## Data Flow

```
┌─────────────┐
│  CLI Flags  │
└──────┬──────┘
       │
       ▼
┌─────────────┐     ┌──────────────┐
│   Config    │────▶│ Orchestrator │
└─────────────┘     └──────┬───────┘
                           │
                           ▼
                  ┌────────────────┐
                  │    Sniffer     │
                  │ (Live or PCAP) │
                  └────────┬───────┘
                           │
                           ▼ PacketEvent chan
                  ┌────────────────┐
                  │   Dispatcher   │
                  └────────┬───────┘
                           │
                           ▼ ParsedRecord
                  ┌────────────────┐
                  │  Aggregator    │
                  └────────┬───────┘
                           │
                           ▼ []*model.Host
                  ┌────────────────┐
                  │     Fusion     │
                  └────────┬───────┘
                           │
                           ▼
                  ┌────────────────┐
                  │   Exporters    │
                  └────────────────┘
```

## External Dependencies

- `github.com/google/gopacket v1.1.19`: Packet capture and parsing
- `github.com/rs/zerolog v1.34.0`: Structured logging
- `gopkg.in/yaml.v3 v3.0.1`: YAML parsing
- `github.com/google/uuid v1.6.0`: UUID generation
- `github.com/stretchr/testify v1.10.0`: Unit testing

## Compatibility

- **Go**: ≥ 1.24.2
- **OS**: Linux/Unix (tested on Kali Linux)
- **Privileges**: root required for live network capture

