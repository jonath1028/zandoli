# Schémas d'Architecture Zandoli

## Vue d'ensemble des Modules

```mermaid
graph TB
    subgraph "Point d'entrée"
        CLI[cmd/zandoli/main.go]
        CONFIG[internal/config/]
    end
    
    subgraph "Orchestration"
        ORCH[pkg/orchestrator/]
        FACTORY[orchestrator_factory.go]
        PIPELINE[run_pipeline.go]
    end
    
    subgraph "Capture"
        SNIFFER[pkg/sniffer/]
        PCAP[pcap_sniffer.go]
        LIVE[live_sniffer.go]
        STATS[statistics.go]
    end
    
    subgraph "Analyse"
        ANALYZER[pkg/analyzer/]
        DISPATCH[dispatcher.go]
        AGGREGATE[aggregator.go]
        ROLE[role_inference.go]
    end
    
    subgraph "Parseurs L2"
        CDP[cdp.go]
        LLDP[lldp.go]
        STP[stp.go]
        EAPOL[8021x.go]
    end
    
    subgraph "Parseurs L3+"
        DHCP[dhcp.go]
        ARP[arp_passive.go]
        MDNS[mdns.go]
        TCP[tcp.go]
    end
    
    subgraph "Export"
        EXPORTER[pkg/exporter/]
        JSON[json_exporter.go]
        HTML[html_exporter.go]
        CSV[csv_exporter.go]
    end
    
    CLI --> CONFIG
    CLI --> ORCH
    ORCH --> FACTORY
    ORCH --> PIPELINE
    PIPELINE --> SNIFFER
    PIPELINE --> ANALYZER
    SNIFFER --> PCAP
    SNIFFER --> LIVE
    ANALYZER --> DISPATCH
    ANALYZER --> AGGREGATE
    ANALYZER --> ROLE
    DISPATCH --> CDP
    DISPATCH --> LLDP
    DISPATCH --> STP
    DISPATCH --> EAPOL
    DISPATCH --> DHCP
    DISPATCH --> ARP
    DISPATCH --> MDNS
    DISPATCH --> TCP
    AGGREGATE --> EXPORTER
    EXPORTER --> JSON
    EXPORTER --> HTML
    EXPORTER --> CSV
```

## Flux de Données Principal

```mermaid
sequenceDiagram
    participant CLI as CLI
    participant ORCH as Orchestrator
    participant SNIFFER as Sniffer
    participant DISPATCH as Dispatcher
    participant PARSERS as Parseurs
    participant AGG as Aggregator
    participant EXP as Exporter
    
    CLI->>ORCH: Lancement
    ORCH->>SNIFFER: Initialisation capture
    SNIFFER->>DISPATCH: PacketEvent
    DISPATCH->>PARSERS: Routage par protocole
    PARSERS->>AGG: ParsedRecord
    AGG->>AGG: Corrélation & fusion
    AGG->>EXP: Hosts finaux
    EXP->>CLI: Rapports générés
```

## Séparation des Couches

```mermaid
graph LR
    subgraph "internal/ - Configuration & Utilitaires"
        CONFIG[config/]
        LOGGER[logger/]
        VALID[validation/]
        OUI[oui/]
    end
    
    subgraph "pkg/ - Logique Métier"
        SNIFFER[pkg/sniffer/]
        ANALYZER[pkg/analyzer/]
        MODEL[pkg/model/]
        EXPORTER[pkg/exporter/]
        ORCHESTRATOR[pkg/orchestrator/]
        SCANNER[pkg/scanner/]
        FUSION[pkg/fusion/]
        UI[pkg/ui/]
        UTILS[pkg/utils/]
    end
    
    subgraph "cmd/ - Point d'entrée"
        MAIN[cmd/zandoli/main.go]
    end
    
    MAIN --> CONFIG
    MAIN --> LOGGER
    MAIN --> ORCHESTRATOR
    ORCHESTRATOR --> SNIFFER
    ORCHESTRATOR --> ANALYZER
    ORCHESTRATOR --> SCANNER
    ANALYZER --> MODEL
    ANALYZER --> EXPORTER
    EXPORTER --> UTILS
    SCANNER --> FUSION
    ORCHESTRATOR --> UI
```

## Interfaces et Dépendances

```mermaid
graph TD
    subgraph "Interfaces Principales"
        PacketSource[PacketSource]
        ActiveScanFunc[ActiveScanFunc]
        Logger[Logger]
    end
    
    subgraph "Implémentations"
        PCAPSniffer[PCAPSniffer]
        LiveSniffer[LiveSniffer]
        ARPScanner[ARPScanner]
        SYNScanner[SYNScanner]
        ZerologLogger[ZerologLogger]
    end
    
    PacketSource --> PCAPSniffer
    PacketSource --> LiveSniffer
    ActiveScanFunc --> ARPScanner
    ActiveScanFunc --> SYNScanner
    Logger --> ZerologLogger
```

## Modes d'Exécution

```mermaid
stateDiagram-v2
    [*] --> ModeSelection
    
    ModeSelection --> Passive : --passive
    ModeSelection --> Active : --active
    ModeSelection --> Combined : --combined
    ModeSelection --> PCAP : --pcap file
    
    Passive --> LiveCapture
    Active --> ARPScan
    Active --> SYNScan : --SYN
    Combined --> LiveCapture
    Combined --> ARPScan
    PCAP --> FileAnalysis
    
    LiveCapture --> Analysis
    ARPScan --> Analysis
    SYNScan --> Analysis
    FileAnalysis --> Analysis
    
    Analysis --> Export
    Export --> [*]
```

## Gestion de la Concurrence

```mermaid
graph TB
    subgraph "Goroutines Principales"
        MAIN[Main Goroutine]
        CAPTURE[Capture Goroutine]
        ANALYSIS[Analysis Goroutine]
        EXPORT[Export Goroutine]
    end
    
    subgraph "Canaux de Communication"
        PACKET_CHAN[Packet Channel]
        RESULT_CHAN[Result Channel]
        ERROR_CHAN[Error Channel]
    end
    
    MAIN --> CAPTURE
    CAPTURE --> PACKET_CHAN
    PACKET_CHAN --> ANALYSIS
    ANALYSIS --> RESULT_CHAN
    RESULT_CHAN --> EXPORT
    CAPTURE --> ERROR_CHAN
    ANALYSIS --> ERROR_CHAN
    ERROR_CHAN --> MAIN
```

## Configuration et Injection de Dépendances

```mermaid
graph TD
    subgraph "Configuration"
        YAML[config.yaml]
        FLAGS[CLI Flags]
        DEFAULTS[Default Values]
    end
    
    subgraph "Factory Pattern"
        FACTORY[OrchestratorFactory]
        OPTIONS[Options]
    end
    
    subgraph "Injection"
        ORCHESTRATOR[Orchestrator]
        SNIFFER[Sniffer]
        ANALYZER[Analyzer]
        SCANNER[Scanner]
    end
    
    YAML --> CONFIG[Config Struct]
    FLAGS --> CONFIG
    DEFAULTS --> CONFIG
    CONFIG --> FACTORY
    FACTORY --> OPTIONS
    OPTIONS --> ORCHESTRATOR
    OPTIONS --> SNIFFER
    OPTIONS --> ANALYZER
    OPTIONS --> SCANNER
```
