# Zandoli Documentation Schemas

This directory contains visual schemas to help understand Zandoli's documentation. These diagrams use Mermaid syntax for better readability.

## Available Files

### 📋 [architecture.md](architecture.md)
**System architecture schemas**
- Module overview
- Main data flow
- Layer separation (internal/ vs pkg/)
- Interfaces and dependencies
- Execution modes
- Concurrency management
- Configuration and dependency injection

### 🗃️ [data_model.md](data_model.md)
**Data model schemas**
- Complete Host structure
- Entity relationships
- PacketEvent → Host flow
- Role classification
- IP↔MAC conflict management
- Protocol priority matrix
- Anomaly structure
- JSON serialization
- VLAN management
- Metrics and statistics

### 🔄 [pipeline.md](pipeline.md)
**Data processing pipeline schemas**
- Pipeline overview
- Detailed data flow
- Execution modes
- Concurrency management
- Parsing pipeline
- Protocol dispatch
- Aggregation and correlation
- Role inference
- Error handling
- Metrics and performance

### 🌐 [protocols.md](protocols.md)
**Supported protocol schemas**
- Protocol overview
- CDP (Cisco Discovery Protocol)
- LLDP (Link Layer Discovery Protocol)
- STP (Spanning Tree Protocol)
- DHCP (Dynamic Host Configuration Protocol)
- ARP (Address Resolution Protocol)
- mDNS (Multicast DNS)
- TCP Fingerprinting
- Parsing flow by protocol
- Protocol priorities
- Anomaly detection by protocol

### 📤 [exports.md](exports.md)
**Export format schemas**
- Export overview
- JSON structure
- HTML structure
- CSV structure
- Export generation flow
- IP selection for export
- Detailed HTML template
- Export error handling
- Export metrics
- Export configuration

### ⚙️ [configuration.md](configuration.md)
**Configuration schemas**
- Configuration overview
- Complete configuration structure
- Execution modes
- Scan configuration
- Log configuration
- Export configuration
- Configuration priority
- Configuration validation
- Environment-specific configuration
- Configuration error handling
- Metrics configuration

## How to Use These Schemas

### 1. Online Visualization
These schemas can be visualized directly in:
- **GitHub**: Mermaid diagrams are rendered automatically
- **GitLab**: Native Mermaid diagram support
- **Mermaid Live Editor**: https://mermaid.live/
- **VS Code**: Mermaid Preview extension

### 2. Integration in Documentation
Schemas are referenced in main documents:
- `docs/ARCHITECTURE.md` → `schemas/architecture.md`
- `docs/DATA_MODEL.md` → `schemas/data_model.md`
- `docs/PIPELINE.md` → `schemas/pipeline.md`
- `docs/L2_PROTOCOLS.md` → `schemas/protocols.md`
- `docs/EXPORTS.md` → `schemas/exports.md`
- `docs/CLI.md` → `schemas/configuration.md`

### 3. Schema Updates
When modifying code:
1. Identify changes in architecture
2. Update corresponding schema
3. Verify consistency with documentation
4. Test Mermaid rendering

## Conventions Used

### Colors and Styles
- **Blue**: Main modules
- **Green**: Data and structures
- **Orange**: Processes and flows
- **Red**: Errors and anomalies
- **Purple**: Configuration and parameters

### Symbols
- **🔵**: Modules/Components
- **📊**: Data/Structures
- **⚡**: Processes/Flows
- **⚠️**: Errors/Anomalies
- **⚙️**: Configuration

### Diagram Types
- **Graph TB/LR**: Hierarchies and flows
- **Sequence**: Temporal interactions
- **State**: States and transitions
- **Class**: Data structures
- **ER**: Entity relationships

## Contribution

To add or modify schemas:

1. **Identify the need**: What concept needs visualization?
2. **Choose the type**: Which Mermaid diagram is most appropriate?
3. **Create the schema**: Use appropriate Mermaid syntax
4. **Test rendering**: Verify in Mermaid Live Editor
5. **Integrate**: Add to appropriate file
6. **Document**: Update this README if necessary

## Recommended Tools

### Editing
- **VS Code** + Mermaid Preview extension
- **Mermaid Live Editor** (https://mermaid.live/)
- **Draw.io** (Mermaid export)

### Validation
- **Mermaid CLI**: Syntax validation
- **GitHub/GitLab**: Automatic rendering
- **Documentation**: Consistency with code

### Maintenance
- **Validation scripts**: Check syntax
- **Rendering tests**: Ensure readability
- **Automatic updates**: Synchronize with code

---

**Note**: These schemas are visual representations of documentation. They must be maintained in consistency with source code and textual documentation.
