# Zandoli Visual Schemas

> 📊 **Complete collection of diagrams** to understand Zandoli's architecture, data, and flows.

## 🎯 Quick Access to Schemas

| Document | Associated Schemas | Description |
|----------|-------------------|-------------|
| **[ARCHITECTURE.md](ARCHITECTURE.md)** | [schemas/architecture.md](schemas/architecture.md) | System architecture and modules |
| **[DATA_MODEL.md](DATA_MODEL.md)** | [schemas/data_model.md](schemas/data_model.md) | Data model and structures |
| **[PIPELINE.md](PIPELINE.md)** | [schemas/pipeline.md](schemas/pipeline.md) | Processing pipeline |
| **[L2_PROTOCOLS.md](L2_PROTOCOLS.md)** | [schemas/protocols.md](schemas/protocols.md) | Supported protocols |
| **[EXPORTS.md](EXPORTS.md)** | [schemas/exports.md](schemas/exports.md) | Export formats |
| **[CLI.md](CLI.md)** | [schemas/configuration.md](schemas/configuration.md) | Configuration and CLI |

## 📋 Complete Index

### 🏗️ Architecture and Design
- **[schemas/architecture.md](schemas/architecture.md)** - System overview
  - Main modules and their responsibilities
  - Data flows and interfaces
  - Layer separation (internal/ vs pkg/)
  - Concurrency management
  - Configuration and dependency injection

- **[schemas/pipeline.md](schemas/pipeline.md)** - Data processing flows
  - Pipeline steps from capture to export
  - Execution modes (passive/active/combined/PCAP)
  - Concurrency management with goroutines
  - Protocol dispatch
  - Data aggregation and correlation

### 📊 Data and Structures
- **[schemas/data_model.md](schemas/data_model.md)** - Complete data model
  - Host structure and its components
  - Entity relationships (Host, Anomaly, L2Signals, etc.)
  - Role classification and conflict management
  - JSON serialization and VLAN management
  - Metrics and statistics

- **[schemas/protocols.md](schemas/protocols.md)** - Protocol structures
  - CDP, LLDP, STP, DHCP, ARP, mDNS
  - TCP Fingerprinting and options
  - Parsing flows by protocol
  - Priorities and anomaly detection

### ⚙️ Configuration and Usage
- **[schemas/configuration.md](schemas/configuration.md)** - System configuration
  - Complete configuration structure
  - Execution modes and scan parameters
  - Log and export configuration
  - Validation and error handling
  - Environment-specific configuration

- **[schemas/exports.md](schemas/exports.md)** - Output formats
  - JSON, HTML, CSV, XML structures
  - Export generation flows
  - IP selection and HTML templates
  - Error handling and metrics

## 🚀 How to Use These Schemas

### For Developers
1. **Understand the architecture**: Start with [schemas/architecture.md](schemas/architecture.md)
2. **Analyze data**: Study [schemas/data_model.md](schemas/data_model.md)
3. **Follow the pipeline**: Visualize [schemas/pipeline.md](schemas/pipeline.md)

### For Users
1. **Configuration**: Consult [schemas/configuration.md](schemas/configuration.md)
2. **Output formats**: Explore [schemas/exports.md](schemas/exports.md)
3. **Supported protocols**: Discover [schemas/protocols.md](schemas/protocols.md)

### For Administrators
1. **System architecture**: [schemas/architecture.md](schemas/architecture.md)
2. **Error management**: [schemas/pipeline.md](schemas/pipeline.md#error-management)
3. **Advanced configuration**: [schemas/configuration.md](schemas/configuration.md#environment-specific-configuration)

## 🛠️ Visualization Tools

### Online Visualization
- **GitHub/GitLab**: Automatic Mermaid diagram rendering
- **Mermaid Live Editor**: https://mermaid.live/
- **VS Code**: Mermaid Preview extension

### Validation and Testing
- **Mermaid CLI**: Syntax validation
- **Documentation**: Consistency with source code
- **Rendering tests**: Readability verification

## 📝 Schema Maintenance

### When to Update
- ✅ Architecture modification
- ✅ New protocol addition
- ✅ Data model change
- ✅ New export formats
- ✅ Configuration modification

### Update Process
1. **Identify the change** in source code
2. **Locate the schema** concerned
3. **Modify the Mermaid diagram**
4. **Test rendering** in Mermaid Live Editor
5. **Verify consistency** with documentation

## 🔗 Useful Links

- **[schemas/README.md](schemas/README.md)** - Detailed schema guide
- **[schemas/index.md](schemas/index.md)** - Navigation index
- **[Mermaid Documentation](https://mermaid-js.github.io/mermaid/)** - Diagram syntax

---

**💡 Tip**: Use these schemas as a complement to textual documentation. They provide a quick overview and facilitate understanding of Zandoli's complex concepts.
