# Zandoli Schemas Index

## Quick Navigation

| Main Document | Associated Schemas | Description |
|---------------|-------------------|-------------|
| [ARCHITECTURE.md](../ARCHITECTURE.md) | [architecture.md](architecture.md) | System architecture and modules |
| [DATA_MODEL.md](../DATA_MODEL.md) | [data_model.md](data_model.md) | Data model and structures |
| [PIPELINE.md](../PIPELINE.md) | [pipeline.md](pipeline.md) | Processing pipeline |
| [L2_PROTOCOLS.md](../L2_PROTOCOLS.md) | [protocols.md](protocols.md) | Supported protocols |
| [EXPORTS.md](../EXPORTS.md) | [exports.md](exports.md) | Export formats |
| [CLI.md](../CLI.md) | [configuration.md](configuration.md) | Configuration and CLI |

## Schemas by Category

### 🏗️ Architecture and Design
- **[architecture.md](architecture.md)** - System overview
- **[pipeline.md](pipeline.md)** - Data processing flows

### 📊 Data and Structures
- **[data_model.md](data_model.md)** - Complete data model
- **[protocols.md](protocols.md)** - Protocol structures

### ⚙️ Configuration and Usage
- **[configuration.md](configuration.md)** - System configuration
- **[exports.md](exports.md)** - Output formats

## Cross Links

### Architecture → Data
- [Module architecture](architecture.md#module-overview) → [Host structure](data_model.md#host-structure---overview)
- [Data flow](architecture.md#main-data-flow) → [Entity relationships](data_model.md#entity-relationships)

### Pipeline → Protocols
- [Protocol dispatch](pipeline.md#protocol-dispatch) → [Protocol overview](protocols.md#protocol-overview)
- [Specialized parsing](pipeline.md#parsing-pipeline) → [Parsing flow by protocol](protocols.md#parsing-flow-by-protocol)

### Configuration → Exports
- [Export configuration](configuration.md#export-configuration) → [Export overview](exports.md#export-overview)
- [Available formats](configuration.md#export-configuration) → [Format structures](exports.md#json-structure)

## Schema Usage

### For Developers
1. **Understand architecture**: Start with [architecture.md](architecture.md)
2. **Analyze data**: Study [data_model.md](data_model.md)
3. **Follow pipeline**: Visualize [pipeline.md](pipeline.md)

### For Users
1. **Configuration**: Consult [configuration.md](configuration.md)
2. **Output formats**: Explore [exports.md](exports.md)
3. **Supported protocols**: Discover [protocols.md](protocols.md)

### For Administrators
1. **System architecture**: [architecture.md](architecture.md)
2. **Error management**: [pipeline.md](pipeline.md#error-management)
3. **Advanced configuration**: [configuration.md](configuration.md#environment-specific-configuration)

## Schema Updates

### When to Update
- ✅ Architecture modification
- ✅ New protocol addition
- ✅ Data model change
- ✅ New export formats
- ✅ Configuration modification

### How to Update
1. **Identify the change** in source code
2. **Locate the schema** concerned
3. **Modify the Mermaid diagram**
4. **Test rendering** in Mermaid Live Editor
5. **Verify consistency** with documentation

### Validation Tools
- **Mermaid Live Editor**: https://mermaid.live/
- **VS Code Extension**: Mermaid Preview
- **GitHub/GitLab**: Automatic rendering

## Usage Examples

### Understanding a Bug
1. Identify the component in [architecture.md](architecture.md)
2. Follow the flow in [pipeline.md](pipeline.md)
3. Verify the structure in [data_model.md](data_model.md)

### Adding a Feature
1. Analyze architectural impact in [architecture.md](architecture.md)
2. Modify the pipeline in [pipeline.md](pipeline.md)
3. Adapt configuration in [configuration.md](configuration.md)

### Optimizing Performance
1. Identify bottlenecks in [pipeline.md](pipeline.md#metrics-and-performance)
2. Analyze metrics in [data_model.md](data_model.md#metrics-and-statistics)
3. Adjust configuration in [configuration.md](configuration.md#metrics-configuration)

---

**💡 Tip**: Use these schemas as a complement to textual documentation. They provide a quick overview and facilitate understanding of complex concepts.
