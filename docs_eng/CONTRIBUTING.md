# Contributing

This document provides guidelines for contributing to the Zandoli project.

## Development Environment

### Prerequisites
- **Go ≥ 1.18**: Required for building and testing
- **Linux/Unix**: Primary development platform
- **Git**: Version control system
- **Make**: Build automation (optional)

### Development Setup
```bash
# Clone the repository
git clone <repository-url>
cd zandoli

# Install dependencies
go mod download

# Build the project
go build -o zandoli cmd/zandoli/main.go

# Run tests
go test ./...

# Run with verbose output
go test -v ./...
```

### Required Tools
```bash
# Install development tools
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest

# Run linting
golangci-lint run

# Run security checks
gosec ./...
```

## Code Style and Conventions

### Go Code Style
Follow standard Go conventions and the project's style guidelines:

- **Formatting**: Use `gofmt` and `goimports`
- **Naming**: Follow Go naming conventions
- **Comments**: Document all exported functions and types
- **Error handling**: Use explicit error checking, no `panic()`
- **Concurrency**: Use channels and goroutines appropriately

### Architecture Guidelines

#### Package Structure
```
pkg/
├── analyzer/     # Packet analysis and protocol parsing
├── exporter/     # Report generation in multiple formats
├── fusion/       # Data integration and conflict resolution
├── model/        # Core data structures
├── orchestrator/ # Pipeline coordination
├── scanner/      # Active scanning (ARP, SYN)
├── sniffer/      # Packet capture and source management
├── ui/           # User interface components
└── utils/        # Common utilities and helpers
```

#### Internal Packages
```
internal/
├── config/       # Configuration management
├── logger/       # Structured logging
├── oui/          # MAC address vendor lookup
└── validation/   # Input validation
```

### Anti-Redundancy Rules

#### Centralized Utilities
All common helpers must be centralized in `pkg/utils`:

- **String utilities**: `pkg/utils/slices.go::ContainsString`
- **IP utilities**: `pkg/utils/ip.go::{IsExcludedIPv4, IsExcludedIPv6}`
- **Merge utilities**: `pkg/utils/slices.go::{MergeIntUnique, MergeStrUnique}`
- **Parsing utilities**: `pkg/utils/parse.go::ParseInfoParts`

#### Forbidden Patterns
- ❌ **Duplicate functions**: No local copies of utility functions
- ❌ **Global state**: No mutable global variables
- ❌ **Panic usage**: Use proper error handling instead
- ❌ **Circular dependencies**: Avoid package interdependencies

### Import Organization
```go
import (
    // Standard library imports
    "fmt"
    "net"
    "time"
    
    // Third-party imports
    "github.com/google/gopacket"
    "github.com/rs/zerolog"
    
    // Internal imports (always use full path)
    "zandoli/internal/config"
    "zandoli/internal/logger"
    
    // Package imports
    "zandoli/pkg/model"
    "zandoli/pkg/utils"
)
```

## Testing Guidelines

### Test Structure
```go
func TestFunctionName(t *testing.T) {
    // Arrange
    input := createTestInput()
    expected := createExpectedOutput()
    
    // Act
    result, err := FunctionName(input)
    
    // Assert
    assert.NoError(t, err)
    assert.Equal(t, expected, result)
}
```

### Test Categories

#### Unit Tests
- **Location**: `*_test.go` files in same package
- **Coverage**: All exported functions and methods
- **Mocking**: Use interfaces for external dependencies
- **Isolation**: Tests should be independent and parallelizable

#### Integration Tests
- **Location**: `test/` directory
- **Purpose**: Test component interactions
- **Data**: Use `testdata/` for test PCAP files
- **Cleanup**: Ensure tests clean up resources

#### Performance Tests
- **Location**: `*_perf_test.go` files
- **Purpose**: Benchmark critical functions
- **Naming**: `BenchmarkFunctionName`
- **Profiling**: Include memory and CPU profiling

### Test Data
```bash
# Test data structure
testdata/
├── sample.pcap      # Small test PCAP file
├── large.pcap       # Large PCAP for performance tests
├── corrupted.pcap   # Corrupted file for error testing
└── protocols/       # Protocol-specific test files
    ├── cdp.pcap
    ├── lldp.pcap
    └── stp.pcap
```

### Running Tests
```bash
# Run all tests
go test ./...

# Run tests with coverage
go test -cover ./...

# Run tests with race detection
go test -race ./...

# Run specific test
go test -run TestFunctionName ./pkg/analyzer

# Run benchmarks
go test -bench=. ./pkg/analyzer
```

## Pull Request Process

### Before Submitting
1. **Run tests**: Ensure all tests pass
2. **Run linting**: Fix any linting issues
3. **Update documentation**: Update relevant documentation
4. **Test manually**: Verify functionality works as expected

### Pull Request Template
```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] Unit tests added/updated
- [ ] Integration tests added/updated
- [ ] Manual testing completed

## Checklist
- [ ] Code follows project style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] No breaking changes (or documented)
```

### Review Process
1. **Automated checks**: CI/CD pipeline runs tests and linting
2. **Code review**: At least one maintainer review required
3. **Testing**: Reviewer tests the changes
4. **Approval**: Maintainer approval required for merge

## Development Workflow

### Branch Strategy
```bash
# Create feature branch
git checkout -b feature/new-protocol-parser

# Create bugfix branch
git checkout -b bugfix/memory-leak

# Create documentation branch
git checkout -b docs/update-readme
```

### Commit Messages
Follow conventional commit format:
```
type(scope): description

[optional body]

[optional footer]
```

Examples:
```
feat(analyzer): add LLDP protocol parser

Add support for Link Layer Discovery Protocol parsing
with TLV extraction and capability decoding.

fix(exporter): resolve CSV delimiter issue

The CSV exporter was using comma delimiter instead of
semicolon, causing Excel import issues.

docs(readme): update installation instructions

Add Go version requirement and build steps.
```

### Commit Types
- **feat**: New feature
- **fix**: Bug fix
- **docs**: Documentation changes
- **style**: Code style changes
- **refactor**: Code refactoring
- **test**: Test additions or changes
- **chore**: Maintenance tasks

## Adding New Features

### New Protocol Parser
1. **Create parser module** in `pkg/analyzer/`
2. **Define data structures** in `pkg/model/`
3. **Register with dispatcher** in `pkg/analyzer/dispatcher.go`
4. **Add tests** with sample packets
5. **Update documentation**

### New Export Format
1. **Create exporter module** in `pkg/exporter/`
2. **Implement export interface**
3. **Add CLI option** in `cmd/zandoli/main.go`
4. **Update configuration** in `internal/config/`
5. **Add tests and documentation**

### New Scan Type
1. **Create scanner module** in `pkg/scanner/`
2. **Integrate with orchestrator** in `pkg/orchestrator/`
3. **Add configuration options**
4. **Update CLI interface**
5. **Add tests and documentation**

## Performance Guidelines

### Memory Management
- **Streaming processing**: For large PCAP files
- **Efficient data structures**: Use appropriate data types
- **Memory cleanup**: Clear temporary data structures
- **Profiling**: Use `go tool pprof` for memory analysis

### Concurrency
- **Goroutine pools**: Limit concurrent goroutines
- **Channel communication**: Use channels for data passing
- **Lock-free operations**: Minimize mutex usage
- **Context cancellation**: Support graceful shutdown

### Optimization
- **Benchmarking**: Use `go test -bench` for performance testing
- **Profiling**: Profile CPU and memory usage
- **Algorithm efficiency**: Choose appropriate algorithms
- **Data structure optimization**: Use efficient data structures

## Documentation Requirements

### Code Documentation
- **Package comments**: Document package purpose and usage
- **Function comments**: Document all exported functions
- **Type comments**: Document all exported types
- **Example usage**: Provide usage examples where helpful

### API Documentation
- **Interface documentation**: Document all public interfaces
- **Parameter documentation**: Document all parameters and return values
- **Error documentation**: Document all possible errors
- **Usage examples**: Provide practical usage examples

### User Documentation
- **README updates**: Update README for new features
- **CLI documentation**: Update CLI reference for new options
- **Configuration documentation**: Document new configuration options
- **Troubleshooting**: Add troubleshooting information

## Security Considerations

### Code Security
- **Input validation**: Validate all inputs
- **Error handling**: Handle errors securely
- **No hardcoded secrets**: Use configuration for sensitive data
- **Secure coding**: Follow secure coding practices

### Testing Security
- **Security tests**: Test for security vulnerabilities
- **Input fuzzing**: Test with malformed inputs
- **Boundary testing**: Test edge cases and limits
- **Error condition testing**: Test error handling

## Release Process

### Version Management
- **Semantic versioning**: Use semver for releases
- **Changelog**: Maintain detailed changelog
- **Release notes**: Document changes and migration notes
- **Backward compatibility**: Maintain API compatibility

### Release Checklist
- [ ] All tests pass
- [ ] Documentation updated
- [ ] Changelog updated
- [ ] Version bumped
- [ ] Release notes prepared
- [ ] Security review completed

## Community Guidelines

### Code of Conduct
- **Respectful communication**: Be respectful and professional
- **Constructive feedback**: Provide constructive criticism
- **Inclusive environment**: Welcome contributors of all backgrounds
- **Focus on code**: Keep discussions focused on code and technical topics

### Getting Help
- **GitHub issues**: Use issues for bug reports and feature requests
- **Discussions**: Use discussions for questions and ideas
- **Documentation**: Check documentation before asking questions
- **Search**: Search existing issues before creating new ones

## See Also

- [Architecture Overview](ARCHITECTURE.md)
- [CLI Reference](CLI.md)
- [Security Considerations](SECURITY.md)
- [Troubleshooting](TROUBLESHOOTING.md)
