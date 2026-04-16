# Installing Zandoli Alpha

## Automated Install (Recommended)

### Quick Install

```bash
curl -fsSL https://raw.githubusercontent.com/jonath1028/zandoli/main/install.sh -o install.sh

# Full automatic install (Go + system dependencies)
sudo bash install.sh --install-go --install-deps

# Verbose install with detailed logs
sudo bash install.sh --install-go --install-deps --verbose

# Dry run (simulation, no changes)
sudo bash install.sh --dry-run --verbose
```

### Installer Options

| Option | Description |
|--------|-------------|
| `-h, --help` | Show help |
| `-v, --verbose` | Verbose logging |
| `-f, --force` | Force reinstall even if already installed |
| `-d, --dry-run` | Simulate without installing |
| `--install-go` | Auto-install Go if missing |
| `--install-deps` | Auto-install system dependencies |
| `--no-deps` | Skip system dependency installation |
| `--version` | Show installer version |

## Manual Install

### Prerequisites

- **Go 1.24+**
- **System dependencies**:
  - `build-essential` / `gcc` / `make`
  - `git`
  - `libpcap-dev` / `libpcap-devel`
  - `tcpdump`
  - `nmap`
  - `net-tools`
- **Root privileges** for live packet capture

### System Dependencies by Distribution

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install -y build-essential git libpcap-dev tcpdump nmap net-tools
```

**CentOS/RHEL:**
```bash
sudo yum install -y gcc gcc-c++ make git libpcap-devel tcpdump nmap net-tools
```

**Fedora:**
```bash
sudo dnf install -y gcc gcc-c++ make git libpcap-devel tcpdump nmap net-tools
```

**Arch Linux:**
```bash
sudo pacman -S base-devel git libpcap tcpdump nmap net-tools
```

**openSUSE:**
```bash
sudo zypper install -y gcc gcc-c++ make git libpcap-devel tcpdump nmap net-tools
```

**Alpine Linux:**
```bash
sudo apk add build-base git libpcap-dev tcpdump nmap net-tools
```

### Build from Source

```bash
# Clone the repository
git clone https://github.com/jonath1028/zandoli.git
cd zandoli

# Download dependencies
go mod download

# Build
go build -o zandoli ./cmd/zandoli

# Install system-wide
sudo cp zandoli /usr/local/bin/
sudo chmod +x /usr/local/bin/zandoli

# Create symlink (optional)
sudo ln -sf /usr/local/bin/zandoli /usr/bin/zandoli
```

## Verify Installation

```bash
# Check version
zandoli --version

# Show help and all available flags
zandoli --help

# Run the progress bar demo (no network access needed)
zandoli --demo

# Analyze a PCAP file
sudo zandoli --pcap capture.pcap --formats json,csv,html --output-dir results/
```

## Configuration

Zandoli uses a YAML config file. See `config.yaml` for the full reference.

```bash
# Use a specific config file
zandoli --config /path/to/config.yaml

# Use a scan profile (overrides individual settings)
zandoli --profile stealth --passive --interface eth0
```

Available profiles: `stealth`, `normal`, `aggressive`, `passive-only`.

Priority: CLI flags > YAML config > profile defaults > hardcoded defaults.

## Uninstall

```bash
# Remove binaries
sudo rm -f /usr/local/bin/zandoli /usr/bin/zandoli

# Remove configuration (optional)
sudo rm -rf /etc/zandoli
```

## Troubleshooting

### `command not found`
- Ensure `/usr/local/bin` is in your `$PATH`
- Restart your terminal or run `source ~/.bashrc`

### Permission denied
- Run with `sudo` for live capture
- Check binary permissions: `ls -la /usr/local/bin/zandoli`

### Build fails
- Check Go version (need 1.24+): `go version`
- Ensure system dependencies are installed
- Check install logs: `/tmp/zandoli_install.log`

### Missing dependencies
- Install system dependencies for your distribution (see above)
- Use `--install-deps` for automatic installation

### No hosts found
- Verify the PCAP has Ethernet frames, not raw IP

## Security

The install script:
- Verifies download integrity
- Uses HTTPS for all downloads
- Does not store any sensitive data
- Can be audited before execution
- Supports dry-run mode for simulation

**Recommendation**: Always review the script before running it:
```bash
curl -fsSL https://raw.githubusercontent.com/jonath1028/zandoli/main/install.sh | less
```

## Support

- **Issues**: [GitHub Issues](https://github.com/jonath1028/zandoli/issues)
- **Documentation**: [Full docs](https://github.com/jonath1028/zandoli/blob/main/docs/)
- **Install logs**: `/tmp/zandoli_install.log`
