#!/bin/bash

set -e

# ════════════════════════════════════════════════════════════════════════
# 🛠️ Zandoli Installation Script
# Version: 1.0
# Target: Debian/Ubuntu
# Author: Jonathan NOMED
# License: Apache 2.0
# ════════════════════════════════════════════════════════════════════════

echo "[+] Starting Zandoli installation..."

# 1. Vérification des droits root
if [ "$EUID" -ne 0 ]; then
  echo "[-] Please run as root (sudo ./install.sh)"
  exit 1
fi

# 2. Installation des dépendances système
echo "[+] Installing system dependencies..."
apt update && apt install -y golang libpcap-dev

# 3. Configuration de l'environnement Go
echo "[+] Setting up Go environment..."
export GO111MODULE=on
export GOPATH=$HOME/go
export PATH=$PATH:/usr/local/go/bin:$GOPATH/bin

# 4. Vérification version Go
echo "[+] Checking Go version..."
go_version=$(go version | awk '{print $3}' | sed 's/go//')
required_version="1.20"
if [ "$(printf '%s\n' "$required_version" "$go_version" | sort -V | head -n1)" != "$required_version" ]; then
  echo "[-] Go $required_version or higher is required. Found: $go_version"
  exit 1
fi

# 5. Téléchargement des modules Go
echo "[+] Downloading Go modules..."
go mod tidy

# 6. Compilation du binaire
echo "[+] Building Zandoli binary..."
mkdir -p bin
go build -o bin/zandoli ./cmd/zandoli

# 7. Vérification des fichiers de ressources
echo "[+] Verifying assets..."
if [ ! -f assets/mac_vendor.txt ]; then
  echo "[-] Required file 'assets/mac_vendor.txt' not found!"
  exit 1
fi

# 8. Fin de l'installation
echo "[✓] Installation complete."
echo "[→] Binary available at: ./bin/zandoli"

