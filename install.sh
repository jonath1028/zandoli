#!/bin/bash

echo "[*] Installing Zandoli dependencies..."

# Stop on first error
set -e

# Vérifie la présence de go.mod
if [ ! -f "go.mod" ]; then
    echo "[!] go.mod not found. You must run 'go mod init zandoli' manually."
    exit 1
fi

# Récupère toutes les dépendances (déclarées ou indirectes)
echo "[*] Tidying up modules..."
go mod tidy

# Récupère explicitement les dépendances principales
echo "[*] Installing main dependencies..."
go get github.com/google/gopacket@v1.1.19
go get github.com/rs/zerolog@v1.34.0
go get github.com/cheggaaa/pb/v3@v3.1.7
go get gopkg.in/yaml.v2@v2.4.0

echo "[✓] Zandoli dependencies installed successfully."

