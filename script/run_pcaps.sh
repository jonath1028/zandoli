#!/bin/bash

# Script de test pour les fichiers PCAP
# Exécute Zandoli sur chaque fichier PCAP et effectue des assertions

set -e

# Couleurs pour l'affichage
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Variables
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$PROJECT_ROOT/build"
TESTDATA_DIR="$PROJECT_ROOT/testdata/testdata"
OUTPUT_DIR="$PROJECT_ROOT/output"
FAILED_TESTS=0
TOTAL_TESTS=0

# Fonction pour afficher les résultats
print_result() {
    local status="$1"
    local filename="$2"
    local message="$3"
    
    if [ "$status" = "PASS" ]; then
        echo -e "${GREEN}PASS${NC}: $filename - $message"
    else
        echo -e "${RED}FAIL${NC}: $filename - $message"
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi
}

# Fonction pour trouver le dernier fichier hosts.json
find_latest_hosts_json() {
    local latest_scan_dir
    latest_scan_dir=$(find "$OUTPUT_DIR" -name "scan_*" -type d | sort | tail -1)
    if [ -n "$latest_scan_dir" ]; then
        local scan_name=$(basename "$latest_scan_dir")
        # Vérifier si le fichier existe dans le sous-répertoire scan_*
        local hosts_file="$latest_scan_dir/scan_$scan_name/hosts.json"
        if [ -f "$hosts_file" ]; then
            echo "$hosts_file"
        else
            # Essayer de trouver directement dans le répertoire
            local direct_file="$latest_scan_dir/hosts.json"
            if [ -f "$direct_file" ]; then
                echo "$direct_file"
            else
                echo ""
            fi
        fi
    else
        echo ""
    fi
}

# Fonction pour vérifier si jq est disponible
check_jq() {
    if command -v jq >/dev/null 2>&1; then
        return 0
    else
        return 1
    fi
}

# Fonction pour compter les hôtes avec jq
count_hosts_jq() {
    local json_file="$1"
    if [ -f "$json_file" ]; then
        jq '.metadata.total_hosts // 0' "$json_file" 2>/dev/null || echo "0"
    else
        echo "0"
    fi
}

# Fonction pour vérifier les clés avec jq
check_key_jq() {
    local json_file="$1"
    local key_path="$2"
    if [ -f "$json_file" ]; then
        jq -e "$key_path" "$json_file" >/dev/null 2>&1
    else
        return 1
    fi
}

# Fonction pour vérifier les anomalies avec jq
check_anomalies_jq() {
    local json_file="$1"
    if [ -f "$json_file" ]; then
        # Vérifier s'il y a des anomalies dans le JSON
        jq -e '.anomalies // empty' "$json_file" >/dev/null 2>&1 || \
        jq -e '.hosts[] | select(.anomalies) | .anomalies' "$json_file" >/dev/null 2>&1
    else
        return 1
    fi
}

# Fonction pour utiliser le helper Go si jq n'est pas disponible
use_go_helper() {
    local json_file="$1"
    local operation="$2"
    local key_path="$3"
    
    # Construire le helper Go s'il n'existe pas
    if [ ! -f "$PROJECT_ROOT/cmd/tools/jsoncheck/jsoncheck" ]; then
        echo "Construction du helper Go jsoncheck..."
        go build -o "$PROJECT_ROOT/cmd/tools/jsoncheck/jsoncheck" "$PROJECT_ROOT/cmd/tools/jsoncheck/main.go"
    fi
    
    "$PROJECT_ROOT/cmd/tools/jsoncheck/jsoncheck" "$json_file" "$operation" "$key_path"
}

# Fonction principale de test
test_pcap_file() {
    local pcap_file="$1"
    local filename="$(basename "$pcap_file")"
    local test_passed=true
    local message=""
    
    echo "Test de $filename..."
    
    # Exécuter Zandoli
    if ! "$BUILD_DIR/zandoli" --pcap "$pcap_file" >/dev/null 2>&1; then
        print_result "FAIL" "$filename" "Échec de l'exécution de Zandoli"
        return 1
    fi
    
    # Trouver le dernier fichier hosts.json
    local hosts_json
    hosts_json=$(find_latest_hosts_json)
    
    if [ -z "$hosts_json" ] || [ ! -f "$hosts_json" ]; then
        print_result "FAIL" "$filename" "Fichier hosts.json non trouvé"
        return 1
    fi
    
    # Compter les hôtes
    local host_count
    if check_jq; then
        host_count=$(count_hosts_jq "$hosts_json")
    else
        host_count=$(use_go_helper "$hosts_json" "count_hosts" "")
    fi
    
    # Tests spécifiques selon le nom du fichier
    case "$filename" in
        dhcp*.pcap)
            if [ "$host_count" -ge 2 ]; then
                message="Hôtes >= 2 ($host_count)"
            else
                test_passed=false
                message="Hôtes < 2 ($host_count)"
            fi
            ;;
        eapol-mka.pcap)
            if [ "$host_count" -ge 1 ]; then
                message="Hôtes >= 1 ($host_count)"
            else
                test_passed=false
                message="Hôtes < 1 ($host_count)"
            fi
            ;;
        lldp.*.pcap)
            if [ "$host_count" -ge 1 ]; then
                message="Hôtes >= 1 ($host_count)"
            else
                test_passed=false
                message="Hôtes < 1 ($host_count)"
            fi
            ;;
        cdp*.pcap)
            if [ "$host_count" -ge 1 ]; then
                local cdp_check=false
                if check_jq; then
                    if check_key_jq "$hosts_json" '.hosts[] | select(.cdp) | .cdp | has("device_id") or has("platform")'; then
                        cdp_check=true
                    fi
                else
                    if use_go_helper "$hosts_json" "check_key" ".hosts[].cdp.device_id" || \
                       use_go_helper "$hosts_json" "check_key" ".hosts[].cdp.platform"; then
                        cdp_check=true
                    fi
                fi
                
                if [ "$cdp_check" = true ]; then
                    message="Hôtes >= 1 ($host_count) et champs CDP présents"
                else
                    test_passed=false
                    message="Hôtes >= 1 ($host_count) mais champs CDP manquants"
                fi
            else
                test_passed=false
                message="Hôtes < 1 ($host_count)"
            fi
            ;;
        stp.pcap)
            if [ "$host_count" -ge 1 ]; then
                local stp_check=false
                if check_jq; then
                    if check_key_jq "$hosts_json" '.hosts[] | select(.stp) | .stp | has("bridge_id")'; then
                        stp_check=true
                    fi
                else
                    if use_go_helper "$hosts_json" "check_key" ".hosts[].stp.bridge_id"; then
                        stp_check=true
                    fi
                fi
                
                if [ "$stp_check" = true ]; then
                    message="Hôtes >= 1 ($host_count) et bridge_id STP présent"
                else
                    test_passed=false
                    message="Hôtes >= 1 ($host_count) mais bridge_id STP manquant"
                fi
            else
                test_passed=false
                message="Hôtes < 1 ($host_count)"
            fi
            ;;
        arp-storm.pcap)
            local has_hosts=false
            local has_anomalies=false
            
            if [ "$host_count" -ge 1 ]; then
                has_hosts=true
            fi
            
            if check_jq; then
                if check_anomalies_jq "$hosts_json"; then
                    has_anomalies=true
                fi
            else
                if use_go_helper "$hosts_json" "check_anomalies" ""; then
                    has_anomalies=true
                fi
            fi
            
            if [ "$has_hosts" = true ] || [ "$has_anomalies" = true ]; then
                message="Hôtes >= 1 ($host_count) ou anomalies détectées"
            else
                test_passed=false
                message="Ni hôtes ni anomalies détectées"
            fi
            ;;
        *)
            # Pour les autres fichiers, on vérifie juste qu'il y a au moins un hôte
            if [ "$host_count" -ge 1 ]; then
                message="Hôtes >= 1 ($host_count)"
            else
                test_passed=false
                message="Hôtes < 1 ($host_count)"
            fi
            ;;
    esac
    
    if [ "$test_passed" = true ]; then
        print_result "PASS" "$filename" "$message"
    else
        print_result "FAIL" "$filename" "$message"
    fi
    
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
}

# Vérifier que le binaire Zandoli existe
if [ ! -f "$BUILD_DIR/zandoli" ]; then
    echo -e "${RED}Erreur: Le binaire Zandoli n'existe pas dans $BUILD_DIR${NC}"
    echo "Veuillez compiler le projet avec 'make' ou 'go build'"
    exit 1
fi

# Vérifier que le répertoire testdata existe
if [ ! -d "$TESTDATA_DIR" ]; then
    echo -e "${RED}Erreur: Le répertoire testdata n'existe pas: $TESTDATA_DIR${NC}"
    exit 1
fi

echo -e "${YELLOW}Démarrage des tests PCAP...${NC}"
echo "Répertoire de test: $TESTDATA_DIR"
echo "Répertoire de sortie: $OUTPUT_DIR"
echo ""

# Parcourir tous les fichiers PCAP
for pcap_file in "$TESTDATA_DIR"/*.pcap; do
    if [ -f "$pcap_file" ]; then
        test_pcap_file "$pcap_file"
    fi
done

echo ""
echo "=========================================="
echo -e "${YELLOW}Résumé des tests:${NC}"
echo "Total: $TOTAL_TESTS"
echo -e "Échecs: ${RED}$FAILED_TESTS${NC}"

if [ "$FAILED_TESTS" -eq 0 ]; then
    echo -e "${GREEN}Tous les tests ont réussi !${NC}"
    exit 0
else
    echo -e "${RED}Certains tests ont échoué.${NC}"
    exit 1
fi
