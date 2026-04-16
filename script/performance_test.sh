#!/bin/bash

# Script de test de performance pour Zandoli
# Compare les performances avec et sans optimisations

set -e

echo "=== Test de performance Zandoli ==="
echo "Date: $(date)"
echo ""

# Configuration
PCAP_FILE="testdata/The Ultimate PCAP v20250325.pcapng"
OUTPUT_DIR="performance_test_$(date +%Y%m%d_%H%M%S)"

# Créer le répertoire de sortie
mkdir -p "$OUTPUT_DIR"

echo "Fichier PCAP: $PCAP_FILE"
echo "Répertoire de sortie: $OUTPUT_DIR"
echo ""

# Test 1: Configuration par défaut (optimisée)
echo "=== Test 1: Configuration optimisée (par défaut) ==="
echo "Métriques: désactivées"
echo "Traitement: séquentiel"
echo "Début: $(date)"

time_start=$(date +%s.%N)
./build/zandoli --pcap "$PCAP_FILE" --output "$OUTPUT_DIR/test1_optimized" --formats json
time_end=$(date +%s.%N)
time1=$(echo "$time_end - $time_start" | bc)

echo "Fin: $(date)"
echo "Durée: ${time1}s"
echo ""

# Test 2: Avec métriques activées
echo "=== Test 2: Avec métriques activées ==="
echo "Métriques: activées (échantillonnage 1:100)"
echo "Traitement: séquentiel"
echo "Début: $(date)"

time_start=$(date +%s.%N)
./build/zandoli --pcap "$PCAP_FILE" --output "$OUTPUT_DIR/test2_metrics" --formats json --config <(cat config.yaml | sed 's/enable_metrics: false/enable_metrics: true/' | sed 's/metrics_sample_rate: 0/metrics_sample_rate: 100/')
time_end=$(date +%s.%N)
time2=$(echo "$time_end - $time_start" | bc)

echo "Fin: $(date)"
echo "Durée: ${time2}s"
echo ""

# Test 3: Avec traitement parallèle
echo "=== Test 3: Avec traitement parallèle ==="
echo "Métriques: désactivées"
echo "Traitement: parallèle (4 workers)"
echo "Début: $(date)"

time_start=$(date +%s.%N)
./build/zandoli --pcap "$PCAP_FILE" --output "$OUTPUT_DIR/test3_parallel" --formats json --config <(cat config.yaml | sed 's/parallel_workers: 0/parallel_workers: 4/')
time_end=$(date +%s.%N)
time3=$(echo "$time_end - $time_start" | bc)

echo "Fin: $(date)"
echo "Durée: ${time3}s"
echo ""

# Test 4: Configuration complète (métriques + parallèle)
echo "=== Test 4: Configuration complète ==="
echo "Métriques: activées (échantillonnage 1:1000)"
echo "Traitement: parallèle (8 workers)"
echo "Début: $(date)"

time_start=$(date +%s.%N)
./build/zandoli --pcap "$PCAP_FILE" --output "$OUTPUT_DIR/test4_full" --formats json --config <(cat config.yaml | sed 's/enable_metrics: false/enable_metrics: true/' | sed 's/metrics_sample_rate: 0/metrics_sample_rate: 1000/' | sed 's/parallel_workers: 0/parallel_workers: 8/')
time_end=$(date +%s.%N)
time4=$(echo "$time_end - $time_start" | bc)

echo "Fin: $(date)"
echo "Durée: ${time4}s"
echo ""

# Résumé des résultats
echo "=== RÉSUMÉ DES PERFORMANCES ==="
echo "Test 1 (Optimisé):     ${time1}s"
echo "Test 2 (+ Métriques):  ${time2}s"
echo "Test 3 (+ Parallèle):  ${time3}s"
echo "Test 4 (Complet):      ${time4}s"
echo ""

# Calcul des améliorations
if (( $(echo "$time1 > 0" | bc -l) )); then
    improvement2=$(echo "scale=2; (($time1 - $time2) / $time1) * 100" | bc)
    improvement3=$(echo "scale=2; (($time1 - $time3) / $time1) * 100" | bc)
    improvement4=$(echo "scale=2; (($time1 - $time4) / $time1) * 100" | bc)
    
    echo "=== AMÉLIORATIONS ==="
    echo "Test 2 vs Test 1: ${improvement2}%"
    echo "Test 3 vs Test 1: ${improvement3}%"
    echo "Test 4 vs Test 1: ${improvement4}%"
fi

echo ""
echo "Résultats détaillés dans: $OUTPUT_DIR"
echo "Test terminé: $(date)"



