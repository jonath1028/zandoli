#!/bin/bash

# Script de test des optimisations Zandoli
# Vérifie que toutes les optimisations fonctionnent correctement

set -e

echo "=== Test des optimisations Zandoli ==="
echo "Date: $(date)"
echo ""

# Configuration
PCAP_FILE="testdata/cdp.pcap"
OUTPUT_DIR="optimization_test_$(date +%Y%m%d_%H%M%S)"

# Créer le répertoire de sortie
mkdir -p "$OUTPUT_DIR"

echo "Fichier PCAP: $PCAP_FILE"
echo "Répertoire de sortie: $OUTPUT_DIR"
echo ""

# Test 1: Configuration par défaut (optimisée)
echo "=== Test 1: Configuration par défaut (optimisée) ==="
echo "Métriques: désactivées, Traitement: séquentiel"
echo "Début: $(date)"

start_time=$(date +%s.%N)
./build/zandoli --pcap "$PCAP_FILE" --output-dir "$OUTPUT_DIR/test1_default" --quiet
end_time=$(date +%s.%N)
time1=$(echo "$end_time - $start_time" | bc)

echo "Fin: $(date)"
echo "Durée: ${time1}s"
echo ""

# Test 2: Avec métriques activées
echo "=== Test 2: Avec métriques activées ==="
echo "Métriques: activées (échantillonnage 1:10), Traitement: séquentiel"
echo "Début: $(date)"

start_time=$(date +%s.%N)
./build/zandoli --pcap "$PCAP_FILE" --config <(cat config.yaml | sed 's/enable_metrics: false/enable_metrics: true/' | sed 's/metrics_sample_rate: 0/metrics_sample_rate: 10/') --output-dir "$OUTPUT_DIR/test2_metrics" --quiet
end_time=$(date +%s.%N)
time2=$(echo "$end_time - $start_time" | bc)

echo "Fin: $(date)"
echo "Durée: ${time2}s"
echo ""

# Test 3: Avec traitement parallèle
echo "=== Test 3: Avec traitement parallèle ==="
echo "Métriques: désactivées, Traitement: parallèle (4 workers)"
echo "Début: $(date)"

start_time=$(date +%s.%N)
./build/zandoli --pcap "$PCAP_FILE" --config <(cat config.yaml | sed 's/parallel_workers: 0/parallel_workers: 4/') --output-dir "$OUTPUT_DIR/test3_parallel" --quiet
end_time=$(date +%s.%N)
time3=$(echo "$end_time - $start_time" | bc)

echo "Fin: $(date)"
echo "Durée: ${time3}s"
echo ""

# Test 4: Configuration complète
echo "=== Test 4: Configuration complète ==="
echo "Métriques: activées (échantillonnage 1:100), Traitement: parallèle (8 workers)"
echo "Début: $(date)"

start_time=$(date +%s.%N)
./build/zandoli --pcap "$PCAP_FILE" --config <(cat config.yaml | sed 's/enable_metrics: false/enable_metrics: true/' | sed 's/metrics_sample_rate: 0/metrics_sample_rate: 100/' | sed 's/parallel_workers: 0/parallel_workers: 8/') --output-dir "$OUTPUT_DIR/test4_full" --quiet
end_time=$(date +%s.%N)
time4=$(echo "$end_time - $start_time" | bc)

echo "Fin: $(date)"
echo "Durée: ${time4}s"
echo ""

# Vérification des résultats
echo "=== Vérification des résultats ==="
for test in test1_default test2_metrics test3_parallel test4_full; do
    if [ -f "$OUTPUT_DIR/$test/scan_"*/hosts.json ]; then
        echo "✅ $test: Fichier de sortie généré"
    else
        echo "❌ $test: Fichier de sortie manquant"
    fi
done
echo ""

# Résumé des performances
echo "=== RÉSUMÉ DES PERFORMANCES ==="
echo "Test 1 (Défaut):     ${time1}s"
echo "Test 2 (+ Métriques): ${time2}s"
echo "Test 3 (+ Parallèle): ${time3}s"
echo "Test 4 (Complet):    ${time4}s"
echo ""

# Vérification du fonctionnement parallèle
echo "=== Vérification du traitement parallèle ==="
if grep -q "Using parallel packet processing" "$OUTPUT_DIR/test3_parallel/scan_"*/log.txt 2>/dev/null; then
    echo "✅ Traitement parallèle activé correctement"
else
    echo "❌ Traitement parallèle non détecté"
fi

if grep -q "Starting parallel packet processing" "$OUTPUT_DIR/test3_parallel/scan_"*/log.txt 2>/dev/null; then
    echo "✅ Workers parallèles démarrés"
else
    echo "❌ Workers parallèles non démarrés"
fi
echo ""

# Vérification des métriques
echo "=== Vérification des métriques ==="
if grep -q "enableMetrics.*true" "$OUTPUT_DIR/test2_metrics/scan_"*/log.txt 2>/dev/null; then
    echo "✅ Métriques activées correctement"
else
    echo "❌ Métriques non activées"
fi
echo ""

echo "=== Test terminé ==="
echo "Résultats détaillés dans: $OUTPUT_DIR"
echo "Test terminé: $(date)"



