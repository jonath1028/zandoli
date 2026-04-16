# Dépannage Zandoli

## Vue d'ensemble

Ce guide couvre les problèmes courants rencontrés lors de l'utilisation de Zandoli, leurs causes et leurs solutions.

## Erreurs de Configuration

### Interface Réseau Inexistante
**Erreur** : `Interface 'eth0' not found`

**Causes** :
- Interface réseau inexistante
- Interface désactivée
- Permissions insuffisantes

**Solutions** :
```bash
# Lister les interfaces disponibles
ip link show
# ou
ifconfig -a

# Utiliser une interface existante
./zandoli --passive --interface wlan0

# Activer l'interface si nécessaire
sudo ip link set eth0 up
```

### Permissions Insuffisantes
**Erreur** : `Permission denied` ou `Operation not permitted`

**Causes** :
- Pas de droits root pour l'écoute réseau
- Pas de droits root pour le scan actif

**Solutions** :
```bash
# Utiliser sudo pour les modes nécessitant des privilèges
sudo ./zandoli --passive --interface eth0

# Vérifier les capabilities si disponibles
sudo setcap cap_net_raw,cap_net_admin+ep ./zandoli
```

### Fichier de Configuration Invalide
**Erreur** : `Config load error: yaml: unmarshal errors`

**Causes** :
- Syntaxe YAML incorrecte
- Fichier corrompu
- Encodage incorrect

**Solutions** :
```bash
# Valider la syntaxe YAML
python -c "import yaml; yaml.safe_load(open('config.yaml'))"

# Utiliser la configuration par défaut
./zandoli --passive  # Ignore config.yaml si corrompu

# Recréer le fichier de configuration
rm config.yaml
./zandoli --help  # Affiche les valeurs par défaut
```

## Erreurs de PCAP

### PCAP Corrompu
**Erreur** : `pcap: corrupted file` ou `invalid pcap header`

**Causes** :
- Fichier PCAP tronqué
- Format non supporté
- Corruption lors du transfert

**Solutions** :
```bash
# Vérifier l'intégrité du fichier
file testdata/traffic_lab.pcap

# Tester avec un autre PCAP
./zandoli --pcap testdata/empty.pcap

# Utiliser tcpdump pour recréer le PCAP
tcpdump -r corrupted.pcap -w fixed.pcap
```

### PCAP Vide
**Erreur** : `No packets found` ou `Empty capture`

**Causes** :
- Fichier PCAP vide
- Filtres trop restrictifs
- Période sans trafic

**Solutions** :
```bash
# Vérifier la taille du fichier
ls -la testdata/empty.pcap

# Utiliser un PCAP avec du trafic
./zandoli --pcap testdata/traffic_lab.pcap

# Vérifier le contenu avec tcpdump
tcpdump -r testdata/empty.pcap -c 10
```

### PCAP avec Sections Multiples
**Erreur** : `multiple pcapng sections not supported`

**Causes** :
- Fichier PCAPNG avec plusieurs sections
- Fusion de captures multiples

**Solutions** :
```bash
# Extraire une seule section
tshark -r input.pcapng -w output.pcap

# Utiliser un PCAP simple
./zandoli --pcap testdata/traffic_lab.pcap
```

## Erreurs de Parsing

### Paquets Tronqués
**Erreur** : `truncated packet` (dans les logs)

**Causes** :
- MTU insuffisant
- Capture partielle
- Paquets fragmentés

**Solutions** :
```bash
# Augmenter la taille de capture
sudo ./zandoli --passive --interface eth0

# Vérifier la MTU
ip link show eth0

# Capturer avec une taille plus grande
tcpdump -i eth0 -s 0 -w capture.pcap
```

### Protocoles Non Reconnus
**Erreur** : `unknown protocol` (dans les logs)

**Causes** :
- Protocole non implémenté
- Version de protocole non supportée
- Paquets malformés

**Solutions** :
```bash
# Activer les logs de debug pour voir les détails
./zandoli --pcap file.pcap --verbose

# Vérifier avec tcpdump
tcpdump -r file.pcap -v

# Signaler le protocole manquant
# (créer une issue GitHub)
```

## Erreurs de Scan Actif

### ARP Non Répondu
**Symptôme** : Peu ou pas d'hôtes découverts par ARP

**Causes** :
- Hôtes avec firewall ARP
- Réseau avec protection anti-ARP
- TTL incorrect

**Solutions** :
```bash
# Ajuster le TTL
./zandoli --active --ttl 64

# Réduire la vitesse de scan
./zandoli --active --arp-max-per-sec 1
```

### SYN Timeout
**Erreur** : `SYN timeout` (dans les logs)

**Causes** :
- Ports fermés
- Firewall bloquant
- Timeout trop court

**Solutions** :
```bash
# Augmenter le timeout
./zandoli --active --SYN --syn-timeout 5000

# Réduire le nombre de ports
./zandoli --active --SYN --syn-ports "80,443"

# Vérifier la connectivité manuellement
telnet target_ip 80
```

### Débit Trop Élevé
**Erreur** : `rate limit exceeded` (dans les logs)

**Causes** :
- Scan trop agressif
- Protection anti-DDoS
- Interface surchargée

**Solutions** :
```bash
# Réduire le débit
./zandoli --active --arp-max-per-sec 1 --arp-burst 5

# Augmenter les délais
./zandoli --active --burst-min-delay 1000 --burst-max-delay 5000
```

## Erreurs d'Export

### CSV Delimiter
**Erreur** : `CSV delimiter conflict` (dans Excel)

**Causes** :
- Délimiteur `;` non reconnu
- Encodage incorrect
- Guillemets mal échappés

**Solutions** :
```bash
# Ouvrir avec un éditeur de texte
cat hosts.csv | head -5

# Importer dans Excel avec le bon délimiteur
# Excel > Données > Texte/CSV > Délimiteur: Point-virgule

# Convertir en délimiteur virgule si nécessaire
sed 's/;/,/g' hosts.csv > hosts_comma.csv
```

### Encodage JSON
**Erreur** : `invalid character` lors du parsing JSON

**Causes** :
- Encodage non UTF-8
- Caractères spéciaux non échappés
- JSON malformé

**Solutions** :
```bash
# Vérifier l'encodage
file hosts.json

# Valider la syntaxe JSON
python -m json.tool hosts.json

# Corriger l'encodage
iconv -f ISO-8859-1 -t UTF-8 hosts.json > hosts_utf8.json
```

### Fichiers de Sortie Verrouillés
**Erreur** : `file locked` ou `permission denied`

**Causes** :
- Fichiers ouverts dans Excel
- Permissions insuffisantes
- Répertoire en lecture seule

**Solutions** :
```bash
# Vérifier les processus utilisant les fichiers
lsof output/scan_*/hosts.csv

# Changer les permissions
chmod 755 output/scan_*/

# Utiliser un autre répertoire
./zandoli --pcap file.pcap --output-dir /tmp/results
```

## Erreurs de Performance

### Mémoire Insuffisante
**Erreur** : `out of memory` ou `allocation failed`

**Causes** :
- PCAP très volumineux
- Trop d'hôtes simultanés
- Fuite mémoire

**Solutions** :
```bash
# Utiliser un PCAP plus petit
./zandoli --pcap testdata/small.pcap

# Surveiller l'utilisation mémoire
top -p $(pgrep zandoli)

# Augmenter la limite mémoire
ulimit -v 2097152  # 2GB
```

### CPU Surchargé
**Symptôme** : Scanner très lent, CPU à 100%

**Causes** :
- Parsing intensif
- Trop de goroutines
- PCAP volumineux

**Solutions** :
```bash
# Réduire la verbosité des logs
./zandoli --pcap file.pcap --quiet

# Utiliser un PCAP plus petit
split -b 100M large.pcap small_part_

# Limiter le nombre de workers
# (modification du code nécessaire)
```

## Problèmes Réseau

### Hôte Infra Apparaît Client/Serveur
**Symptôme** : Routeur ou switch classé comme client

**Causes** :
- Pas de signaux L2 (CDP/LLDP/STP)
- OUI non reconnu comme réseau
- Comportement ambigu

**Solutions** :
```bash
# Vérifier les signaux L2 dans les logs
./zandoli --pcap file.pcap --verbose | grep -i "cdp\|lldp\|stp"

# Ajouter le vendor au fichier OUI
echo "aa:bb:cc:dd:ee:ff Cisco Systems" >> oui.txt

# Forcer la classification via configuration
# (modification du code nécessaire)
```

### IP Publique/Privée Incorrecte
**Symptôme** : Classification IP incorrecte

**Causes** :
- Plages CGNAT non reconnues
- Configuration réseau non standard
- Bug dans la détection

**Solutions** :
```bash
# Vérifier la classification
./zandoli --pcap file.pcap --verbose | grep -i "public\|private"

# Vérifier manuellement
ipcalc 100.64.0.1/10

# Signaler le bug avec les détails
```

### VLANs Non Détectés
**Symptôme** : Tous les hôtes sur VLAN 0

**Causes** :
- Pas de tags 802.1Q
- Interface sans vue VLAN
- Filtres trop restrictifs

**Solutions** :
```bash
# Vérifier les VLANs dans le PCAP
tcpdump -r file.pcap -v | grep -i vlan

# Utiliser une interface avec vue VLAN
# (configuration du port miroir)

# Vérifier les filtres BPF
# (modification du code nécessaire)
```

## Problèmes de Logs

### Logs Manquants
**Symptôme** : Aucun fichier de log généré

**Causes** :
- Permissions insuffisantes
- Répertoire inexistant
- Configuration de logging incorrecte

**Solutions** :
```bash
# Vérifier les permissions
ls -la output/
mkdir -p output
chmod 755 output

# Vérifier l'espace disque
df -h output/

# Tester avec un PCAP simple
./zandoli --pcap testdata/empty.pcap
```

### Logs Trop Verbose
**Symptôme** : Fichiers de log énormes

**Causes** :
- Niveau de log trop élevé
- Trop de paquets traités
- Pas de rotation

**Solutions** :
```bash
# Réduire la verbosité
./zandoli --quiet --pcap file.pcap

# Filtrer les logs
grep -v "packet processed" output/log.txt > filtered.log

# Implémenter la rotation
# (modification du code nécessaire)
```

## FAQ Réseau

### Q: Pourquoi un équipement infra apparaît comme client/serveur ?
**R** : Cela peut arriver si :
- Pas de signaux L2 (CDP/LLDP/STP) capturés
- OUI du vendor non reconnu comme réseau
- Comportement ambigu (fait du routing ET des requêtes HTTP)

**Solutions** :
- Vérifier la capture des protocoles L2
- Ajouter le vendor au fichier OUI
- Augmenter la durée d'écoute

### Q: Comment activer la résolution OUI ?
**R** : Utiliser le flag `--oui-file` :
```bash
./zandoli --pcap file.pcap --oui-file /path/to/oui.txt
```

### Q: Pourquoi une IP est classée publique/privée incorrectement ?
**R** : Vérifier la plage d'adresse :
- **Privées** : 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
- **CGNAT** : 100.64.0.0/10
- **Publiques** : Tout le reste

### Q: Comment capturer le trafic sur plusieurs VLANs ?
**R** : Configurer le port miroir pour inclure les VLANs :
```bash
# Sur un switch Cisco
monitor session 1 source vlan 1,10,20
monitor session 1 destination interface Gi0/1
```

## Support et Contribution

### Signaler un Bug
1. **Vérifier** que le bug n'est pas déjà connu
2. **Collecter** les informations :
   - Version de Zandoli
   - Commande utilisée
   - Fichiers de log
   - PCAP de test (si applicable)
3. **Créer** une issue GitHub avec le template

### Informations Utiles pour le Support
```bash
# Version et build
./zandoli --help

# Informations système
uname -a
go version

# Configuration réseau
ip addr show
route -n

# Logs détaillés
./zandoli --pcap file.pcap --verbose 2>&1 | tee debug.log
```

### Tests de Régression
```bash
# Tests unitaires
go test ./...

# Tests d'intégration
go test -tags integration ./...

# Tests de performance
go test -bench=. ./pkg/sniffer/
```

---

**Voir aussi** : [CLI](CLI.md) | [Logging](LOGGING.md) | [Architecture](ARCHITECTURE.md) | [Contribution](../CONTRIBUTING.md)
