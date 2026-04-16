# Sécurité Zandoli

## Vue d'ensemble

Zandoli est conçu comme un outil d'analyse réseau **passif** et **non-intrusif**. Il n'exploite aucune vulnérabilité et respecte les standards des protocoles réseau. Cette approche garantit une utilisation sûre en environnement de production.

## Modèle de Sécurité

### Principe Fondamental
**Zandoli ne génère aucune activité malveillante** - il observe et analyse uniquement le trafic existant.

### Modes d'Opération

#### Mode Passif (Recommandé)
- **Lecture seule** du trafic réseau
- **Aucun paquet généré** par Zandoli
- **Aucun impact** sur le réseau
- **Sûr en production** sans restriction

#### Mode Actif (Contrôlé)
- **ARP** : Requêtes ARP standard (RFC 826)
- **SYN** : Connexions TCP standard (RFC 793)
- **Régulation** : Débit contrôlé et configurable
- **Respect** : Pas de flood, pas d'exploitation

## Protection des Données

### Données Sensibles

#### Adresses IP et MAC
- **Collecte** : Nécessaire pour l'analyse réseau
- **Stockage** : Chiffrement recommandé pour les rapports
- **Anonymisation** : Option disponible (à implémenter)

#### Informations d'Équipements
- **Hostnames** : Peuvent révéler l'infrastructure
- **Versions** : Informations de sécurité sensibles
- **Topologie** : Architecture réseau privée

#### Recommandations
```bash
# Stockage sécurisé des rapports
chmod 600 output/scan_*/
gpg --encrypt --recipient admin@company.com report.html
```

### Logs et Traces

#### Contenu des Logs
- **Adresses IP/MAC** : Présentes dans les logs
- **Hostnames** : Visibles dans les messages
- **Erreurs** : Peuvent révéler des informations système

#### Sécurisation
```bash
# Permissions restrictives
chmod 600 output/log.txt

# Rotation sécurisée
logrotate -f /etc/logrotate.d/zandoli

# Suppression automatique
find output/ -name "*.log" -mtime +30 -delete
```

## Formats d'Export

### HTML
- **Format** : Rapport interactif avec filtres et recherche
- **Usage** : Analyse visuelle des résultats

### CSV
- **Format** : Données tabulaires avec délimiteur point-virgule
- **Usage** : Analyse dans Excel ou outils de traitement

### JSON
- **Format** : Structure de données pour intégration API
- **Usage** : Intégration avec d'autres outils

## Considérations Opérationnelles

### Permissions Requises

#### Écoute Réseau
```bash
# Droits root nécessaires
sudo ./zandoli --passive --interface eth0

# Ou capabilities Linux
sudo setcap cap_net_raw,cap_net_admin+ep ./zandoli
```

#### Scan Actif
```bash
# Droits root obligatoires
sudo ./zandoli --active --interface eth0

# Pas de capabilities alternatives (sécurité)
```

### Détection par les IDS/IPS

#### Signatures Possibles
- **ARP** : Volume de requêtes ARP
- **SYN** : Scan de ports TCP
- **Patterns** : Comportement de scan

#### Réduction de la Détection
```bash
# Débit réduit
./zandoli --active --arp-max-per-sec 1

# Délais augmentés
./zandoli --active --burst-min-delay 1000 --burst-max-delay 5000
```

### Impact sur le Réseau

#### Mode Passif
- **Bande passante** : Aucun impact
- **Latence** : Aucun impact
- **Disponibilité** : Aucun impact

#### Mode Actif
- **ARP** : ~1-10 paquets/seconde (négligeable)
- **SYN** : ~1-5 connexions/seconde (négligeable)
- **Régulation** : Débit configurable et limité

## Bonnes Pratiques

### Déploiement en Production

#### Configuration Sécurisée
```yaml
# config.yaml pour production
logging:
  verbose: false    # Pas de logs détaillés
  quiet: true       # Logs minimaux
  paranoid: false   # Garder les logs pour audit

scan:
  arp_max_per_sec: 1    # Débit très conservateur
  burst_min_delay_ms: 1000 # Délais importants
```

#### Surveillance
```bash
# Monitoring des ressources
top -p $(pgrep zandoli)

# Surveillance des logs
tail -f output/log.txt | grep -i error

# Vérification des permissions
ls -la output/scan_*/
```

### Tests de Pénétration

#### Utilisation Autorisée
- **Reconnaissance** : Cartographie réseau autorisée
- **Audit** : Tests de sécurité internes
- **Compliance** : Vérifications réglementaires

#### Restrictions
- **Pas d'exploitation** : Zandoli ne teste pas les vulnérabilités
- **Pas d'attaque** : Aucune activité malveillante
- **Respect** : Conformité aux politiques de sécurité

### Conformité Réglementaire

#### RGPD
- **Minimisation** : Collecte uniquement des données nécessaires
- **Rétention** : Politique de suppression des rapports recommandée

#### PCI DSS
- **Scope** : Délimitation des réseaux de paiement
- **Monitoring** : Surveillance continue
- **Audit** : Traçabilité des accès

#### ISO 27001
- **Classification** : Données sensibles identifiées
- **Protection** : Mesures de sécurité appropriées
- **Monitoring** : Surveillance des accès

## Limitations et Risques

### Limitations Techniques

#### Détection
- **Chiffrement** : Contenu des paquets chiffrés non analysé
- **Tunnels** : Trafic encapsulé non décapsulé
- **IPv6** : Support partiel (en développement)

#### Performance
- **Débit** : Limité par les performances de parsing
- **Mémoire** : Consommation proportionnelle au trafic
- **CPU** : Parsing intensif sur gros volumes

### Risques Identifiés

#### Faible Risque
- **Détection** : Possibilité de détection par les IDS
- **Logs** : Fuite d'informations via les logs
- **Stockage** : Rapports non sécurisés

#### Risques Mitigés
- **Permissions** : Droits root nécessaires (contrôle d'accès)
- **Régulation** : Débit limité et configurable
- **Mode passif** : Option sans impact réseau

## Recommandations de Sécurité

### Déploiement
1. **Test** : Validation en environnement de test
2. **Permissions** : Accès restreint aux administrateurs
3. **Monitoring** : Surveillance des exécutions
4. **Audit** : Traçabilité des analyses

### Maintenance
1. **Mises à jour** : Veille de sécurité continue
2. **Patches** : Application des corrections
3. **Tests** : Validation après mise à jour
4. **Documentation** : Mise à jour des procédures

### Formation
1. **Utilisateurs** : Formation aux bonnes pratiques
2. **Administrateurs** : Formation technique approfondie
3. **Sécurité** : Sensibilisation aux risques
4. **Procédures** : Documentation des processus

## Incident Response

### En Cas de Détection
1. **Arrêt** : Arrêt immédiat du scanner
2. **Analyse** : Investigation des logs
3. **Communication** : Information des équipes
4. **Correction** : Mise en place de mesures

### En Cas d'Intrusion
1. **Isolation** : Déconnexion du système
2. **Préservation** : Conservation des preuves
3. **Analyse** : Investigation forensique
4. **Restauration** : Remise en état sécurisée

## Audit et Compliance

### Logs d'Audit
```bash
# Audit des exécutions
grep "scan completed" output/log.txt | tail -10

# Audit des accès
grep "permission denied" output/log.txt

# Audit des erreurs
grep "error" output/log.txt | wc -l
```

### Rapports de Conformité
- **Activité** : Log des analyses effectuées
- **Accès** : Traçabilité des utilisateurs
- **Résultats** : Inventaire des équipements
- **Anomalies** : Détection des comportements suspects

---

**Voir aussi** : [Architecture](ARCHITECTURE.md) | [Logging](LOGGING.md) | [Dépannage](TROUBLESHOOTING.md) | [Contribution](../CONTRIBUTING.md)
