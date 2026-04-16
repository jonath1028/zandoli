# Schémas Visuels Zandoli

> 📊 **Collection complète de diagrammes** pour comprendre l'architecture, les données et les flux de Zandoli.

## 🎯 Accès Rapide aux Schémas

| Document | Schémas Associés | Description |
|----------|------------------|-------------|
| **[ARCHITECTURE.md](ARCHITECTURE.md)** | [schemas/architecture.md](schemas/architecture.md) | Architecture système et modules |
| **[DATA_MODEL.md](DATA_MODEL.md)** | [schemas/data_model.md](schemas/data_model.md) | Modèle de données et structures |
| **[PIPELINE.md](PIPELINE.md)** | [schemas/pipeline.md](schemas/pipeline.md) | Pipeline de traitement |
| **[L2_PROTOCOLS.md](L2_PROTOCOLS.md)** | [schemas/protocols.md](schemas/protocols.md) | Protocoles supportés |
| **[EXPORTS.md](EXPORTS.md)** | [schemas/exports.md](schemas/exports.md) | Formats d'export |
| **[CLI.md](CLI.md)** | [schemas/configuration.md](schemas/configuration.md) | Configuration et CLI |

## 📋 Index Complet

### 🏗️ Architecture et Design
- **[schemas/architecture.md](schemas/architecture.md)** - Vue d'ensemble du système
  - Modules principaux et leurs responsabilités
  - Flux de données et interfaces
  - Séparation des couches (internal/ vs pkg/)
  - Gestion de la concurrence
  - Configuration et injection de dépendances

- **[schemas/pipeline.md](schemas/pipeline.md)** - Flux de traitement des données
  - Étapes du pipeline de capture à export
  - Modes d'exécution (passif/actif/combiné/PCAP)
  - Gestion de la concurrence avec goroutines
  - Dispatch des protocoles
  - Agrégation et corrélation des données

### 📊 Données et Structures
- **[schemas/data_model.md](schemas/data_model.md)** - Modèle de données complet
  - Structure Host et ses composants
  - Relations entre entités (Host, Anomaly, L2Signals, etc.)
  - Classification des rôles et gestion des conflits
  - Sérialisation JSON et gestion des VLANs
  - Métriques et statistiques

- **[schemas/protocols.md](schemas/protocols.md)** - Structures des protocoles
  - CDP, LLDP, STP, DHCP, ARP, mDNS
  - TCP Fingerprinting et options
  - Flux de parsing par protocole
  - Priorités et détection d'anomalies

### ⚙️ Configuration et Utilisation
- **[schemas/configuration.md](schemas/configuration.md)** - Configuration système
  - Structure de configuration complète
  - Modes d'exécution et paramètres de scan
  - Configuration des logs et exports
  - Validation et gestion des erreurs
  - Configuration par environnement

- **[schemas/exports.md](schemas/exports.md)** - Formats de sortie
  - Structures JSON, HTML, CSV, XML
  - Flux de génération des exports
  - Sélection des IPs et template HTML
  - Gestion des erreurs et métriques

## 🚀 Comment Utiliser ces Schémas

### Pour les Développeurs
1. **Comprendre l'architecture** : Commencer par [schemas/architecture.md](schemas/architecture.md)
2. **Analyser les données** : Étudier [schemas/data_model.md](schemas/data_model.md)
3. **Suivre le pipeline** : Visualiser [schemas/pipeline.md](schemas/pipeline.md)

### Pour les Utilisateurs
1. **Configuration** : Consulter [schemas/configuration.md](schemas/configuration.md)
2. **Formats de sortie** : Explorer [schemas/exports.md](schemas/exports.md)
3. **Protocoles supportés** : Découvrir [schemas/protocols.md](schemas/protocols.md)

### Pour les Administrateurs
1. **Architecture système** : [schemas/architecture.md](schemas/architecture.md)
2. **Gestion des erreurs** : [schemas/pipeline.md](schemas/pipeline.md#gestion-des-erreurs)
3. **Configuration avancée** : [schemas/configuration.md](schemas/configuration.md#configuration-par-environnement)

## 🛠️ Outils de Visualisation

### Visualisation en Ligne
- **GitHub/GitLab** : Rendu automatique des diagrammes Mermaid
- **Mermaid Live Editor** : https://mermaid.live/
- **VS Code** : Extension Mermaid Preview

### Validation et Test
- **Mermaid CLI** : Validation syntaxique
- **Documentation** : Cohérence avec le code source
- **Tests de rendu** : Vérification de la lisibilité

## 📝 Maintenance des Schémas

### Quand Mettre à Jour
- ✅ Modification de l'architecture
- ✅ Ajout de nouveaux protocoles
- ✅ Changement du modèle de données
- ✅ Nouveaux formats d'export
- ✅ Modification de la configuration

### Processus de Mise à Jour
1. **Identifier le changement** dans le code source
2. **Localiser le schéma** concerné
3. **Modifier le diagramme** Mermaid
4. **Tester le rendu** dans Mermaid Live Editor
5. **Vérifier la cohérence** avec la documentation

## 🔗 Liens Utiles

- **[schemas/README.md](schemas/README.md)** - Guide détaillé des schémas
- **[schemas/index.md](schemas/index.md)** - Index de navigation
- **[Mermaid Documentation](https://mermaid-js.github.io/mermaid/)** - Syntaxe des diagrammes

---

**💡 Conseil** : Utilisez ces schémas comme complément à la documentation textuelle. Ils offrent une vue d'ensemble rapide et facilitent la compréhension des concepts complexes de Zandoli.
