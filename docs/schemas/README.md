# Schémas de Documentation Zandoli

Ce répertoire contient des schémas visuels pour aider à comprendre la documentation de Zandoli. Ces diagrammes utilisent la syntaxe Mermaid pour une meilleure lisibilité.

## Fichiers Disponibles

### 📋 [architecture.md](architecture.md)
**Schémas d'architecture du système**
- Vue d'ensemble des modules
- Flux de données principal
- Séparation des couches (internal/ vs pkg/)
- Interfaces et dépendances
- Modes d'exécution
- Gestion de la concurrence
- Configuration et injection de dépendances

### 🗃️ [data_model.md](data_model.md)
**Schémas du modèle de données**
- Structure Host complète
- Relations entre entités
- Flux PacketEvent → Host
- Classification des rôles
- Gestion des conflits IP↔MAC
- Matrice de priorité des protocoles
- Structure des anomalies
- Sérialisation JSON
- Gestion des VLANs
- Métriques et statistiques

### 🔄 [pipeline.md](pipeline.md)
**Schémas du pipeline de traitement**
- Vue d'ensemble du pipeline
- Flux de données détaillé
- Modes d'exécution
- Gestion de la concurrence
- Pipeline de parsing
- Dispatch des protocoles
- Agrégation et corrélation
- Inférence de rôle
- Gestion des erreurs
- Métriques et performance

### 🌐 [protocols.md](protocols.md)
**Schémas des protocoles supportés**
- Vue d'ensemble des protocoles
- CDP (Cisco Discovery Protocol)
- LLDP (Link Layer Discovery Protocol)
- STP (Spanning Tree Protocol)
- DHCP (Dynamic Host Configuration Protocol)
- ARP (Address Resolution Protocol)
- mDNS (Multicast DNS)
- TCP Fingerprinting
- Flux de parsing par protocole
- Priorités des protocoles
- Détection des anomalies par protocole

### 📤 [exports.md](exports.md)
**Schémas des formats d'export**
- Vue d'ensemble des exports
- Structure JSON
- Structure HTML
- Structure CSV
- Flux de génération des exports
- Sélection des IPs pour l'export
- Template HTML détaillé
- Gestion des erreurs d'export
- Métriques d'export
- Configuration des exports

### ⚙️ [configuration.md](configuration.md)
**Schémas de configuration**
- Vue d'ensemble de la configuration
- Structure de configuration complète
- Modes d'exécution
- Configuration des scans
- Configuration des logs
- Configuration des exports
- Priorité de configuration
- Validation de configuration
- Configuration par environnement
- Gestion des erreurs de configuration
- Configuration des métriques

## Comment Utiliser ces Schémas

### 1. Visualisation en Ligne
Ces schémas peuvent être visualisés directement dans :
- **GitHub** : Les diagrammes Mermaid sont rendus automatiquement
- **GitLab** : Support natif des diagrammes Mermaid
- **Mermaid Live Editor** : https://mermaid.live/
- **VS Code** : Extension Mermaid Preview

### 2. Intégration dans la Documentation
Les schémas sont référencés dans les documents principaux :
- `docs/ARCHITECTURE.md` → `schemas/architecture.md`
- `docs/DATA_MODEL.md` → `schemas/data_model.md`
- `docs/PIPELINE.md` → `schemas/pipeline.md`
- `docs/L2_PROTOCOLS.md` → `schemas/protocols.md`
- `docs/EXPORTS.md` → `schemas/exports.md`
- `docs/CLI.md` → `schemas/configuration.md`

### 3. Mise à Jour des Schémas
Lors de modifications du code :
1. Identifier les changements dans l'architecture
2. Mettre à jour le schéma correspondant
3. Vérifier la cohérence avec la documentation
4. Tester le rendu Mermaid

## Conventions Utilisées

### Couleurs et Styles
- **Bleu** : Modules principaux
- **Vert** : Données et structures
- **Orange** : Processus et flux
- **Rouge** : Erreurs et anomalies
- **Violet** : Configuration et paramètres

### Symboles
- **🔵** : Modules/Composants
- **📊** : Données/Structures
- **⚡** : Processus/Flux
- **⚠️** : Erreurs/Anomalies
- **⚙️** : Configuration

### Types de Diagrammes
- **Graph TB/LR** : Hiérarchies et flux
- **Sequence** : Interactions temporelles
- **State** : États et transitions
- **Class** : Structures de données
- **ER** : Relations d'entités

## Contribution

Pour ajouter ou modifier des schémas :

1. **Identifier le besoin** : Quel concept nécessite une visualisation ?
2. **Choisir le type** : Quel diagramme Mermaid convient le mieux ?
3. **Créer le schéma** : Utiliser la syntaxe Mermaid appropriée
4. **Tester le rendu** : Vérifier dans Mermaid Live Editor
5. **Intégrer** : Ajouter au fichier approprié
6. **Documenter** : Mettre à jour ce README si nécessaire

## Outils Recommandés

### Édition
- **VS Code** + Extension Mermaid Preview
- **Mermaid Live Editor** (https://mermaid.live/)
- **Draw.io** (export Mermaid)

### Validation
- **Mermaid CLI** : Validation syntaxique
- **GitHub/GitLab** : Rendu automatique
- **Documentation** : Cohérence avec le code

### Maintenance
- **Scripts de validation** : Vérifier la syntaxe
- **Tests de rendu** : S'assurer de la lisibilité
- **Mise à jour automatique** : Synchroniser avec le code

---

**Note** : Ces schémas sont des représentations visuelles de la documentation. Ils doivent être maintenus en cohérence avec le code source et la documentation textuelle.
