# Index des Schémas Zandoli

## Navigation Rapide

| Document Principal | Schémas Associés | Description |
|-------------------|------------------|-------------|
| [ARCHITECTURE.md](../ARCHITECTURE.md) | [architecture.md](architecture.md) | Architecture système et modules |
| [DATA_MODEL.md](../DATA_MODEL.md) | [data_model.md](data_model.md) | Modèle de données et structures |
| [PIPELINE.md](../PIPELINE.md) | [pipeline.md](pipeline.md) | Pipeline de traitement |
| [L2_PROTOCOLS.md](../L2_PROTOCOLS.md) | [protocols.md](protocols.md) | Protocoles supportés |
| [EXPORTS.md](../EXPORTS.md) | [exports.md](exports.md) | Formats d'export |
| [CLI.md](../CLI.md) | [configuration.md](configuration.md) | Configuration et CLI |

## Schémas par Catégorie

### 🏗️ Architecture et Design
- **[architecture.md](architecture.md)** - Vue d'ensemble du système
- **[pipeline.md](pipeline.md)** - Flux de traitement des données

### 📊 Données et Structures
- **[data_model.md](data_model.md)** - Modèle de données complet
- **[protocols.md](protocols.md)** - Structures des protocoles

### ⚙️ Configuration et Utilisation
- **[configuration.md](configuration.md)** - Configuration système
- **[exports.md](exports.md)** - Formats de sortie

## Liens Croisés

### Architecture → Données
- [Architecture des modules](architecture.md#vue-densemble-des-modules) → [Structure Host](data_model.md#structure-host---vue-densemble)
- [Flux de données](architecture.md#flux-de-données-principal) → [Relations entre entités](data_model.md#relations-entre-entités)

### Pipeline → Protocoles
- [Dispatch des protocoles](pipeline.md#dispatch-des-protocoles) → [Vue d'ensemble des protocoles](protocols.md#vue-densemble-des-protocoles)
- [Parsing spécialisé](pipeline.md#pipeline-de-parsing) → [Flux de parsing par protocole](protocols.md#flux-de-parsing-par-protocole)

### Configuration → Exports
- [Configuration des exports](configuration.md#configuration-des-exports) → [Vue d'ensemble des exports](exports.md#vue-densemble-des-exports)
- [Formats disponibles](configuration.md#configuration-des-exports) → [Structure des formats](exports.md#structure-json)

## Utilisation des Schémas

### Pour les Développeurs
1. **Comprendre l'architecture** : Commencer par [architecture.md](architecture.md)
2. **Analyser les données** : Étudier [data_model.md](data_model.md)
3. **Suivre le pipeline** : Visualiser [pipeline.md](pipeline.md)

### Pour les Utilisateurs
1. **Configuration** : Consulter [configuration.md](configuration.md)
2. **Formats de sortie** : Explorer [exports.md](exports.md)
3. **Protocoles supportés** : Découvrir [protocols.md](protocols.md)

### Pour les Administrateurs
1. **Architecture système** : [architecture.md](architecture.md)
2. **Gestion des erreurs** : [pipeline.md](pipeline.md#gestion-des-erreurs)
3. **Configuration avancée** : [configuration.md](configuration.md#configuration-par-environnement)

## Mise à Jour des Schémas

### Quand Mettre à Jour
- ✅ Modification de l'architecture
- ✅ Ajout de nouveaux protocoles
- ✅ Changement du modèle de données
- ✅ Nouveaux formats d'export
- ✅ Modification de la configuration

### Comment Mettre à Jour
1. **Identifier le changement** dans le code source
2. **Localiser le schéma** concerné
3. **Modifier le diagramme** Mermaid
4. **Tester le rendu** dans Mermaid Live Editor
5. **Vérifier la cohérence** avec la documentation

### Outils de Validation
- **Mermaid Live Editor** : https://mermaid.live/
- **VS Code Extension** : Mermaid Preview
- **GitHub/GitLab** : Rendu automatique

## Exemples d'Utilisation

### Comprendre un Bug
1. Identifier le composant dans [architecture.md](architecture.md)
2. Suivre le flux dans [pipeline.md](pipeline.md)
3. Vérifier la structure dans [data_model.md](data_model.md)

### Ajouter une Fonctionnalité
1. Analyser l'impact architectural dans [architecture.md](architecture.md)
2. Modifier le pipeline dans [pipeline.md](pipeline.md)
3. Adapter la configuration dans [configuration.md](configuration.md)

### Optimiser les Performances
1. Identifier les goulots dans [pipeline.md](pipeline.md#métriques-et-performance)
2. Analyser les métriques dans [data_model.md](data_model.md#métriques-et-statistiques)
3. Ajuster la configuration dans [configuration.md](configuration.md#configuration-des-métriques)

---

**💡 Conseil** : Utilisez ces schémas comme complément à la documentation textuelle. Ils offrent une vue d'ensemble rapide et facilitent la compréhension des concepts complexes.
