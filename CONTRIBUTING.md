# Guide de Contribution Zandoli

## Vue d'ensemble

Ce guide explique comment contribuer au projet Zandoli, les conventions de code, et le processus de contribution.

## Prérequis Développeur

### Environnement de Développement
- **Go** ≥ 1.24.2
- **Git** pour le versioning
- **Linux/Unix** (testé sur Kali Linux)
- **Make** pour les tâches de build
- **Docker** (optionnel) pour les tests

### Outils Recommandés
```bash
# Installation des outils
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
go install github.com/stretchr/testify/assert@latest
go install golang.org/x/tools/cmd/goimports@latest
```

### Configuration Git
```bash
# Configuration des hooks (optionnel)
git config core.hooksPath .githooks
chmod +x .githooks/pre-commit
```

## Architecture et Conventions

### Structure du Projet
```
zandoli/
├── cmd/                    # Applications
│   ├── zandoli/           # CLI principal
│   └── tools/             # Outils utilitaires
├── internal/              # Code privé (config, logger, validation)
├── pkg/                   # Code réutilisable
│   ├── analyzer/          # Analyse des protocoles
│   ├── exporter/          # Formats d'export
│   ├── model/             # Structures de données
│   ├── orchestrator/      # Coordination du pipeline
│   ├── scanner/           # Scans actifs
│   ├── sniffer/           # Capture de paquets
│   ├── ui/                # Interface utilisateur
│   └── utils/             # Utilitaires communs
├── testdata/              # Données de test
├── docs/                  # Documentation
└── script/                # Scripts utilitaires
```

### Règles d'Architecture

#### Séparation `internal/` vs `pkg/`
- **`internal/`** : Configuration, logging, validation uniquement
- **`pkg/`** : Code métier réutilisable et modulaire
- **Interdiction** : Aucune dépendance de `internal/` vers `pkg/`

#### Anti-Redondance
- **Helpers communs** : Centralisés dans `pkg/utils/`
- **Fonctions dupliquées** : Interdites, factorisation obligatoire
- **Exemples** :
  - `containsString` → `pkg/utils/slices.go::ContainsString`
  - `mergeIntSlices` → `pkg/utils/slices.go::{MergeIntUnique, MergeStrUnique}`
  - `getStrengthPriority` → `pkg/model/strength.go::StrengthPriority`

## Standards de Code

### Style Go
```bash
# Formatage automatique
go fmt ./...

# Imports organisés
goimports -w .

# Linting complet
golangci-lint run
```

### Conventions de Nommage
- **Packages** : minuscules, courts (`analyzer`, `exporter`)
- **Types** : PascalCase (`Host`, `CDPInfo`)
- **Fonctions** : PascalCase pour export, camelCase pour privé
- **Variables** : camelCase (`hostCount`, `isActive`)
- **Constantes** : PascalCase (`DefaultTTL`, `MaxRetries`)

### Documentation
```go
// Package analyzer provides protocol analysis capabilities.
package analyzer

// InferRole analyzes a host and infers its role with confidence.
// It returns a RoleInfo struct containing the inferred role,
// confidence level, and signals used for inference.
func InferRole(host *model.Host) *model.RoleInfo {
    // Implementation...
}
```

### Gestion d'Erreurs
```go
// ✅ Bon : Propagation avec contexte
func ParsePacket(data []byte) (*Packet, error) {
    if len(data) < 14 {
        return nil, fmt.Errorf("packet too short: %d bytes", len(data))
    }
    // ...
}

// ❌ Mauvais : Panic ou erreur générique
func ParsePacket(data []byte) *Packet {
    if len(data) < 14 {
        panic("invalid packet")
    }
    // ...
}
```

### Concurrence
```go
// ✅ Bon : Canaux et goroutines contrôlées
func ProcessPackets(input <-chan PacketEvent) <-chan ParsedRecord {
    output := make(chan ParsedRecord, 100)
    go func() {
        defer close(output)
        for packet := range input {
            if record := parsePacket(packet); record != nil {
                output <- *record
            }
        }
    }()
    return output
}

// ❌ Mauvais : Goroutines non contrôlées
func ProcessPackets(input <-chan PacketEvent) {
    for packet := range input {
        go func(p PacketEvent) {
            // Goroutine non contrôlée
        }(packet)
    }
}
```

## Tests

### Tests Unitaires
```bash
# Exécution des tests
go test ./...

# Tests avec couverture
go test -cover ./...

# Tests spécifiques
go test -v ./pkg/analyzer -run TestInferRole
```

### Tests d'Intégration
```bash
# Tests d'intégration (nécessitent des PCAP)
go test -tags integration ./...

# Tests de performance
go test -bench=. ./pkg/sniffer/
```

### Exemples de Tests
```go
func TestInferRole(t *testing.T) {
    tests := []struct {
        name     string
        host     *model.Host
        expected *model.RoleInfo
    }{
        {
            name: "CDP router should be network",
            host: &model.Host{
                L2Signals: model.L2SignalsInfo{CDP: true},
                CDP: &model.CDPInfo{DeviceID: "Router-01"},
            },
            expected: &model.RoleInfo{
                Role:       "reseau",
                Confidence: 100,
                Signals:    []string{"L2_PRESENT"},
            },
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            result := InferRole(tt.host)
            assert.Equal(t, tt.expected, result)
        })
    }
}
```

## Processus de Contribution

### 1. Fork et Clone
```bash
# Fork du repository sur GitHub
# Puis clone de votre fork
git clone https://github.com/your-username/zandoli.git
cd zandoli
```

### 2. Branche de Développement
```bash
# Créer une branche pour votre feature
git checkout -b feature/new-protocol-parser
# ou
git checkout -b fix/csv-encoding-issue
```

### 3. Développement
```bash
# Développement avec tests
go test ./...
go build ./cmd/zandoli

# Validation du style
golangci-lint run
```

### 4. Commit et Push
```bash
# Commits atomiques avec messages clairs
git add .
git commit -m "feat: add LLDP protocol parser

- Parse LLDP TLVs 1, 2, 5, 7
- Add LLDPInfo struct to model
- Update role inference for LLDP
- Add unit tests for LLDP parsing"

git push origin feature/new-protocol-parser
```

### 5. Pull Request
- **Titre** : Description claire et concise
- **Description** : Contexte, changements, tests
- **Template** : Utiliser le template GitHub
- **Reviewers** : Assigner les reviewers appropriés

## Conventions de Commit

### Format des Messages
```
<type>(<scope>): <description>

<body>

<footer>
```

### Types de Commit
- **feat** : Nouvelle fonctionnalité
- **fix** : Correction de bug
- **docs** : Documentation uniquement
- **style** : Formatage, pas de changement de code
- **refactor** : Refactoring sans changement de fonctionnalité
- **test** : Ajout ou modification de tests
- **chore** : Tâches de maintenance

### Exemples
```bash
# Fonctionnalité
git commit -m "feat(analyzer): add STP protocol parser"

# Bug fix
git commit -m "fix(exporter): correct CSV delimiter escaping"

# Documentation
git commit -m "docs: update CLI reference with new flags"

# Refactoring
git commit -m "refactor(utils): consolidate IP helper functions"
```

## Review Process

### Checklist pour les Reviewers
- [ ] **Architecture** : Respect des règles `internal/` vs `pkg/`
- [ ] **Anti-redondance** : Pas de duplication de code
- [ ] **Tests** : Couverture et qualité des tests
- [ ] **Performance** : Pas de régression de performance
- [ ] **Sécurité** : Pas d'introduction de vulnérabilités
- [ ] **Documentation** : Documentation à jour

### Checklist pour les Auteurs
- [ ] **Tests** : Tests unitaires et d'intégration
- [ ] **Linting** : `golangci-lint` passe sans erreur
- [ ] **Formatage** : `go fmt` et `goimports` appliqués
- [ ] **Documentation** : Fonctions et types documentés
- [ ] **Changelog** : Entrée ajoutée si nécessaire

## Roadmap et Contributions

### Priorités Actuelles
1. **Parseurs L2** : Support de protocoles additionnels
2. **Performance** : Optimisation du parsing
3. **UX HTML** : Amélioration de l'interface
4. **IPv6** : Support complet IPv6
5. **Tests** : Amélioration de la couverture

### Nouvelles Fonctionnalités
- **Parseurs** : VTP, HSRP, OSPF, BGP
- **Exports** : Formats additionnels (YAML, XML)
- **UI** : Interface web interactive
- **API** : REST API pour intégration
- **Monitoring** : Métriques Prometheus

### Améliorations Techniques
- **Concurrence** : Pipeline parallèle optimisé
- **Mémoire** : Réduction de l'empreinte mémoire
- **Logs** : Rotation et compression automatiques
- **Config** : Validation avancée des configurations

## Support et Communication

### Canaux de Communication
- **Documentation** : [docs/](docs/)
- **Issues** : Reportez les problèmes via les issues GitHub
- **Discussions** : Utilisez les discussions GitHub pour les questions

### Types d'Issues
- **Bug** : Problème identifié
- **Feature** : Demande de fonctionnalité
- **Enhancement** : Amélioration existante
- **Documentation** : Amélioration de la doc
- **Question** : Question technique

### Template d'Issue
```markdown
## Description
Description claire du problème ou de la demande.

## Environnement
- OS: Linux/Windows/macOS
- Go version: 1.24.2
- Zandoli version: Alpha

## Étapes pour reproduire
1. ...
2. ...
3. ...

## Comportement attendu
Description du comportement attendu.

## Comportement observé
Description du comportement observé.

## Logs
```
Logs pertinents ici
```

## Informations additionnelles
Toute information supplémentaire utile.
```

## Licence et Droits

### Contribution
En contribuant à Zandoli, vous acceptez que vos contributions soient sous licence **Apache License 2.0** (voir [`LICENSE`](./LICENSE)).

### Propriété Intellectuelle
- **Code** : Sous licence du projet
- **Documentation** : Sous licence du projet
- **Tests** : Sous licence du projet

### Attribution
Les contributeurs sont reconnus dans :
- **CONTRIBUTORS.md** : Liste des contributeurs
- **Changelog** : Mentions dans les releases
- **Commits** : Historique Git

---

**Voir aussi** : [Architecture](docs/ARCHITECTURE.md) | [Pipeline](docs/PIPELINE.md) | [Modèle de Données](docs/DATA_MODEL.md) | [Dépannage](docs/TROUBLESHOOTING.md)
