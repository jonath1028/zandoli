# Logging Zandoli

## Vue d'ensemble

Zandoli utilise le framework de logging `zerolog` pour fournir des logs structurés, performants et configurables. Les logs sont écrits dans des fichiers et optionnellement sur la console selon la configuration.

## Configuration du Logging

### Niveaux de Log
- **Debug** : Informations de debugging (décisions internes)
- **Info** : Événements importants (hôtes découverts, scan terminé)
- **Warn** : Problèmes non critiques (paquets corrompus, timeouts)
- **Error** : Erreurs bloquantes (permissions, fichiers manquants)
- **Fatal** : Erreurs fatales (arrêt du programme)

### Configuration par Flags
```bash
# Logs détaillés (console + fichier)
./zandoli --verbose --passive

# Logs réduits (fichier uniquement)
./zandoli --quiet --active

# Mode silencieux (fichier uniquement)
./zandoli --paranoid --combined
```

### Configuration YAML
```yaml
logging:
  verbose: false    # Niveau Debug + console
  quiet: false      # Niveau Warn uniquement
  paranoid: false   # Pas de logs console
```

## Comportement par Mode

### Mode Par Défaut
- **Niveau** : Info
- **Sortie** : Fichier uniquement
- **Console** : Aucune

### Mode Verbose (`--verbose`)
- **Niveau** : Debug
- **Sortie** : Console + fichier
- **Console** : Tous les logs

### Mode Quiet (`--quiet`)
- **Niveau** : Warn
- **Sortie** : Fichier uniquement
- **Console** : Aucune

### Mode Paranoid (`--paranoid`)
- **Niveau** : Selon config (Info par défaut)
- **Sortie** : Fichier uniquement
- **Console** : Aucune

## Structure des Logs

### Format des Entrées
```
2025-01-30T10:30:15.123Z INF host discovered ip=192.168.1.1 mac=aa:bb:cc:dd:ee:ff vendor="Cisco Systems" role=reseau
```

### Champs Standard
- **Timestamp** : Format RFC3339 avec microsecondes
- **Level** : Niveau de log (DBG, INF, WRN, ERR, FTL)
- **Message** : Message descriptif
- **Fields** : Champs structurés (key=value)

### Exemples de Logs

#### Découverte d'Hôte
```
2025-01-30T10:30:15.123Z INF host discovered ip=192.168.1.1 mac=aa:bb:cc:dd:ee:ff vendor="Cisco Systems" role=reseau confidence=100 signals="L2_PRESENT"
```

#### Erreur de Parsing
```
2025-01-30T10:30:16.456Z WRN packet parsing failed error="truncated packet" size=64 expected=128 protocol=TCP
```

#### Scan Terminé
```
2025-01-30T10:32:45.789Z INF scan completed hosts=42 duration=2m30s mode=combined
```

## Fichiers de Log

### Localisation
- **Fichier principal** : `output/log.txt` (global)
- **Fichier de scan** : `output/scan_YYYYMMDD-HHMMSS/log.txt`
- **Console** : stdout (seulement en mode verbose)

### Structure des Répertoires
```
output/
├── log.txt                    # Log global (tous les scans)
└── scan_20250130-103000/
    ├── log.txt                # Log spécifique au scan
    ├── report.html
    └── hosts.json
```

### Écriture Multi-Fichier
Le logger écrit simultanément dans :
1. **Fichier global** : `output/log.txt`
2. **Fichier de scan** : `output/scan_YYYYMMDD-HHMMSS/log.txt`

### Rotation des Logs
**⚠️ Non implémentée actuellement**

La rotation automatique des logs n'est pas encore implémentée. Les fichiers de log peuvent grandir indéfiniment.

**Recommandations** :
- Utiliser `logrotate` pour la rotation manuelle
- Surveiller la taille des fichiers
- Nettoyer les anciens scans si nécessaire

## Configuration Avancée

### Logger Personnalisé
```go
import "github.com/rs/zerolog"

// Configuration du logger
zerolog.SetGlobalLevel(zerolog.DebugLevel)
zerolog.TimeFieldFormat = zerolog.TimeFormatUnix

// Création du logger
log := zerolog.New(os.Stdout).With().
    Timestamp().
    Caller().
    Logger()
```

### Champs Contextuels
```go
// Ajout de champs contextuels
log = log.With().
    Str("component", "sniffer").
    Str("interface", "eth0").
    Logger()

// Utilisation
log.Info().Str("packet_id", "12345").Msg("packet processed")
```

### Filtrage des Logs
```go
// Filtrage par composant
log = log.Filter(func(e *zerolog.Event, level zerolog.Level, msg string) *zerolog.Event {
    if strings.Contains(msg, "packet") && level < zerolog.DebugLevel {
        return nil // Ignore les logs de paquets en dessous de Debug
    }
    return e
})
```

## Bonnes Pratiques

### Niveaux Appropriés
- **Debug** : Décisions internes, états
- **Info** : Événements métier importants
- **Warn** : Problèmes récupérables
- **Error** : Erreurs bloquantes
- **Fatal** : Erreurs fatales (rare)

### Messages Informatifs
```go
// ✅ Bon
log.Info().
    Str("ip", host.IP.String()).
    Str("mac", host.MAC.String()).
    Str("role", host.Role).
    Msg("host discovered")

// ❌ Mauvais
log.Info().Msg("found something")
```

### Performance
- **Évitez** les logs dans les boucles critiques
- **Utilisez** des niveaux appropriés en production
- **Désactivez** les logs de debug en production

## Monitoring et Alertes

### Métriques de Logs
- **Débit** : Logs par seconde
- **Erreurs** : Taux d'erreur
- **Latence** : Temps de traitement
- **Hôtes** : Hôtes découverts par minute

### Exemple de Monitoring
```bash
# Compter les erreurs
grep -c "level=ERR" output/log.txt

# Dernières découvertes d'hôtes
grep "host discovered" output/log.txt | tail -10

# Statistiques par rôle
grep "host discovered" output/log.txt | grep -o 'role=[^ ]*' | sort | uniq -c
```

### Alertes Recommandées
- **Taux d'erreur > 5%** : Problème de parsing
- **Aucun hôte découvert** : Problème de capture
- **Logs manquants** : Problème de permissions

## Dépannage

### Logs Manquants
```bash
# Vérifier les permissions
ls -la output/
touch output/test.log

# Vérifier l'espace disque
df -h output/

# Vérifier les processus
ps aux | grep zandoli
```

### Logs Trop Verbose
```bash
# Réduire la verbosité
./zandoli --quiet --passive

# Filtrer les logs
grep -v "packet processed" output/log.txt > filtered.log
```

### Logs Corrompus
```bash
# Vérifier l'intégrité
file output/log.txt

# Nettoyer les logs corrompus
tail -n +1000 output/log.txt > output/log_clean.txt
```

## Configuration de Production

### Recommandations
```yaml
# config.yaml pour production
logging:
  verbose: false    # Pas de debug en production
  quiet: true       # Seulement les événements importants
  paranoid: false   # Garder les logs pour monitoring
```

### Rotation avec logrotate
```bash
# /etc/logrotate.d/zandoli
/path/to/zandoli/output/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 644 root root
}
```

## Mode Test

### Configuration Test
```go
// Mode test : pas de fichier, console uniquement
log, err := logger.New("", config)
// ou
log, err := logger.New("test", config)
```

### Utilisation en Tests
```go
func TestSomething(t *testing.T) {
    cfg := &config.Config{
        Logging: config.LoggingConfig{
            Verbose: true,
            Quiet: false,
            Paranoid: false,
        },
    }
    
    log, err := logger.New("test", cfg)
    if err != nil {
        t.Fatal(err)
    }
    
    log.Info().Msg("test log message")
}
```

---

**Voir aussi** : [CLI](CLI.md) | [Dépannage](TROUBLESHOOTING.md) | [Architecture](ARCHITECTURE.md) | [Sécurité](SECURITY.md)