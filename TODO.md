# 🗺️ Zandoli Roadmap

Ce document décrit les différentes étapes de développement de l'outil de reconnaissance réseau **Zandoli**, découpé en versions progressives, pensées pour un usage Red Team / pentest.

---

## ✅ V1 — Version initiale stable (terminée)

### 🎯 Objectifs atteints :
- [x] Analyse ARP passive via `libpcap`
- [x] Scan ARP actif standard
- [x] Scan ARP furtif (`--stealthy`) :
  - 15 requêtes max / 25s
  - 5 requêtes max / seconde
  - Délai aléatoire entre 150ms et 400ms
- [x] Exclusion automatique de l’IP locale
- [x] Export des résultats en JSON, CSV, HTML (horodatés)
- [x] Logger configurable avec `zerolog`
- [x] Fichier de configuration `config.yaml`
- [x] Exclusion manuelle d’IP dans le fichier de config
- [x] Tests unitaires `utils`, `sniffer`, `scanner`
- [x] Makefile complet (`build`, `test`, `lint`, `check`)

---

## 🔜 V2 — Intelligence et furtivité augmentées (en cours)

### 🎯 Objectifs :
- [ ] 🔬 **Fingerprinting semi-passif** (analyse SYN/SYN+ACK pour OS/TTL/MSS/WindowSize)
- [x] 🧠 **Classification heuristique** (workstation, IoT, firewall, honeypot…)
- [x] 🔍 **Filtrage OUI actif + passif** (defensive_ouis.txt, blacklist)
- [x] 🛡️ **Détection d’équipements défensifs** (802.1X)
- [x] 📈 **Détection passive de protocoles** :
  - [x] CDP / LLDP / STP
  - [x] mDNS, LLMNR, NetBIOS
  - [x] SMB, DNS
  - [x] DHCP (option 15, 54, 82)
- [x] 🌐 **Découverte de nouveaux sous-réseaux** (par IP observées)
- [x] 🧭 **Détection de passerelle/NAT** (plusieurs IP derrière une même MAC)
- [ ] 🏷️ **Extraction de noms d’utilisateurs** (DHCP hostname, NetBIOS, etc.)
- [ ] 🧾 **Export enrichi** (OSGuess, vendor, catégorie, protocole détecté, domaine)
- [ ] 🧪 Tests unitaires avancés pour chaque analyseur
- [ ] ⚙️ Optimisation traitement concurrent (buffer + worker pool)

---

## 🚧 V3 — Pilotage, scoring, détection offensive

### 🎯 Objectifs :
- [ ] 🧠 **Score de priorité des cibles** (ex: DC = 9.5/10)
- [ ] 🔍 **Détection honeypots** (TTL incohérent, réponse étrange, MAC piégeuse)
- [ ] 🧭 **Fingerprint OS passif** (via `.pcap` ou écoute TCP)
- [ ] 📊 **Score de risque réseau global** (présence IDS, NAC, 802.1X)
- [ ] 📤 **Export HTML lisible type rapport**
- [ ] 🧑‍💻 **TUI minimal live** (affichage CLI dynamique)
- [ ] 🕹️ **Pause / reprise du scan**
- [ ] 🛜 **Contrôle par API REST locale** (scan, pause, export à distance)

---

## 🚀 V4 — Analyse différée et enrichissement post-reconnaissance

### 🎯 Objectifs :
- [ ] 💾 **Mode `--record`** (enregistre trafic `.pcap`, aucune analyse live)
- [ ] 📂 **Mode `--pcap`** (analyse offline : ARP, CDP, LLDP, STP, DNS, etc.)
- [ ] 📦 **Matching fin de vie (EOL)** d’équipements (via vendor + modèle)
- [ ] 🔐 **Recherche CVE locale** pour les équipements détectés comme EOL
- [ ] 🧠 **Export final enrichi** avec EOL, CVE, criticité

---

## 🧩 Modules techniques planifiés

| Module           | Description                                                  | Version |
|------------------|--------------------------------------------------------------|---------|
| `pkg/fingerprint`| Fingerprinting passif & semi-passif                          | V2      |
| `pkg/analyzer`   | Analyse passive multi-protocole + classification             | V2      |
| `pkg/security`   | Détection 802.1X / DHCP snooping / honeypot / proxy          | V2/V3   |
| `pkg/tui`        | Interface terminal (read-only ou interactive)                | V3      |
| `pkg/api`        | API REST locale pour pilotage distant                        | V3      |
| `pkg/export`     | HTML/PDF enrichis, SIEM-ready                                | V3/V4   |
| `pkg/recorder`   | Capture `.pcap` en live (mode `--record`)                    | V4      |
| `pkg/pcap`       | Analyse offline (mode `--pcap`)                              | V4      |
| `pkg/eol`        | Détection équipements en fin de vie                          | V4      |
| `pkg/cve`        | Matching CVE locales offline                                 | V4      |

---

## 🗓️ Timeline estimée (adaptée à ton rythme rapide)

| Étape | Durée estimée |
|-------|----------------|
| Finalisation V1 ✅ | ✔︎ Terminé |
| V2 complète | ~10–14h |
| V2.5 (reco passive complète) | ~10–12h |
| V3 (pilotage, scoring, honeypot, OS) | ~14–16h |
| V4 (offline, record, CVE/EOL) | ~10h |

---

## 🔄 Mise à jour

Ce fichier sera mis à jour à chaque jalon ou pivot.  
Zandoli suit une philosophie : **furtivité, lisibilité, modularité, impact réel** en Red Team.


