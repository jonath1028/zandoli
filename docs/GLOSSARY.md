# Glossaire Zandoli

## Termes Techniques

### Acronymes et Protocoles

#### **ARP** - Address Resolution Protocol
**Définition** : Protocole de résolution d'adresses qui associe une adresse IP à une adresse MAC.  
**Usage Zandoli** : Découverte passive et active des équipements réseau.  
**RFC** : RFC 826

#### **CDP** - Cisco Discovery Protocol
**Définition** : Protocole propriétaire Cisco pour la découverte automatique des équipements voisins.  
**Usage Zandoli** : Identification des équipements Cisco et extraction des informations de topologie.  
**Port** : 2000 (UDP)

#### **DHCP** - Dynamic Host Configuration Protocol
**Définition** : Protocole d'attribution automatique d'adresses IP et de paramètres réseau.  
**Usage Zandoli** : Découverte des hôtes et attribution d'adresses IP.  
**Ports** : 67 (serveur), 68 (client)

#### **EAPOL** - EAP over LAN
**Définition** : Protocole d'authentification 802.1X pour l'accès aux ports réseau.  
**Usage Zandoli** : Détection des équipements d'authentification et de sécurité.  
**Standard** : IEEE 802.1X

#### **LLDP** - Link Layer Discovery Protocol
**Définition** : Protocole standard IEEE pour la découverte des équipements voisins.  
**Usage Zandoli** : Identification des équipements réseau non-Cisco.  
**EtherType** : 0x88CC

#### **mDNS** - Multicast DNS
**Définition** : Protocole de résolution de noms utilisant le multicast pour les réseaux locaux.  
**Usage Zandoli** : Découverte des services et hostnames locaux.  
**Port** : 5353 (UDP)

#### **NDP** - Neighbor Discovery Protocol
**Définition** : Protocole IPv6 équivalent à ARP pour la découverte des voisins.  
**Usage Zandoli** : Découverte des équipements IPv6.  
**RFC** : RFC 4861

#### **STP** - Spanning Tree Protocol
**Définition** : Protocole IEEE 802.1D pour éviter les boucles dans les réseaux commutés.  
**Usage Zandoli** : Identification des commutateurs et topologie de boucle.  
**EtherType** : 0x42 (802.3) ou 0x26 (802.1D)

#### **SYN** - Synchronize
**Définition** : Premier paquet d'une connexion TCP pour établir une session.  
**Usage Zandoli** : Scan de ports TCP pour détecter les services actifs.  
**RFC** : RFC 793

#### **VLAN** - Virtual LAN
**Définition** : Segmentation logique d'un réseau physique en réseaux virtuels.  
**Usage Zandoli** : Classification des hôtes par segment réseau.  
**Standard** : IEEE 802.1Q

### Termes Réseau

#### **Bridge ID**
**Définition** : Identifiant unique d'un pont STP composé de la priorité (4 bits) et de l'adresse MAC (6 octets).  
**Usage Zandoli** : Identification des commutateurs STP et de la topologie.

#### **BPDU** - Bridge Protocol Data Unit
**Définition** : Paquets échangés entre les commutateurs pour la gestion du Spanning Tree.  
**Usage Zandoli** : Analyse de la topologie STP et identification des commutateurs.

#### **CGNAT** - Carrier-Grade NAT
**Définition** : Plage d'adresses IPv4 privées (100.64.0.0/10) utilisée par les FAI.  
**Usage Zandoli** : Classification des adresses IP comme privées.

#### **EtherType**
**Définition** : Champ de 2 octets dans l'en-tête Ethernet indiquant le type de protocole.  
**Usage Zandoli** : Identification des protocoles Layer 2.

#### **MAC Address**
**Définition** : Adresse physique unique d'une interface réseau (6 octets).  
**Usage Zandoli** : Identifiant principal des équipements réseau.

#### **OUI** - Organizationally Unique Identifier
**Définition** : Identifiant de 3 octets attribué à un constructeur par l'IEEE.  
**Usage Zandoli** : Identification du constructeur à partir de l'adresse MAC.

#### **Port ID**
**Définition** : Identifiant unique d'un port sur un équipement réseau.  
**Usage Zandoli** : Détails des connexions dans CDP/LLDP.

#### **Root Bridge**
**Définition** : Pont racine du Spanning Tree, point de référence pour la topologie.  
**Usage Zandoli** : Identification de la topologie STP et du pont racine.

#### **Root Path Cost**
**Définition** : Coût du chemin vers le pont racine dans STP.  
**Usage Zandoli** : Analyse de la topologie et des chemins optimaux.

#### **TTL** - Time To Live
**Définition** : Champ IP indiquant la durée de vie maximale d'un paquet.  
**Usage Zandoli** : Fingerprinting OS et détection de rebond.

### Termes Zandoli

#### **Aggregator**
**Définition** : Module responsable de l'agrégation et de la corrélation des données découvertes.  
**Fichier** : `pkg/analyzer/aggregator.go`

#### **Anomaly**
**Définition** : Comportement réseau détecté comme suspect ou anormal.  
**Types** : IP dupliquée, MAC multiple IP, flip suspect, hostname dupliqué.

#### **Confidence**
**Définition** : Score de confiance (0-100) pour l'inférence de rôle d'un équipement.  
**Usage** : Indique la fiabilité de la classification.

#### **Dispatcher**
**Définition** : Module qui route les paquets vers les parseurs spécialisés.  
**Fichier** : `pkg/analyzer/dispatcher.go`

#### **Host**
**Définition** : Structure principale représentant un équipement découvert sur le réseau.  
**Fichier** : `pkg/model/types.go`

#### **L2 Signals**
**Définition** : Signaux Layer 2 (CDP, LLDP, STP, 802.1X) utilisés pour l'inférence de rôle.  
**Priorité** : Signaux L2 ont priorité absolue sur les signaux comportementaux.

#### **Orchestrator**
**Définition** : Module central coordonnant l'exécution du pipeline complet.  
**Fichier** : `pkg/orchestrator/orchestrator.go`

#### **ParsedRecord**
**Définition** : Structure représentant une donnée parsée d'un paquet réseau.  
**Usage** : Format intermédiaire entre parsing et agrégation.

#### **Priority Matrix**
**Définition** : Matrice définissant les priorités des protocoles pour l'association IP↔MAC.  
**Fichier** : `pkg/analyzer/priority_matrix.go`

#### **Role Inference**
**Définition** : Processus de détermination du rôle d'un équipement (client, serveur, réseau).  
**Fichier** : `pkg/analyzer/role_inference.go`

#### **Sniffer**
**Définition** : Module responsable de la capture et du parsing initial des paquets.  
**Fichier** : `pkg/sniffer/`

### Rôles et Catégories

#### **Client**
**Définition** : Équipement qui initie des connexions et consomme des services.  
**Signaux** : Requêtes HTTP, DNS queries, connexions sortantes.

#### **Réseau** (ou Infrastructure)
**Définition** : Équipement d'infrastructure réseau (routeurs, commutateurs, points d'accès).  
**Signaux** : CDP, LLDP, STP, OUI réseau, comportement de routage.

#### **Serveur**
**Définition** : Équipement qui fournit des services et répond aux requêtes.  
**Signaux** : Réponses HTTP, DNS responses, services TCP/UDP.

### Catégories d'Équipements

#### **Computer**
**Définition** : Ordinateur de bureau ou portable.  
**Caractéristiques** : OS détecté, protocoles client/serveur mixtes.

#### **Network**
**Définition** : Équipement d'infrastructure réseau.  
**Caractéristiques** : Signaux L2, OUI réseau, services de gestion.

#### **Phone**
**Définition** : Téléphone IP ou équipement de communication.  
**Caractéristiques** : Protocoles VoIP, OUI télécom.

#### **VM**
**Définition** : Machine virtuelle.  
**Caractéristiques** : TTL anormal, comportement réseau spécifique.

### Types d'Anomalies

#### **Multiple DHCP Servers**
**Définition** : Plusieurs serveurs DHCP détectés sur le réseau.  
**Sévérité** : High  
**Causes** : Configuration incorrecte, failover DHCP.

#### **Suspicious TTL**
**Définition** : Valeurs TTL suspectes détectées (très basses ou très élevées).  
**Sévérité** : Medium  
**Causes** : Tunnelisation, routage inhabituel.

#### **Unusual Ports**
**Définition** : Combinaisons de ports inhabituelles détectées.  
**Sévérité** : Medium  
**Causes** : Services suspects, configuration non standard.

#### **MAC Anomalies**
**Définition** : Anomalies d'adresse MAC détectées (broadcast, multicast, localement administrée).  
**Sévérité** : Low  
**Causes** : Configuration incorrecte, équipement virtuel.

### Formats et Exports

#### **CSV**
**Définition** : Format tabulaire avec délimiteur point-virgule.  
**Usage** : Analyse dans Excel ou outils de traitement de données.

#### **HTML**
**Définition** : Rapport interactif avec filtres et recherche.  
**Usage** : Analyse visuelle et interactive des résultats.

#### **JSON**
**Définition** : Format structuré pour intégration API.  
**Usage** : Intégration avec d'autres outils et systèmes.

#### **Markdown**
**Définition** : Documentation textuelle formatée.  
**Usage** : Documentation et rapports textuels.

#### **XML**
**Définition** : Format standardisé pour intégration enterprise.  
**Usage** : Intégration avec systèmes d'entreprise.

### Modes d'Exécution

#### **Passive**
**Définition** : Mode d'écoute uniquement, sans génération de paquets.  
**Usage** : Analyse du trafic existant sans impact réseau.

#### **Active**
**Définition** : Mode de scan avec génération de paquets ARP/SYN.  
**Usage** : Découverte active des équipements et services.

#### **Combined**
**Définition** : Mode combinant écoute passive puis scan actif.  
**Usage** : Découverte maximale avec impact réseau minimal.

#### **PCAP**
**Définition** : Mode d'analyse de fichier PCAP offline.  
**Usage** : Analyse de captures réseau sans interface live.

---

**Voir aussi** : [Pipeline](PIPELINE.md) | [Modèle de Données](DATA_MODEL.md) | [Protocoles L2](L2_PROTOCOLS.md) | [Architecture](ARCHITECTURE.md)
