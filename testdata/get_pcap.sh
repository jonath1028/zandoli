#!/bin/bash
set -e

# Dossier de travail
mkdir -p testdata
cd testdata

# Liste des PCAPs à télécharger
declare -A pcaps=(
  ["lldp"]="https://wiki.wireshark.org/SampleCaptures?action=AttachFile&do=get&target=lldp.pcap"
  ["cdp"]="https://wiki.wireshark.org/SampleCaptures?action=AttachFile&do=get&target=cdp.pcap"
  ["stp"]="https://wiki.wireshark.org/SampleCaptures?action=AttachFile&do=get&target=stp.pcap"
  ["dhcp"]="https://wiki.wireshark.org/SampleCaptures?action=AttachFile&do=get&target=dhcp.pcap"
  ["arpflood"]="https://www.netresec.com/?download=ArpFlood.pcap"
  ["eapol"]="https://wiki.wireshark.org/SampleCaptures?action=AttachFile&do=get&target=EAPOL_Authentication.pcap"
  ["vlan"]="https://wiki.wireshark.org/SampleCaptures?action=AttachFile&do=get&target=802.1Q_vlan_tag.pcap"
  ["mdns"]="https://wiki.wireshark.org/SampleCaptures?action=AttachFile&do=get&target=mdns.pcap"
  ["smb"]="https://wiki.wireshark.org/SampleCaptures?action=AttachFile&do=get&target=smb.pcap"
  ["arppoison"]="https://www.netresec.com/?download=ArpPoisoning.pcap"
)

echo "[*] Téléchargement des PCAPs..."
for name in "${!pcaps[@]}"; do
  url="${pcaps[$name]}"
  file="${name}.pcap"
  if [ ! -f "$file" ]; then
    echo "  → $file"
    wget -O "$file" "$url"
  else
    echo "  [skip] $file déjà présent"
  fi
done

echo "[*] Fusion des PCAPs..."
# Fusion avec mergecap (fourni avec Wireshark)
mergecap -w zandoli_test.pcap *.pcap

echo "[*] Fichier final prêt : testdata/zandoli_test.pcap"
ls -lh zandoli_test.pcap

