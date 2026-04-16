#!/bin/bash

WHITE="\033[97m"
GREEN="\033[92m"
GRAY="\033[90m"
RESET="\033[0m"

print_bar() {
  local name=$1
  local total=$2
  local type=$3
  local eta=$4
  local i=0

  while [ $i -le $total ]; do
    local filled=$(( i * 40 / total ))
    local empty=$(( 40 - filled ))
    local bar="$(printf '█%.0s' $(seq 1 $filled))$(printf '░%.0s' $(seq 1 $empty))"

    if [ "$type" == "time" ]; then
      local status="$(printf "%2ds / %2ds" $i $total)"
    else
      local status="$(printf "%3d / %3d  ETA: %s" $i $total $eta)"
    fi

    echo -ne "${WHITE}${name}   ${RESET}▶ [${GREEN}${bar}${RESET}] ${GREEN}${status}${RESET}  \r"
    sleep 0.05
    ((i++))
  done
  echo ""
}

# En-tête
echo -e "${GRAY}================ ZANDOLI PROGRESS BARS ================${RESET}"

# Phase 1 – Sniffing
print_bar "Sniffing" 60 "time" ""

# Phase 2 – Scan ARP
print_bar "Scan ARP" 254 "count" "00:17"

# Phase 3 – Scan SYN
print_bar "Scan SYN" 80 "count" "00:10"

# Fin
echo -e "${GRAY}====================     DONE     ======================${RESET}"

