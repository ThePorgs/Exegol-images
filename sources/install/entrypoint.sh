#!/bin/bash

set -e

source package_base.sh
source package_most_used.sh
source package_misc.sh
source package_osint.sh
source package_web.sh
source package_ad.sh
source package_wordlists.sh
source package_mobile.sh
source package_iot.sh
source package_rfid.sh
source package_voip.sh
source package_sdr.sh
source package_network.sh
source package_wifi.sh
source package_forensic.sh
source package_cloud.sh
source package_steganography.sh
source package_reverse.sh
source package_crypto.sh
source package_code_analysis.sh
source package_cracking.sh
source package_c2.sh
source package_desktop.sh

# Entry point for the installation
if [[ $EUID -ne 0 ]]; then
  criticalecho "You must be a root user"
else
  if declare -f "$1" > /dev/null
  then
    if [[ -f '/.dockerenv' ]]; then
      echo -e "${GREEN}"
      echo "This script is running in docker, as it should :)"
      echo "If you see things in red, don't panic, it's usually not errors, just badly handled colors"
      echo -e "${NOCOLOR}"
      "$@"
    else
      echo -e "${RED}"
      echo "[!] Careful : this script is supposed to be run inside a docker/VM, do not run this on your host unless you know what you are doing and have done backups. You have been warned :)"
      echo -e "${NOCOLOR}"
      "$@"
    fi
  else
    echo "'$1' is not a known function name" >&2
    exit 1
  fi
fi
