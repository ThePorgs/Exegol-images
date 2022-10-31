#!/bin/bash

# Starting
# This procedure is supposed to be executed only once at the first startup, using a lockfile check

if [ -f /exegol/.setup.lock ]
then
  # Lock file exists, exiting
  exit 0
else
  echo "This log file is the result of the execution of the official and personal customization script"
  echo "[$(date +'%d-%m-%Y_%H-%M-%S')] ==== Deploying custom config (/exegol/load_custom_configs.sh) ===="
  echo > /exegol/.setup.lock
fi

if [ -d "/my-resources" ]
then
  # Setup basic directory
  [ -d "/my-resources/config" ] || mkdir -p /my-resources/config/
  [ -d "/my-resources/bin" ] || mkdir -p /my-resources/bin/
else
  echo "Exiting custom resources because 'my-resources' is disable"
  exit 0
fi

# Import README.md to my-resources (first use)
[ -f /my-resources/config/README.md ] || cp /exegol/README.md /my-resources/config/README.md

#TODO implement tmux custom

# End of the file - execute user custom procedure (or create it)
if [ -f /my-resources/config/load_my_configs.sh ]
then
  echo "[$(date +'%d-%m-%Y_%H-%M-%S')] ==== Deploying 'my' config (/my-resources/config/load_my_configs.sh) ===="
  /my-resources/config/load_my_configs.sh
else
  echo "[$(date +'%d-%m-%Y_%H-%M-%S')] ==== Skipping missing 'my' config (/my-resources/config/load_my_configs.sh) ===="
  cp /exegol/templates/load_my_configs.sh /my-resources/config/load_my_configs.sh
  chmod 760 /my-resources/config/load_my_configs.sh
fi

echo "[$(date +'%d-%m-%Y_%H-%M-%S')] ==== End of deployment ===="
exit 0
