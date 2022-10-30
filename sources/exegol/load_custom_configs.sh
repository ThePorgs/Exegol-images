#!/bin/bash

# Starting
# This procedure is supposed to be executed only once at the first startup, using a lockfile check

if [ -f /exegol/.setup.lock ]
then
  # Lock file exists, exiting
  exit 0
else
  echo "[$(date +'%d-%m-%Y_%H-%M-%S')] Deploying custom config"
  echo > /exegol/.setup.lock
fi

#TODO implement tmux custom

# End of the file - execute user custom procedure (or create it)
if [ -f /my-resources/config/load_my_configs.sh ]
then
  echo "$(date +'%d-%m-%Y_%H-%M-%S')] Deploying 'my' config"
  /my-resources/config/load_my_configs.sh
else
  cp /exegol/templates/load_my_configs.sh /my-resources/config/load_my_configs.sh
  chmod 760 /my-resources/config/load_my_configs.sh
fi

echo "End of deployment"
exit 0
