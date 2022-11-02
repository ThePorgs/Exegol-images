#!/bin/bash

# Starting
# This procedure is supposed to be executed only once at the first startup, using a lockfile check

if [ -f /.exegol/.setup.lock ]
then
  # Lock file exists, exiting
  exit 0
else
  echo "This log file is the result of the execution of the official and personal customization script"
  echo "[$(date +'%d-%m-%Y_%H-%M-%S')] ==== Loading custom setups (/.exegol/load_supported_setups.sh) ===="
  echo > /.exegol/.setup.lock
fi

# Deploying the /opt/my-resources/ folder if not already there
if [ -d "/opt/my-resources" ]
then
  # Setup basic structure
  [ -d "/opt/my-resources/setup" ] || mkdir -p /opt/my-resources/setup/
  [ -d "/opt/my-resources/bin" ] || mkdir -p /opt/my-resources/bin/
else
  echo "Exiting, 'my-resources' is disabled"
  exit 0
fi

# Copying README.md to /opt/my-resources/ (first use)
[ -f /opt/my-resources/setup/README.md ] || cp /.exegol/skel/README.md /opt/my-resources/setup/README.md

#TODO implement tmux custom

# Executing user setup (or create the file)
if [ -f /opt/my-resources/setup/load_user_setup.sh ]
then
  echo "[$(date +'%d-%m-%Y_%H-%M-%S')] ==== Loading user setup (/opt/my-resources/setup/load_user_setup.sh) ===="
  /opt/my-resources/setup/load_user_setup.sh
else
  echo "[$(date +'%d-%m-%Y_%H-%M-%S')] ==== User setup loader missing, deploying it (/opt/my-resources/setup/load_user_setup.sh) ===="
  cp /.exegol/skel/load_user_setup.sh /opt/my-resources/setup/load_user_setup.sh
  chmod 760 /opt/my-resources/setup/load_user_setup.sh
fi

echo "[$(date +'%d-%m-%Y_%H-%M-%S')] ==== End of custom setups loading ===="
exit 0
