#!/bin/bash

# !!!!!!!!!!!!! #
# This file was the default entrypoint for the exegol docker image.
# This file is no longer up-to-date because in the later version, the wrapper uploads it's own entrypoint.sh and spawn.sh to the container to keep the wrapper and image features in sync.
# This default file is kept here for backward compatibility. No upcoming development expected here.
# !!!!!!!!!!!!! #

trap shutdown SIGTERM

# Function specific
function load_setups() {
  # Load custom setups (supported setups, and user setup)
  [[ -d "/var/log/exegol" ]] || mkdir -p /var/log/exegol
  if [[ ! -f "/.exegol/.setup.lock" ]]; then
    # Execute initial setup if lock file doesn't exist
    echo >/.exegol/.setup.lock
    /.exegol/load_supported_setups.sh &>>/var/log/exegol/load_setups.log && gzip /var/log/exegol/load_setups.log
  fi
}

function endless() {
  # Start action / endless
  # Entrypoint for the container, in order to have a process hanging, to keep the container alive
  # Alternative to running bash/zsh/whatever as entrypoint, which is longer to start and to stop and to very clean
  # shellcheck disable=SC2162
  read -u 2
}

function shutdown() {
  # SIGTERM received (the container is stopping).
  # Shutting down the container.
  # Sending SIGTERM to all interactive process for proper closing
  # shellcheck disable=SC2046
  kill $(pgrep -f -- openvpn | grep -vE '^1$') 2>/dev/null
  # shellcheck disable=SC2046
  kill $(pgrep -x -f -- zsh) 2>/dev/null
  # shellcheck disable=SC2046
  kill $(pgrep -x -f -- -zsh) 2>/dev/null
  # shellcheck disable=SC2046
  kill $(pgrep -x -f -- bash) 2>/dev/null
  # shellcheck disable=SC2046
  kill $(pgrep -x -f -- -bash) 2>/dev/null
  # Wait for every active process to exit (e.g: shell logging compression, VPN closing)
  WAIT_LIST="$(pgrep -f "(.log|start.sh)" | grep -vE '^1$')"
  for i in $WAIT_LIST; do
    # Waiting for: $i PID process to exit
    tail --pid="$i" -f /dev/null
  done
  exit 0
}

function resolv_docker_host() {
  # On docker desktop host, resolving the host.docker.internal before starting a VPN connection for GUI applications
  DOCKER_IP=$(getent hosts host.docker.internal | head -n1 | awk '{ print $1 }')
  if [[ "$DOCKER_IP" ]]; then
    # Add docker internal host resolution to the hosts file to preserve access to the X server
    echo "$DOCKER_IP        host.docker.internal" >>/etc/hosts
  fi
}

# Managed features
function default() {
  load_setups
  endless
}

function ovpn() {
  load_setups
  [[ "$DISPLAY" == *"host.docker.internal"* ]] && resolv_docker_host
  # Starting openvpn as a job with '&' to be able to receive SIGTERM signal and close everything properly
  # shellcheck disable=SC2086
  openvpn --log-append /var/log/exegol/vpn.log $2 &
  endless
}

function cmd() {
  load_setups
  # echo "Executing: ${*:2}"
  "${@:2}"
}

function compatibility() {
  # Older versions of exegol wrapper launch the container with the 'bash' command
  # This command is now interpreted by the custom entrypoint
  echo "Your version of Exegol wrapper is not up-to-date!" | tee -a ~/banner.txt
  # If the command is bash, redirect to endless. Otherwise execute the command as job to keep the shutdown procedure available
  if [[ "$*" != "bash" ]]; then
    echo "Executing command in backwards compatibility mode"
    echo "$1 -c '${*:3}'"
    $1 -c "${*:3}" &
  fi
  endless
}

echo "Your version of Exegol wrapper is not up-to-date!" | tee ~/banner.txt

# Default action is "default"
FUNC_NAME="${1:-default}"

# Older versions of exegol wrapper launch the container with the 'bash' command
# This command is now interpreted by the custom entrypoint. Redirect execution to the raw execution for backward compatibility.
# shellcheck disable=SC2068
[[ "$FUNC_NAME" == "bash" ]] || [[ "$FUNC_NAME" == "zsh" ]] && compatibility $@

# Dynamic execution
$FUNC_NAME "$@" || (
  echo "An error occurred executing the '$FUNC_NAME' action. Your exegol (wrapper / image) version might be out of date to use this feature. Please update your wrapper and image."  | tee -a ~/banner.txt
  exit 1
)
