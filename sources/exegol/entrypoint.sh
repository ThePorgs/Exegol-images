#!/bin/bash
trap shutdown SIGTERM

# Function specific
function load_config() {
  # Load custom config
  /exegol/load_custom_configs.sh &>>/var/log/exegol_custom.log
}

function endless() {
  # Start action / endless (keep the container running)
  read -u 2
}

function shutdown() {
  # SIGTERM received (the container is stopping).
  # Shutting down the container.
  # Sending SIGTERM to all interactive process for proper closing
  kill $(pgrep -x -f zsh) 2>/dev/null
  kill $(pgrep -x -f bash) 2>/dev/null
  kill $(pgrep -x -f tmux) 2>/dev/null
  # Wait for shell logging compression
  wait_list=$(pgrep -f "filelog=/workspace/logs/")
  for i in $wait_list
    do
      # Waiting for: $i PID process to exit
      tail --pid="$i" -f /dev/null
    done
  exit 0
}

# Managed features
function default() {
  load_config
  endless
}

function ovpn() {
  load_config
  openvpn $2 | tee /var/log/vpn.log
  # TODO add log rotation
  endless
}

function cmd() {
  load_config
  command_line=${*:2}
  echo "Executing: $command_line"
  $command_line
}

# Default action is "default"
func_name="${1:-default}"

# Dynamic execution
$func_name "$@" || (
  echo "An error occurred executing the '$func_name' action. Your image version is probably out of date for this feature. Please update your image."
  exit 1
)
