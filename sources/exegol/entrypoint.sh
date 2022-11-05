#!/bin/bash
trap shutdown SIGTERM

# Function specific
function load_setups() {
    # Load custom setups (supported setups, and user setup)
    [ -d /var/log/exegol ] || mkdir -p /var/log/exegol
    /.exegol/load_supported_setups.sh &>> /var/log/exegol/load_setups.log
}

function endless() {
    # Start action / endless
    # Entrypoint for the container, in order to have a process hanging, to keep the container alive
    # Alternative to running bash/zsh/whatever as entrypoint, which is longer to start and to stop and to very clean
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

function resolv_docker_host() {
  # On docker desktop host, resolving the host.docker.internal before starting a VPN connection for GUI applications
  docker_ip=$(getent hosts host.docker.internal | head -n1 | awk '{ print $1 }')
  if [ "$docker_ip" ]; then
    # Add docker internal host resolution to the hosts file to preserve access to the X server
    echo "$docker_ip        host.docker.internal" >> /etc/hosts
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
	openvpn $2 | tee /var/log/exegol/vpn.log
	# TODO add log rotation
	endless
}

function cmd() {
	load_setups
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
