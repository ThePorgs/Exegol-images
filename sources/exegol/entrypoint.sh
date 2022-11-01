#!/bin/bash

# Function specific
function load_config() {
    # Load custom config
    /exegol/load_custom_configs.sh &>> /var/log/exegol_custom.log
}

function endless() {
    # Start action / endless
    while :; do sleep 300; done
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
$func_name "$@" || (echo "An error occurred executing the '$func_name' action. Your image version is probably out of date for this feature. Please update your image."; exit 1)
