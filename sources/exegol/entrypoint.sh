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

# Dynamic execution
$1 "$@"
