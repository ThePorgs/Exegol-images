#!/bin/bash
# Author: The Exegol Project

source common.sh

function install_sdr_apt_tools() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing sdr apt tools"
    fapt hackrf gqrx-sdr rtl-433

    add-history hackrf
    add-history gqrx
    add-history rtl-433

    add-test-command "hackrf_debug --help"              # tools for hackrf
    add-test-command "dpkg -l rtl-433 | grep 'rtl-433'" # decode radio transmissions from devices on the ISM bands

    local version
    version="$(apt_version hackrf)"
    add-to-list "hackrf,${version},https://github.com/mossmann/hackrf,Low cost software defined radio platform"
    version="$(apt_version gqrx)"
    add-to-list "gqrx,${version},https://github.com/csete/gqrx,Software defined radio receiver powered by GNU Radio and Qt"
    version="$(apt_version rtl-433)"
    add-to-list "rtl-433,${version},https://github.com/merbanan/rtl_433,Tool for decoding various wireless protocols/ signals such as those used by weather stations"
}

function install_jackit() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing jackit"
    # MouseJack exploit tooling. Requires a CrazyRadio PA already flashed with
    # Bastille nRF research firmware (https://github.com/BastilleResearch/mousejack).
    pipx install --system-site-packages git+https://github.com/insecurityofthings/jackit
    add-history jackit
    add-test-command "jackit --help"
    local version
    version="$(pipx_version jackit)"
    add-to-list "jackit,${version},https://github.com/insecurityofthings/jackit,Exploit to take over a wireless mouse and keyboard"
}

# Package dedicated to SDR
function package_sdr() {
    set_env
    local start_time
    local end_time
    start_time=$(date +%s)
    install_sdr_apt_tools
    install_jackit                  # MouseJack exploit (needs pre-flashed CrazyRadio PA)
    post_install
    end_time=$(date +%s)
    local elapsed_time=$((end_time - start_time))
    colorecho "Package sdr completed in $elapsed_time seconds."
}
