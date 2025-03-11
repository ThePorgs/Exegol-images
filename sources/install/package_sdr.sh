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
    add-test-command "which gqrx"                       # spectrum analyzer for SDR
    add-test-command "dpkg -l rtl-433 | grep 'rtl-433'" # decode radio transmissions from devices on the ISM bands
  
    add-to-list "hackrf,https://github.com/mossmann/hackrf,Low cost software defined radio platform"
    add-to-list "gqrx,https://github.com/csete/gqrx,Software defined radio receiver powered by GNU Radio and Qt"
    add-to-list "rtl-433,https://github.com/merbanan/rtl_433,Tool for decoding various wireless protocols/ signals such as those used by weather stations"
}

function install_mousejack() {
    colorecho "Installing mousejack"
    fapt sdcc binutils
    git -C /opt/tools/ clone --depth 1 --recursive --shallow-submodules https://github.com/BastilleResearch/mousejack
    cd /opt/tools/mousejack/nrf-research-firmware || exit
    make -j
    pip2 install libusb pyusb
    add-aliases mousejack
    add-history mousejack
    add-test-command "nrf24-scanner.py --help"
    add-test-command "nrf24-sniffer.py --help"
    add-test-command "nrf24-network-mapper.py --help"
    add-to-list "mousejack,https://github.com/BastilleResearch/mousejack,Exploit to take over a wireless mouse and keyboard"
}

function install_jackit() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing jackit"
    pipx install --system-site-packages git+https://github.com/insecurityofthings/jackit
    add-history jackit
    add-test-command "jackit --help"
    add-to-list "jackit,https://github.com/insecurityofthings/jackit,Exploit to take over a wireless mouse and keyboard"
}

# Package dedicated to SDR
function package_sdr() {
    set_env
    local start_time
    local end_time
    start_time=$(date +%s)
    install_sdr_apt_tools
    install_mousejack               # tools for mousejacking
    install_jackit                  # tools for mousejacking
    post_install
    end_time=$(date +%s)
    local elapsed_time=$((end_time - start_time))
    colorecho "Package sdr completed in $elapsed_time seconds."
}
