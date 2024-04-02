#!/bin/bash
# Author: The Exegol Project

source common.sh

function install_sipvicious() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing SIPVicious"
    pipx install --system-site-packages git+https://github.com/enablesecurity/sipvicious.git
    add-history sipvicious_svcrack
    add-test-command "sipvicious_svcrack --version"
    add-to-list "sipvicious,https://github.com/enablesecurity/sipvicious,Enumeration and MITM tool for SIP devices"
}

# Package dedicated to VOIP/SIP pentest tools
function package_voip() {
    set_env
    local start_time
    local end_time
    start_time=$(date +%s)
    install_sipvicious              # Set of tools for auditing SIP based VOIP systems
    end_time=$(date +%s)
    local elapsed_time=$((end_time - start_time))
    colorecho "Package voip completed in $elapsed_time seconds."
}
