#!/bin/bash
# Author: The Exegol Project

source common.sh

function install_sipvicious() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing SIPVicious"
    python3 -m pipx install git+https://github.com/enablesecurity/sipvicious.git
    add-history sipvicious_svcrack
    add-test-command "sipvicious_svcrack --version"
    add-to-list "sipvicious,https://github.com/enablesecurity/sipvicious,Enumeration and MITM tool for SIP devices"
}

# Package dedicated to VOIP/SIP pentest tools
function package_voip() {
    set_ruby_env
    install_sipvicious              # Set of tools for auditing SIP based VOIP systems
}
