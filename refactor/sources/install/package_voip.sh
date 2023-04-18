#!/bin/bash
# Author: The Exegol Project

source common.sh

# Package dedicated to VOIP/SIP pentest tools
function package_voip() {
    install_sipvicious              # Set of tools for auditing SIP based VOIP systems
}

function install_sipvicious() {
    colorecho "Installing SIPVicious"
    python3 -m pipx install git+https://github.com/enablesecurity/sipvicious.git
    add-test-command "sipvicious_svcrack --version"
    add-to-list "sipvicious,https://github.com/enablesecurity/sipvicious,Enumeration and MITM tool for SIP devices"
}