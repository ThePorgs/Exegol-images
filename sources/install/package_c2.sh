#!/bin/bash
# Author: The Exegol Project

source common.sh

# Package dedicated to command & control frameworks
function package_c2() {
    # install_empire                # Exploit framework FIXME
    # install_starkiller            # GUI for Empire, commenting while Empire install is not fixed
    install_pwncat                  # netcat and rlwrap on steroids to handle revshells, automates a few things too
    install_metasploit              # Offensive framework
    install_routersploit            # Exploitation Framework for Embedded Devices
}

function package_c2_configure() {
    configure_metasploit
}

function install_pwncat() {
    colorecho "Installing pwncat"
    python3 -m pipx install pwncat-cs
    add-test-command "pwncat-cs --version"
    add-to-list "pwncat,https://github.com/calebstewart/pwncat,A lightweight and versatile netcat alternative that includes various additional features."
}

function install_metasploit() {
    colorecho "Installing Metasploit"
    mkdir /opt/tools/metasploit
    cd /opt/tools/metasploit
    curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && chmod 755 msfinstall
    add-test-command "msfconsole --version"
    add-to-list "metasploit,https://github.com/rapid7/metasploit-framework,A popular penetration testing framework that includes many exploits and payloads"
}

function configure_metasploit() {
    colorecho "Configuring Metasploit"
    cd /opt/tools/metasploit
    ./msfinstall
}

function install_routersploit() {
    colorecho "Installing RouterSploit"
    python3 -m pipx install routersploit
    python3 -m pipx inject routersploit colorama
    add-aliases routersploit
    add-test-command "which rsf.py"
    add-to-list "routersploit,https://github.com/threat9/routersploit,Security audit tool for routers."
}
