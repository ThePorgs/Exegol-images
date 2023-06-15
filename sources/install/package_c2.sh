#!/bin/bash
# Author: The Exegol Project

source common.sh

function install_pwncat() {
    colorecho "Installing pwncat"
    python3 -m pipx install pwncat-cs
    add-test-command "pwncat-cs --version"
    add-to-list "pwncat,https://github.com/calebstewart/pwncat,A lightweight and versatile netcat alternative that includes various additional features."
}

function install_metasploit() {
    colorecho "Installing Metasploit"
    fapt libpcap-dev libpq-dev zlib1g-dev libsqlite3-dev
    mkdir /tmp/metasploit_install
    cd /tmp/metasploit_install
    curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb -o msfinstall
    chmod +x msfinstall
    ./msfinstall
    cd /tmp
    rm -rf /tmp/metasploit_install
    add-aliases msfconsole
    add-test-command "msfconsole --help"
    add-to-list "metasploit,https://github.com/rapid7/metasploit-framework,A popular penetration testing framework that includes many exploits and payloads"
}

function configure_metasploit() {
    colorecho "Configuring Metasploit"
    cd /opt/metasploit-framework/embedded/framework
    bundle install
}

function install_routersploit() {
    colorecho "Installing RouterSploit"
    python3 -m pipx install routersploit
    python3 -m pipx inject routersploit colorama
    add-aliases routersploit
    add-test-command "which rsf.py"
    add-to-list "routersploit,https://github.com/threat9/routersploit,Security audit tool for routers."
}

function install_sliver() {
    colorecho "Installing Sliver"
    git -C /opt/tools/ clone https://github.com/BishopFox/sliver.git
    cd /opt/tools/sliver
    make
    cp sliver-* /opt/tools/bin
    add-history sliver
    add-test-command "sliver-server help"
    add-test-command "sliver-client help"
}

# Package dedicated to command & control frameworks
function package_c2() {
    set_go_env
    # install_empire                # Exploit framework FIXME
    # install_starkiller            # GUI for Empire, commenting while Empire install is not fixed
    install_pwncat                  # netcat and rlwrap on steroids to handle revshells, automates a few things too
    install_metasploit              # Offensive framework
    install_routersploit            # Exploitation Framework for Embedded Devices
    install_sliver                  # Sliver is an open source cross-platform adversary emulation/red team framework
}

function package_c2_configure() {
    configure_metasploit
}
