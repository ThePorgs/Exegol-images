#!/bin/bash
# Author: The Exegol Project

source common.sh

function install_cracking_apt_tools() {
    fapt hashcat fcrackzip pdfcrack bruteforce-luks

    add-history hashcat
    add-history fcrackzip

    add-test-command "hashcat --help"                                   # Password cracker
    add-test-command "fcrackzip --help"                                 # Zip cracker
    add-test-command "pdfcrack --version"                               # PDF cracker
    add-test-command "bruteforce-luks -h |& grep 'Print progress info'" # Find the password of a LUKS encrypted volume

    add-to-list "hashcat,https://hashcat.net/hashcat,A tool for advanced password recovery"
    add-to-list "fcrackzip,https://github.com/hyc/fcrackzip,Password cracker for zip archives."
    add-to-list "pdfcrack,https://github.com/robins/pdfcrack,A tool for cracking password-protected PDF files"
    add-to-list "bruteforce-luks,https://github.com/glv2/bruteforce-luks,A tool to help recover encrypted LUKS2 containers"
}

function install_john() {
    colorecho "Installing john the ripper"
    git -C /opt/tools/ clone --depth 1 https://github.com/openwall/john
    add-aliases john-the-ripper
    add-history john-the-ripper
    add-test-command "john --help"
    add-to-list "john,https://github.com/openwall/john,John the Ripper password cracker."
}

function configure_john() {
    cd /opt/tools/john/src
    ./configure --disable-native-tests && make
}

function install_name-that-hash() {
    colorecho "Installing Name-That-Hash"
    python3 -m pipx install name-that-hash
    add-history name-that-hash
    add-test-command "nth --help"
    add-to-list "name-that-hash,https://github.com/HashPals/Name-That-Hash,Online tool for identifying hashes."
}

function install_haiti() {
    colorecho "Installing haiti"
    # TODO: Gem venv
    gem install haiti-hash
    add-history haiti
    add-test-command "haiti --help"
    add-to-list "haiti,https://github.com/noraj/haiti is a A CLI tool (and library) to identify hash types (hash type identifier)."
}

# Package dedicated to offline cracking/bruteforcing tools
function package_cracking() {
    install_cracking_apt_tools
    install_john                    # Password cracker
    install_name-that-hash          # Name-That-Hash, the hash identifier tool
    install_haiti                   # haiti, hash type identifier
}

function package_cracking_configure() {
    configure_john
}
