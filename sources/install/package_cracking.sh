#!/bin/bash
# Author: The Exegol Project

source common.sh

function install_cracking_apt_tools() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing cracking apt tools"
    fapt hashcat fcrackzip pdfcrack bruteforce-luks

    add-history hashcat
    add-history fcrackzip
    add-history pdfcrack
    add-history bruteforce-luks

    add-test-command "hashcat --help"                                   # Password cracker
    add-test-command "fcrackzip --help"                                 # Zip cracker
    add-test-command "pdfcrack --version"                               # PDF cracker
    add-test-command "bruteforce-luks -h |& grep 'Print progress info'" # Find the password of a LUKS encrypted volume

    local version
    version=$(hashcat --version)
    local version
    version=$(fcrackzip --version | awk '{print $3}')
    local version
    version=$(pdfcrack --version | awk '{print $3}')
    local version
    version=$(bruteforce-luks -h |& grep bruteforce-luks | head -n 1 | awk '{print $2}')

    add-to-list "hashcat,https://hashcat.net/hashcat,A tool for advanced password recovery,$version"
    add-to-list "fcrackzip,https://github.com/hyc/fcrackzip,Password cracker for zip archives.,$version"
    add-to-list "pdfcrack,https://github.com/robins/pdfcrack,A tool for cracking password-protected PDF files,$version"
    add-to-list "bruteforce-luks,https://github.com/glv2/bruteforce-luks,A tool to help recover encrypted LUKS2 containers,$version"
}

function install_john() {
    colorecho "Installing john the ripper"
    git -C /opt/tools/ clone --depth 1 https://github.com/openwall/john
    cd /opt/tools/john/src || exit
    ./configure --disable-native-tests && make
    yes|cpan install Compress::Raw::Lzma
    add-aliases john-the-ripper
    add-history john-the-ripper
    local version
    version=$(john --help | head -n 1 | awk '{print $4}')
    add-test-command "john --help"
    add-test-command "7z2john.pl|& grep 'Usage'"
    add-to-list "john,https://github.com/openwall/john,John the Ripper password cracker.,$version"
}

function install_name-that-hash() {
    # CODE-CHECK-WHITELIST=add-aliases,add-version
    colorecho "Installing Name-That-Hash"
    pipx install --system-site-packages name-that-hash
    add-history name-that-hash
    add-test-command "nth --help"
    add-to-list "name-that-hash,https://github.com/HashPals/Name-That-Hash,Online tool for identifying hashes.,$version"
}

function install_haiti() {
    colorecho "Installing haiti"
    rvm use 3.2.2@haiti --create
    gem install haiti-hash
    rvm use 3.2.2@default
    add-aliases haiti
    add-history haiti
    local version
    version=$(haiti --version)
    add-test-command "haiti --help"
    add-to-list "haiti,https://github.com/noraj/haiti,haiti is a A CLI tool (and library) to identify hash types (hash type identifier).,$version"
}

function install_geowordlists() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing GeoWordlists"
    pipx install --system-site-packages git+https://github.com/p0dalirius/GeoWordlists
    add-history geowordlists
    local version
    version=$(geowordlists --help | head -n 1 | awk '{print $2}')
    add-test-command "geowordlists --help"
    add-to-list "geowordlists,https://github.com/p0dalirius/GeoWordlists,tool to generate wordlists of passwords containing cities at a defined distance around the client city.,$version"
}

function install_pkcrack() {
    # CODE-CHECK-WHITELIST=add-aliases,add-version
    colorecho "Installing pkcrack"
    git -C /opt/tools/ clone --depth 1 https://github.com/keyunluo/pkcrack
    mkdir -v /opt/tools/pkcrack/build/
    cd /opt/tools/pkcrack/build || exit
    cmake ..
    make
    ln -s /opt/tools/pkcrack/bin/pkcrack /opt/tools/bin
    ln -s /opt/tools/pkcrack/bin/zipdecrypt /opt/tools/bin
    add-history pkcrack
    add-test-command 'pkcrack --help |& grep "Usage"'
    add-to-list "pkcrack,https://github.com/keyunluo/pkcrack,tool to generate wordlists of passwords containing cities at a defined distance around the client city,$version"
}

# Package dedicated to offline cracking/bruteforcing tools
function package_cracking() {
    set_env
    local start_time
    local end_time
    start_time=$(date +%s)
    install_cracking_apt_tools
    install_john                    # Password cracker
    install_name-that-hash          # Name-That-Hash, the hash identifier tool
    install_haiti                   # haiti, hash type identifier
    install_geowordlists            # wordlists generator
    install_pkcrack                 # known plaintext ZIP cracker
    end_time=$(date +%s)
    local elapsed_time=$((end_time - start_time))
    colorecho "Package cracking completed in $elapsed_time seconds."
}
