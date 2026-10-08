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
    version="$(apt_version hashcat)"
    add-to-list "hashcat,${version},https://hashcat.net/hashcat,A tool for advanced password recovery"
    version="$(apt_version fcrackzip)"
    add-to-list "fcrackzip,${version},https://github.com/hyc/fcrackzip,Password cracker for zip archives."
    version="$(apt_version pdfcrack)"
    add-to-list "pdfcrack,${version},https://github.com/robins/pdfcrack,A tool for cracking password-protected PDF files"
    version="$(apt_version bruteforce-luks)"
    add-to-list "bruteforce-luks,${version},https://github.com/glv2/bruteforce-luks,A tool to help recover encrypted LUKS2 containers"
}

function install_john() {
    colorecho "Installing john the ripper"
    git -C /opt/tools/ clone --depth 1 https://github.com/openwall/john
    cd /opt/tools/john/src || exit
    ./configure --disable-native-tests && make
    yes|cpan install Compress::Raw::Lzma
    # Python *2john helpers are on PATH via $JOHN (#!/usr/bin/env python).
    # Upstream doc/INSTALL uses: venv + pip install -r requirements.txt (~130MB).
    # We ship a curated subset (~16MB after stripping pip/setuptools) for the common
    # helpers; omitted niche deps: scapy (pcap/radius/oracle/apop), pytsk3+cryptography
    # (fvde), pyhanko (pdf2john.py — use pdf2john.pl), lxml (krb), ldap3 (sspr), bsddb3
    # (bitcoin). Full set remains: cd /opt/tools/john/run && python3 -m venv venv && ...
    cd /opt/tools/john/run || exit
    python3 -m venv --system-site-packages ./venv
    source ./venv/bin/activate
    pip3 install --no-cache-dir asn1crypto pycryptodome olefile parsimonious cbor2 simplejson protobuf
    pip3 uninstall -y pip setuptools wheel
    deactivate
    find ./venv -type d -name '__pycache__' -prune -exec rm -rf {} +
    find . -maxdepth 1 -type f -name '*.py' -exec sed -i '1s|^#![[:space:]]*/usr/bin/env python[^ ]*|#!/opt/tools/john/run/venv/bin/python3|' {} +
    cd / || exit
    add-aliases john-the-ripper
    add-history john-the-ripper
    add-test-command "john --help"
    add-test-command "7z2john.pl|& grep 'Usage'"
    add-test-command "ssh2john.py|& grep 'Usage'"
    add-test-command "pfx2john.py|& grep 'Usage'"
    add-test-command "pem2john.py|& grep 'Usage'"
    local version
    version="$(git_version /opt/tools/john)"
    add-to-list "john,${version},https://github.com/openwall/john,John the Ripper password cracker."
}

function install_name-that-hash() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing Name-That-Hash"
    pipx install --system-site-packages name-that-hash
    add-history name-that-hash
    add-test-command "nth --help"
    local version
    version="$(pipx_version name-that-hash)"
    add-to-list "name-that-hash,${version},https://github.com/HashPals/Name-That-Hash,Online tool for identifying hashes."
}

function install_haiti() {
    colorecho "Installing haiti"
    rvm use 3.2.2@haiti --create
    gem install haiti-hash
    rvm use 3.2.2@default
    add-aliases haiti
    add-history haiti
    add-test-command "haiti --help"
    local version
    version="$(gem_version haiti-hash)"
    add-to-list "haiti,${version},https://github.com/noraj/haiti,haiti is a A CLI tool (and library) to identify hash types (hash type identifier)."
}

function install_geowordlists() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing GeoWordlists"
    pipx install --system-site-packages git+https://github.com/p0dalirius/GeoWordlists
    add-history geowordlists
    add-test-command "geowordlists --help"
    local version
    version="$(pipx_version GeoWordlists)"
    add-to-list "geowordlists,${version},https://github.com/p0dalirius/GeoWordlists,tool to generate wordlists of passwords containing cities at a defined distance around the client city."
}

function install_pkcrack() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing pkcrack"
    git -C /opt/tools/ clone --depth 1 https://github.com/keyunluo/pkcrack
    mkdir -v /opt/tools/pkcrack/build/
    cd /opt/tools/pkcrack/build || exit
    cmake ..
    make -j
    ln -s /opt/tools/pkcrack/bin/pkcrack /opt/tools/bin
    ln -s /opt/tools/pkcrack/bin/zipdecrypt /opt/tools/bin
    add-history pkcrack
    add-test-command 'pkcrack --help |& grep "Usage"'
    local version
    version="$(git_version /opt/tools/pkcrack)"
    add-to-list "pkcrack,${version},https://github.com/keyunluo/pkcrack,tool to generate wordlists of passwords containing cities at a defined distance around the client city"
}

function install_firefox_decrypt() {
    # CODE-CHECK-WHITELIST=add-aliases,add-history
    colorecho "Installing firefox_decrypt"
    pipx install --system-site-packages git+https://github.com/unode/firefox_decrypt
    add-test-command "firefox-decrypt --help"
    local version
    version="$(pipx_version firefox_decrypt)"
    add-to-list "firefox_decrypt,${version},https://github.com/unode/firefox_decrypt,Decrypt Firefox saved passwords."
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
    install_firefox_decrypt         # Decrypt Firefox saved passwords
    post_install
    end_time=$(date +%s)
    local elapsed_time=$((end_time - start_time))
    colorecho "Package cracking completed in $elapsed_time seconds."
}
