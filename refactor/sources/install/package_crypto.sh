#!/bin/bash
# Author: The Exegol Project

source common.sh

# Package dedicated to attack crypto
function package_crypto() {
    # install_rsactftool            # attack rsa FIXME
    install_tls-map                 # CLI & library for mapping TLS cipher algorithm names: IANA, OpenSSL, GnuTLS, NSS
}

function install_tls-map() {
    colorecho "Installing TLS map"
    # TODO: gem venv
    gem install tls-map
    add-history tls-map
    add-test-command "tls-map --help"
}