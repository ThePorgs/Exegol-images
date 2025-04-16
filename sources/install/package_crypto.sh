#!/bin/bash
# Author: The Exegol Project

source common.sh

function install_crypto_apt_tools() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing crypto apt tools"

    fapt sagemath

    add-history sage

    add-test-command "sage --help"

    add-to-list "sage,https://www.sagemath.org,SageMath is a free open-source mathematics software system licensed under the GPL."

}

function install_tls-map() {
    colorecho "Installing TLS map"
    rvm use 3.2.2@tls-map --create
    gem install tls-map
    rvm use 3.2.2@default
    add-aliases tls-map
    add-history tls-map
    add-test-command "tls-map --help"
    add-to-list "tls-map,https://github.com/sec-it/tls-map,tls-map is a library for mapping TLS cipher algorithm names."
}

function install_rsactftool() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing Rsactftool"
    pipx install --system-site-packages git+https://github.com/RsaCtfTool/RsaCtfTool
    add-history rsactftool
    add-test-command "RsaCtfTool --help"
    add-to-list "rsactftool,https://github.com/RsaCtfTool/RsaCtfTool,The rsactftool tool is used for RSA cryptographic operations and analysis."
}

function install_rsacracker() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing RsaCracker"
    source "$HOME/.cargo/env"
    cargo install rsacracker
    add-history rsacracker
    add-test-command "rsacracker --help"
    add-to-list "RsaCracker,https://github.com/skyf0l/RsaCracker,Powerful RSA cracker for CTFs. Supports RSA - X509 - OPENSSH in PEM and DER formats."
}

# Package dedicated to attack crypto
function package_crypto() {
    set_env
    local start_time
    local end_time
    start_time=$(date +%s)
    install_crypto_apt_tools  
    install_rsactftool              # attack rsa
    install_tls-map                 # CLI & library for mapping TLS cipher algorithm names: IANA, OpenSSL, GnuTLS, NSS
    install_rsacracker              # Powerful RSA cracker for CTFs. Supports RSA, X509, OPENSSH in PEM and DER formats.
    post_install
    end_time=$(date +%s)
    local elapsed_time=$((end_time - start_time))
    colorecho "Package crypto completed in $elapsed_time seconds."
}
