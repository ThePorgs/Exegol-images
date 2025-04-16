#!/bin/bash
# Author: The Exegol Project

export RED='\033[1;31m'
export BLUE='\033[1;34m'
export GREEN='\033[1;32m'
export NOCOLOR='\033[0m'

### Echo functions

function colorecho () {
    echo -e "${BLUE}[EXEGOL] $*${NOCOLOR}"
}

function criticalecho () {
    echo -e "${RED}[EXEGOL ERROR] $*${NOCOLOR}" 2>&1
    exit 1
}

function criticalecho-noexit () {
    echo -e "${RED}[EXEGOL ERROR] $*${NOCOLOR}" 2>&1
}

### Support functions

function add-to-list() {
  echo "$1" >> "/.exegol/installed_tools.csv"
}

function add-aliases() {
    colorecho "Adding aliases for: $*"
    # Removing add empty lines and the last trailing newline if any, and adding a trailing newline.
    grep -vE "^\s*$" "/root/sources/assets/shells/aliases.d/$*" | tee -a /opt/.exegol_aliases
}

function add-history() {
    colorecho "Adding history commands for: $*"
    # Removing add empty lines and the last trailing newline if any, and adding a trailing newline.
    grep -vE "^\s*$" "/root/sources/assets/shells/history.d/$*" | tee -a /opt/.exegol_history
}

function add-test-command() {
    colorecho "Adding build pipeline test command: $*"
    echo "$*" >> "/.exegol/unit_tests_all_commands.txt"
}

function fapt() {
    colorecho "Installing apt package(s): $*"
    # Do apt-get update only when no list are found
    if [ -z "$( ls -A '/var/lib/apt/lists/' )" ]; then
      apt-get update
    fi
    apt-fast install -y --no-install-recommends "$@"
}

function set_cargo_env() {
    colorecho "Setting cargo environment"
    source "$HOME/.cargo/env"
}

function set_ruby_env() {
    colorecho "Setting ruby environment"
    source /usr/local/rvm/scripts/rvm
    rvm use 3.2.2@default
}

function set_python_env() {
    colorecho "Setting pyenv environment"
    # add pyenv to PATH
    export PATH="/root/.pyenv/bin:$PATH"
    # add python commands (pyenv shims) to PATH
    eval "$(pyenv init --path)"
}

function set_bin_path() {
    colorecho "Adding /opt/tools/bin to PATH"
    export PATH="/opt/tools/bin:$PATH"
}

function set_asdf_env(){
    colorecho "Setting asdf environment"
    export PATH="${ASDF_DATA_DIR:-$HOME/.asdf}/shims:$PATH"
}

function set_build_only_env(){
    # Here you can set environment variables that are only needed during the build process
    colorecho "Setting build only environment"
    
    # Make curl fails on HTTP errors (4xx and 5xx) because it doesn't by default
    export CURL_HOME="/root/sources/assets/shells/" # Curl will search for .curlrc in this directory
    # Make wget a bit less verbose
    export WGETRC="/root/sources/assets/shells/wgetrc"
}

function set_env() {
    colorecho "Setting env (caller)"
    set_bin_path
    set_cargo_env
    set_ruby_env
    set_python_env
    set_asdf_env
    set_build_only_env
}

function post_install() {
    # Function used to clean up post-install files
    colorecho "Cleaning..."
    updatedb
    rm -rf /root/.bundle/cache
    rm -rf /root/.cache
    rm -rf /root/.cargo/registry
    rm -rf /root/.gradle/caches
    rm -rf /root/.npm/_cacache
    rm -rf /root/.nvm/.cache
    rm -rf /tmp/*
    rm -rf /var/lib/apt/lists/*

    colorecho "Stop listening processes"
    local listening_processes
    listening_processes=$(ss -lnpt | awk -F"," 'NR>1 {split($2,a,"="); print a[2]}')
    if [[ -n $listening_processes ]]; then
        echo "Listening processes detected"
        ss -lnpt
        echo "Kill processes"
        # shellcheck disable=SC2086
        kill -9 $listening_processes
    fi
}

function post_build() {
    colorecho "Post build..."
    rm -rfv /root/sources
    add-test-command "if [[ $(sudo ss -lnpt | tail -n +2 | wc -l) -ne 0 ]]; then ss -lnpt && false;fi"
    colorecho "Sorting tools list"
    (head -n 1 /.exegol/installed_tools.csv && tail -n +2 /.exegol/installed_tools.csv | sort -f ) | tee /tmp/installed_tools.csv.sorted
    mv /tmp/installed_tools.csv.sorted /.exegol/installed_tools.csv
    colorecho "Adding end-of-preset in zsh_history"
    echo "# -=-=-=-=-=-=-=- YOUR COMMANDS BELOW -=-=-=-=-=-=-=- #" >> /opt/.exegol_history
    cp /opt/.exegol_history ~/.zsh_history
    cp /opt/.exegol_history ~/.bash_history
    colorecho "Removing desktop icons"
    if [ -d "/root/Desktop" ]; then rm -r /root/Desktop; fi
}