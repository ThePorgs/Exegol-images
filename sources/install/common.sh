#!/bin/bash
# Author: The Exegol Project

export RED='\033[1;31m'
export BLUE='\033[1;34m'
export GREEN='\033[1;32m'
export NOCOLOR='\033[0m'


### Support functions

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

function add-to-list() {
  echo $1 >> "/.exegol/installed_tools.csv"
}

function add-aliases() {
    colorecho "Adding aliases for: $*"
    # Removing add empty lines and the last trailing newline if any, and adding a trailing newline.
    grep -vE "^\s*$" "/root/sources/assets/zsh/aliases.d/$*" | tee -a /opt/.exegol_aliases
}

function add-history() {
    colorecho "Adding history commands for: $*"
    # Removing add empty lines and the last trailing newline if any, and adding a trailing newline.
    grep -vE "^\s*$" "/root/sources/assets/zsh/history.d/$*" | tee -a ~/.zsh_history
}

function add-test-command() {
    colorecho "Adding build pipeline test command: $*"
    echo "$*" >> "/.exegol/build_pipeline_tests/all_commands.txt"
}

function fapt() {
    colorecho "Installing apt package(s): $*"
    /usr/local/sbin/apt-fast install -y --no-install-recommends "$@"
}

function set_go_env() {
    colorecho "Setting golang environment variables for installation"
    export GO111MODULE=on
    export PATH=$PATH:/usr/local/go/bin:/root/.local/bin
}

function set_ruby_env() {
    colorecho "Setting ruby environment variables for installation"
    source /usr/local/rvm/scripts/rvm
    rvm use 3.0.0@default
}