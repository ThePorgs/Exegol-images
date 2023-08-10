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

function fapt-noexit() {
    # This function tries the same thing as fapt but doesn't exit in case something's wrong.
    # Example: a package exists in amd64 but not arm64. I didn't find a way of knowing that beforehand.
    colorecho "Installing (no-exit) apt package(s): $*"
    apt-get install -y --no-install-recommends "$*" || echo -e "${RED}[EXEGOL ERROR] Package(s) $* probably doesn't exist for architecture $(uname -m), or no installation candidate was found, or some other error...${NOCOLOR}" 2>&1
}

function fapt-history() {
    fapt "$@"
    for i in "$@"; do
        add-history "$i"
    done
}

function fapt-aliases() {
    fapt "$@"
    for i in "$@"; do
        add-aliases "$i"
    done
}

function fapt-history-aliases() {
    fapt "$@"
    for i in "$@"; do
        add-history "$i"
        add-aliases "$i"
    done
}

function set_go_env() {
    colorecho "Setting golang environment variables for installation"
    export GO111MODULE=on
    export PATH=$PATH:/usr/local/go/bin:/root/.local/bin
}

function set_ruby_env() {
    colorecho "Setting ruby environment variables for installation"
    source /usr/local/rvm/scripts/rvm
    rvm --default use 3.0.0
}

function install_pipx_git_tool() {
    colorecho "Installing $2 with pipx"
    python3 -m pipx install $1
    if [ "$3" ]
    then
        add-test-command $3
    fi
    if [[ "$*" == *"history"* ]]
    then
        add-history $2
    fi
}

function install_go_tool() {
    colorecho "Installing $2 with Golang"
    go install -v $1
    if [ "$3" ]
    then
        add-test-command $3
    fi
    if [[ "$*" == *"history"* ]]
    then
        add-history $2
    fi
}

function install_pipx_tool() {
    colorecho "Installing $1 with pipx"
    python3 -m pipx install $1
    if [ "$2" ]
    then
        add-test-command $2
    fi
    if [[ "$*" == *"history"* ]]
    then
        add-history $1
    fi
 }

function install_apt_tool() {
    colorecho "Installing $1 with apt"
    fapt $1
    if [ "$2" ]
    then
        add-test-command $2
    fi
    if [[ "$*" == *"history"* ]]
    then
        add-history $1
    fi

    if [[ "$*" == *"aliases"* ]]
    then
        add-aliases $1
    fi
}