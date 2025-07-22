#!/bin/bash
# Author: The Exegol Project

# Functions and commands that will be retried multiple times to counter random network issues when building
CATCH_AND_RETRY_COMMANDS=("curl" "wget" "apt-fast" "git" "go" "apt-get" "nvm" "npm" "pip" "pipx" "pip2" "pip3" "cargo" "gem")

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

### Catch & retry definitions

function catch_and_retry() {
  local retries=5
  local i
  # wait time = scale_factor x (base_exponent ^ retry)
  local scale_factor=2  # scaling factor
  local base_exponent=4 # base of the exponent
  # 1st retry: 2×4^1 = 2×4    = 8 seconds
  # 2nd retry: 2×4^2 = 2×16   = 32 seconds
  # 3rd retry: 2×4^3 = 2×64   = 128 seconds
  # 4th retry: 2×4^4 = 2×256  = 512 seconds
  # 5th retry: 2×4^5 = 2×1024 = 2048 seconds
  local max_wait_time=600
  for ((i=1; i<=retries; i++)); do
    # $1 always point to the bin full path to avoid infinite function loop
    # $@ is used to split parameters and run the function
    # TODO : there is a limitation to this approach. It escapes metachars as well (like &&, ;, ||,)
    #  it means commands like "cmd1 && cmd2" won't work and will be interpreted as "cmd1 \&\& cmd2"
    echo "[EXEGOL C&R DEBUG]" "$@"
    # If command exits successfully, no need for more retries
    "$@" && return 0
    # Calculate the exponential backoff time
    local wait_time=$((scale_factor * (base_exponent ** i)))
    # Cap it at max_wait_time
    wait_time=$(( wait_time > max_wait_time ? max_wait_time : wait_time ))
    criticalecho-noexit "Command failed (attempt $i/$retries). Retrying in $wait_time seconds..."
    sleep "$wait_time"
  done
  criticalecho-noexit "Command failed definitively after $retries attempts."
  return 1
}

function define_retry_function() {
  local original_command=$1
  eval "
  function $original_command() {
    colorecho 'Catch & retry function for: $1'
    catch_and_retry \"\$(which $original_command)\" \"\$@\"
  }
  "
}

# Dynamically create wrappers
for CMD in "${CATCH_AND_RETRY_COMMANDS[@]}"; do
  define_retry_function "$CMD"
done

function post_install() {
    # Function used to clean up post-install files
    colorecho "Cleaning..."
    updatedb
    rm -rf /root/.asdf/installs/golang/*/packages/pkg/mod
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

function check_temp_fix_expiry() {
    # This function checks if a temporary fix has expired
    # Parameters:
    # $1: expiry date in YYYY-MM-DD format
    # Returns:
    # 0 if the fix should be applied (not expired or local build)
    # 1 if the fix has expired (and not a local build)
    
    local expiry_date="$1"
    
    # Apply the fix if it's a local build regardless of expiry
    if [[ "$EXEGOL_BUILD_TYPE" == "local" ]]; then
        return 0
    fi
    
    # Check if the current date is past the expiry date
    if [[ "$(date +%Y%m%d)" -gt "$(date -d "$expiry_date" +%Y%m%d)" ]]; then
        criticalecho "Temp fix expired. Exiting."
    fi
    
    # Not expired, apply the fix
    return 0
}
