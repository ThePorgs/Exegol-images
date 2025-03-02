#!/bin/bash
# Author: The Exegol Project

# Functions and commands that will be retried multiple times to counter random network issues when building
CATCH_AND_RETRY_COMMANDS=("curl" "wget" "apt-fast" "git" "go" "apt-get" "nvm" "npm" "pipx" "pip2" "pip3" "cargo" "gem")

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
    echo "$*" >> "/.exegol/build_pipeline_tests/all_commands.txt"
}

function fapt() {
    colorecho "Installing apt package(s): $*"
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

function set_env() {
    colorecho "Setting env (caller)"
    set_bin_path
    set_cargo_env
    set_ruby_env
    set_python_env
    set_asdf_env
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
  local command="$*"
  # escaping characters that could mess with the sh execution
  local escaped_command
  # not double-quoting $command as it would escape spaces inside the command and we don't want that
  # shellcheck disable=SC2086
  escaped_command=$(printf '%q ' $command)
  for ((i=1; i<=retries; i++)); do
    # sh -c is used instead of an "eval" in order to avoid an infinite loop
    #  for instance, with an "eval", "wget" would point to the "wget" function defined with define_retry_function()
    # TODO : there is a limitation to this approach. It escapes metachars as well (like &&, ;, ||,)
    #  it means commands like "cmd1 && cmd2" won't work and will be interpreted as "cmd1 \&\& cmd2"
    echo "[EXEGOL DEBUG] sh -c \"$escaped_command\""
    # If command exits successfully, no need for more retries
    sh -c "$escaped_command" && return 0
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
    catch_and_retry \"$original_command \$@\"
  }
  "
}

# Dynamically create wrappers
for CMD in "${CATCH_AND_RETRY_COMMANDS[@]}"; do
  define_retry_function "$CMD"
done

function measure() {
  echo -e "${BLUE}[EXEGOL MEASURE] Start measuring '$*'${NOCOLOR}"

  # Initial start time and disk usage in bytes
  local start_time
  start_time=$(date +%s)
  local initial_space
  initial_space=$(df --output=used / | tail -1) # df is not fully accurate but fast and good enough

  # Run the command
  "$@"

  # Calculate elapsed time and disk usage change
  local end_time
  local final_space
  end_time=$(date +%s)
  final_space=$(df --output=used / | tail -1)
  local elapsed_time=$((end_time - start_time))
  local space_change=$((final_space - initial_space))

  # Convert disk usage change to human-readable format
  local space_change_human
  space_change_human=$(numfmt --to=iec-i --suffix=B -- $((space_change * 1024)))

  echo -e "${BLUE}[EXEGOL MEASURE] '$*' took ${elapsed_time} seconds, Disk Usage change: ${space_change_human}${NOCOLOR}"
  echo "$*,${elapsed_time}s,${space_change_human}" >> /.exegol/measure.csv
}

function define_measure_function() {
  local original_fn="$1"

  # Redefine the function to include measurement if not already done
  if ! declare -F "measured_$fn" > /dev/null; then
    eval "
    measured_${original_fn}() { $(declare -f "$original_fn" | tail -n +2); }
    ${original_fn}() {
        measure measured_${original_fn} \"\$@\"
    }
    "
  fi
}

function setup_measure() {
  # Find and wrap all functions starting by 'install_'
  for fn in $(declare -F | awk '{print $3}' | grep '^install_'); do
    define_measure_function "$fn"
  done
}

function post_install() {
    # Function used to clean up post-install files
    colorecho "Cleaning..."
    local listening_processes
    updatedb
    rm -rfv /tmp/*
    rm -rfv /var/lib/apt/lists/*
    rm -rfv /root/.cache
    rm -rfv /root/.gradle/caches
    colorecho "Stop listening processes"
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