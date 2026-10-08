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

### Version helpers (for installed_tools.csv Version column)
# Each helper prints one version token or an empty string. They must not fail the build.

function normalize_version() {
    local version="${1:-}"
    local y m d
    # trim whitespace / newlines
    version="$(printf '%s' "$version" | tr -d '\r' | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
    # strip a single leading v/V before a digit
    if [[ "$version" =~ ^[vV][0-9] ]]; then
        version="${version:1}"
    fi
    # strip Debian/Ubuntu epoch (1:1.7 -> 1.7)
    if [[ "$version" =~ ^[0-9]+: ]]; then
        version="${version#*:}"
    fi
    # Go pseudo-version v0.0.0-YYYYmmddHHMMSS-abcdef -> YYYY-MM-DD
    if [[ "$version" =~ ^0\.0\.0-([0-9]{8})[0-9]{6}-[0-9a-f]+$ ]]; then
        y="${BASH_REMATCH[1]:0:4}"
        m="${BASH_REMATCH[1]:4:2}"
        d="${BASH_REMATCH[1]:6:2}"
        version="${y}-${m}-${d}"
    fi
    # Reject placeholder / unusable versions
    case "$version" in
        ''|0.0.0|0.1.0|unknown|null|none|Undefined|undefined)
            return 0
            ;;
    esac
    # Reject 0.0.0+local / 0.0.0.post... style placeholders
    if [[ "$version" == 0.0.0+* || "$version" == 0.0.0.* ]]; then
        return 0
    fi
    printf '%s' "$version"
}

function git_version() {
    local path="${1:-}"
    local tag date
    if [[ -z "$path" || ! -d "$path" ]]; then
        return 0
    fi
    tag="$(git -C "$path" describe --exact-match --tags 2>/dev/null || true)"
    if [[ -n "$tag" ]]; then
        normalize_version "$tag"
        return 0
    fi
    # Untagged shallow clones: commit date is more useful for changelogs than a short SHA
    date="$(git -C "$path" log -1 --format=%cs 2>/dev/null || true)"
    normalize_version "$date"
}

function pipx_version() {
    local name="${1:-}"
    local version
    if [[ -z "$name" ]]; then
        return 0
    fi
    version="$(pipx list --json 2>/dev/null | jq -r --arg n "$name" '
        .venvs as $v
        | ($v[$n] // $v[$n | ascii_downcase] // empty)
        | .metadata.main_package.package_version // empty
    ' 2>/dev/null || true)"
    normalize_version "$version"
}

function apt_version() {
    local pkg="${1:-}"
    local version
    if [[ -z "$pkg" ]]; then
        return 0
    fi
    version="$(dpkg-query -W -f='${Version}' "$pkg" 2>/dev/null || true)"
    normalize_version "$version"
}

function go_version() {
    local bin="${1:-}"
    local real modversion
    if [[ -z "$bin" ]]; then
        return 0
    fi
    # asdf shims are not Go binaries; resolve the real install path first
    if command -v asdf >/dev/null 2>&1; then
        real="$(asdf which "$bin" 2>/dev/null || true)"
    fi
    if [[ -z "$real" || ! -f "$real" ]]; then
        real="$(command -v "$bin" 2>/dev/null || true)"
    fi
    if [[ -z "$real" || ! -f "$real" ]]; then
        return 0
    fi
    # Prefer the module version line from build info
    modversion="$(go version -m "$real" 2>/dev/null | awk '/^\tmod\t/ { print $3; exit }' || true)"
    normalize_version "$modversion"
}

function cargo_version() {
    local name="${1:-}"
    local version
    if [[ -z "$name" ]]; then
        return 0
    fi
    version="$(cargo install --list 2>/dev/null | awk -v n="$name" '
        $1 == n {
            ver=$2
            sub(/^v/, "", ver)
            sub(/:$/, "", ver)
            print ver
            exit
        }
    ' || true)"
    normalize_version "$version"
}

function gem_version() {
    local name="${1:-}"
    local version
    if [[ -z "$name" ]]; then
        return 0
    fi
    version="$(gem list -l "^${name}$" 2>/dev/null | awk -v n="$name" '
        $1 == n {
            gsub(/[()]/, "", $2)
            split($2, parts, /,/)
            print parts[1]
            exit
        }
    ' || true)"
    normalize_version "$version"
}

function github_release_version() {
    local repo="${1:-}"
    local tempfile tag
    if [[ -z "$repo" ]]; then
        return 0
    fi
    tempfile="$(mktemp)"
    if curl --location --silent "https://api.github.com/repos/${repo}/releases/latest" -o "${tempfile}" 2>/dev/null; then
        tag="$(jq -r '.tag_name // empty' "${tempfile}" 2>/dev/null || true)"
    fi
    rm -f "${tempfile}"
    normalize_version "$tag"
}

function cli_version() {
    # usage: cli_version tool --version
    #        cli_version tool version
    local out version candidate
    if [[ $# -lt 1 ]]; then
        return 0
    fi
    # Bound runtime so a hanging CLI cannot stall the image build
    out="$(timeout 8 "$@" 2>&1)" || true
    # Strip ANSI color codes and log prefixes that inject timestamps
    out="$(printf '%s' "$out" | sed -E 's/\x1b\[[0-9;]*m//g')"
    out="$(printf '%s' "$out" | sed -E '/^time="/d')"

    # Prefer an explicit "Version:" / "version:" field (k9s, nuclei, …)
    version="$(printf '%s' "$out" | grep -ioE 'version[:[:space:]]+v?[0-9]+([._-][0-9A-Za-z]+){1,6}' | head -n1 | grep -oE 'v?[0-9]+([._-][0-9A-Za-z]+){1,6}' | head -n1 || true)"
    if [[ -n "$version" ]]; then
        normalize_version "$version"
        return 0
    fi

    # Otherwise scan tokens; require at least major.minor (reject bare "2", dates-only, SHAs)
    while read -r candidate; do
        [[ -z "$candidate" ]] && continue
        # skip ISO dates / datetimes
        if [[ "$candidate" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2} ]]; then
            continue
        fi
        # skip compact timestamps YYYYmmddHHMMSS
        if [[ "$candidate" =~ ^[0-9]{14}$ ]]; then
            continue
        fi
        # skip bare integers / short junk (build numbers, flag leftovers)
        if [[ "$candidate" =~ ^[0-9]{1,6}$ ]]; then
            continue
        fi
        # skip git SHAs
        if [[ "$candidate" =~ ^[0-9a-fA-F]{7,40}$ ]]; then
            continue
        fi
        # require a dotted / underscored multi-part version
        if [[ ! "$candidate" =~ [0-9]+[._-][0-9A-Za-z]+ ]]; then
            continue
        fi
        normalize_version "$candidate"
        return 0
    done < <(printf '%s' "$out" | grep -oE 'v?[0-9]+([._-][0-9A-Za-z]+){0,6}' || true)
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

function add-test-gui-command() {
    colorecho "Adding build pipeline test gui command: $*"
    echo "$*" >> "/.exegol/unit_tests_gui_commands.txt"
}

function fapt() {
    colorecho "Installing apt package(s): $*"
    # Do apt-get update only when no list are found
    if [ -z "$( ls -A '/var/lib/apt/lists/' )" ]; then
      apt-get update
    fi
    apt-fast install -y --no-install-recommends "$@"
}

function install_wkhtmltopdf() {
    # CODE-CHECK-WHITELIST=add-aliases,add-history,add-test-command,add-to-list
    colorecho "Installing wkhtmltopdf (upstream bookworm package)"
    local deb_arch deb url
    case "$(uname -m)" in
        x86_64) deb_arch="amd64" ;;
        aarch64) deb_arch="arm64" ;;
        *) criticalecho-noexit "This installation function doesn't support architecture $(uname -m)" && return ;;
    esac
    deb="wkhtmltox_0.12.6.1-3.bookworm_${deb_arch}.deb"
    url="https://github.com/wkhtmltopdf/packaging/releases/download/0.12.6.1-3/${deb}"
    wget -O "/tmp/${deb}" "$url"
    # Local .deb via apt so runtime deps are resolved.
    fapt "/tmp/${deb}"
    rm -f "/tmp/${deb}"
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

# Find UID ownership of unknown user for unprivileged lxc image download
function fix_ownership() {
  find "$1" -type l -uid +2000 '!' -user nobody -exec chown -h root:root {} \; 2>/dev/null
  find "$1" -uid +2000 '!' -user nobody -exec chown root:root {} \; 2>/dev/null
}

function post_install() {
    # Function used to clean up post-install files
    colorecho "Cleaning..."

    # language/tool caches
    rm -rf /root/.asdf/installs/golang/*/packages/pkg/mod
    rm -rf /root/.bundle/cache
    rm -rf /root/.cache
    rm -rf /root/.cargo/registry
    rm -rf /root/.gradle/caches
    rm -rf /root/.local/state/pipx/log
    rm -rf /root/.npm/_cacache
    rm -rf /root/.nvm/.cache

    # temp + apt
    rm -rf /tmp/*
    rm -rf /var/lib/apt/lists/*

    # debconf cache
    rm -rf /var/cache/debconf

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

    colorecho "Build database for locate command"
    updatedb

    colorecho "Sorting tools list"
    (head -n 1 /.exegol/installed_tools.csv && tail -n +2 /.exegol/installed_tools.csv | sort -f ) | tee /tmp/installed_tools.csv.sorted
    mv /tmp/installed_tools.csv.sorted /.exegol/installed_tools.csv


    colorecho "Removing comments from zsh_history"
    grep -v '^#' /opt/.exegol_history > /tmp/.exegol_history.filtered
    mv /tmp/.exegol_history.filtered /opt/.exegol_history
    
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
