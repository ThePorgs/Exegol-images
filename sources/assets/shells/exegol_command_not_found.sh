# shellcheck shell=bash
# Hint for a command Exegol does not ship. Sourced from exegol_shells_rc.
# Runs only after PATH lookup fails, so a later install of the real command wins.
# Bash and zsh. Print the hint on stderr and leave the command status at 127.
# Table: /opt/.exegol_missing_commands (CSV: command,suggestion).

exegol_missing_command_hint() {
    local cmd="$1"
    local file="/opt/.exegol_missing_commands"
    local suggestion green="" reset=""

    case "$cmd" in
        ""|*/*) return 1 ;;
    esac
    [ -f "$file" ] || return 1

    suggestion=$(awk -F ',' -v c="$cmd" '
        $0 ~ /^[[:space:]]*#/ { next }
        $1 == "command" { next }
        $1 == c && $2 != "" { print $2; found = 1; exit }
        END { exit !found }
    ' "$file") || return 1

    if [ -t 2 ]; then
        green=$'\033[32m'
        reset=$'\033[0m'
    fi
    printf "%s isn't installed. Try %s%s%s instead." "$cmd" "$green" "$suggestion" "$reset" >&2
    if ! command -v "$suggestion" >/dev/null 2>&1; then
        printf " %s%s%s is not in this container." "$green" "$suggestion" "$reset" >&2
    fi
    printf "\n" >&2
    return 0
}

exegol_command_not_found() {
    if exegol_missing_command_hint "$1"; then
        return 127
    fi
    if [ -n "${ZSH_VERSION:-}" ]; then
        printf "zsh: command not found: %s\n" "$1" >&2
    else
        printf "bash: %s: command not found\n" "$1" >&2
    fi
    return 127
}

if [ -n "${ZSH_VERSION:-}" ]; then
    command_not_found_handler() {
        exegol_command_not_found "$@"
    }
elif [ -n "${BASH_VERSION:-}" ]; then
    command_not_found_handle() {
        exegol_command_not_found "$@"
    }
fi
