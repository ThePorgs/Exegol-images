# shellcheck shell=bash
# Hint for a command Exegol does not ship. Sourced from exegol_shells_rc.
# Runs only after PATH lookup fails, so a later install of the real command wins.
# Bash and zsh. Print the hint on stderr and leave the command status at 127.
# Table: /opt/.exegol_missing_commands (CSV: command,suggestion), one line per old name.
# Written by add-suggestions. Several lines for one command are joined in order.

exegol_missing_command_hint() {
    local cmd="$1"
    local file="/opt/.exegol_missing_commands"
    local suggestions available suggestion red="" green="" reset=""
    local count=0 index=0

    case "$cmd" in
        ""|*/*) return 1 ;;
    esac
    [ -f "$file" ] || return 1

    suggestions=$(awk -F ',' -v c="$cmd" '
        $0 ~ /^[[:space:]]*#/ { next }
        $1 == "command" { next }
        $1 == c {
            for (i = 2; i <= NF; i++) if ($i != "" && !seen[$i]++) print $i
            found = 1
        }
        END { exit !found }
    ' "$file") || return 1

    # Smaller images do not ship every suggestion. Name only the ones on PATH.
    # If none are installed, stay quiet so the shell prints "command not found".
    available=$(printf '%s\n' "$suggestions" | while IFS= read -r suggestion; do
        [ -n "$suggestion" ] || continue
        command -v "$suggestion" >/dev/null 2>&1 || continue
        printf '%s\n' "$suggestion"
    done)
    [ -n "$available" ] || return 1

    if [ -t 2 ]; then
        red=$'\033[31m'
        green=$'\033[32m'
        reset=$'\033[0m'
    fi

    count=$(printf '%s\n' "$available" | grep -c .)
    printf "%s%s%s isn't installed. Try " "$red" "$cmd" "$reset" >&2
    printf '%s\n' "$available" | while IFS= read -r suggestion; do
        [ -n "$suggestion" ] || continue
        index=$((index + 1))
        if [ "$index" -gt 1 ]; then
            if [ "$index" -eq "$count" ]; then
                printf " or " >&2
            else
                printf ", " >&2
            fi
        fi
        printf "%s%s%s" "$green" "$suggestion" "$reset" >&2
    done
    printf " instead.\n" >&2
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
