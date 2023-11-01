#!/bin/bash

# !!!!!!!!!!!!! #
# This file is no longer up-to-date because in the later version, the wrapper uploads it's own entrypoint.sh and spawn.sh to the container to keep the wrapper and image features in sync.
# This default file is kept here for backward compatibility. No upcoming development expected here.
# !!!!!!!!!!!!! #

function shell_logging() {
    # First parameter is the method to use for shell logging (default to script)
    local method=$1
    # The second parameter is the shell command to use for the user
    local user_shell=$2
    # The third enable compression at the end of the session
    local compress=$3

    # Logging shell using $method and spawn a $user_shell shell

    umask 007
    mkdir -p /workspace/logs/
    local filelog
    filelog="/workspace/logs/$(date +%d-%m-%Y_%H-%M-%S)_shell.${method}"

    case $method in
      "asciinema")
        # echo "Run using asciinema"
        asciinema rec -i 2 --stdin --quiet --command "$user_shell" --title "$(hostname | sed 's/^exegol-/\[EXEGOL\] /') $(date '+%d/%m/%Y %H:%M:%S')" "$filelog"
        ;;

      "script")
        # echo "Run using script"
        script -qefac "$user_shell" "$filelog"
        ;;

      *)
        echo "Unknown '$method' shell logging method, using 'script' as default shell logging method."
        script -qefac "$user_shell" "$filelog"
        ;;
    esac

    if [[ "$compress" = 'True' ]]; then
      echo 'compressing logs, please wait...'
      gzip "$filelog"
    fi
    exit 0
}

"$@" || (echo -e "[!] This version of the image ($(cat /opt/.exegol_version || echo '?')) does not support the $1 feature.\n[*] Please update your image and create a new container with before using this new feature."; exit 1)

exit 0
