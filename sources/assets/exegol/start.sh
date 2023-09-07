#!/bin/bash

function shell_logging() {
    # First parameter is the method to use for shell logging (default to script)
    METHOD=$1
    # The second parameter is the shell command to use for the user
    USER_SHELL=$2
    # The third enable compression at the end of the session
    COMPRESS=$3

    # Logging shell using $METHOD and spawn a $USER_SHELL shell

    umask 007
    mkdir -p /workspace/logs/
    FILELOG="/workspace/logs/$(date +%d-%m-%Y_%H-%M-%S)_shell.${METHOD}"

    case $METHOD in
      "asciinema")
        # echo "Run using asciinema"
        asciinema rec -i 2 --stdin --quiet --command "$USER_SHELL" --title "$(hostname | sed 's/^exegol-/\[EXEGOL\] /') $(date '+%d/%m/%Y %H:%M:%S')" "$FILELOG"
        ;;

      "script")
        # echo "Run using script"
        script -qefac "$USER_SHELL" "$FILELOG"
        ;;

      *)
        echo "Unknown '$METHOD' shell logging method, using 'script' as default shell logging method."
        script -qefac "$USER_SHELL" "$FILELOG"
        ;;
    esac

    if [ "$COMPRESS" = 'True' ]; then
      echo 'Compressing logs, please wait...'
      gzip "$FILELOG"
    fi
    exit 0
}

$@ || (echo -e "[!] This version of the image ($(cat /opt/.exegol_version || echo '?')) does not support the $1 feature.\n[*] Please update your image and create a new container with before using this new feature."; exit 1)

exit 0
