#!/bin/bash

function init() {
    # Deploying the /opt/my-resources/ folder if not already there
  if [ -d "$MY_Root_PATH" ]; then
    # Setup basic structure
    [ -d "$MY_Setup_PATH" ] || (mkdir "$MY_Setup_PATH" && chmod 770 "$MY_Setup_PATH")
    [ -d "$MY_Root_PATH/bin" ] || (mkdir "$MY_Root_PATH/bin" && chmod 770 "$MY_Root_PATH/bin")
  else
    echo "Exiting, 'my-resources' is disabled"
    exit 1
  fi

  # Copying README.md to /opt/my-resources/ (first use)
  [ -f "$MY_Setup_PATH/README.md" ] || cp --preserve=mode /.exegol/skel/README.md "$MY_Setup_PATH/README.md"
}

function deploy_zsh() {
  ##### ZSH deployment
  if [ -d "$MY_Setup_PATH/zsh" ]; then
    # TODO remove fallback 'cp' command
    grep -vE "^(\s*|#.*)$" "$MY_Setup_PATH/zsh/history" >> /root/.zsh_history || cp --preserve=mode /.exegol/skel/zsh/history "$MY_Setup_PATH/zsh/history"
  else
    mkdir -p /opt/my-resources/setup/zsh
    cp --preserve=mode /.exegol/skel/zsh/* "$MY_Setup_PATH/zsh/"
  fi
}

function deploy_tmux() {
  ##### TMUX deployment
  if [ -d "$MY_Setup_PATH/tmux" ]; then
    # copy tmux/tmux.conf to ~/.tmux.conf
    [ -f "$MY_Setup_PATH/tmux/tmux.conf" ] && cp "$MY_Setup_PATH/tmux/tmux.conf" ~/.tmux.conf
  else
    mkdir "$MY_Setup_PATH/tmux" && chmod 770 "$MY_Setup_PATH/tmux"
  fi
}

function deploy_vim() {
  ##### VIM deployment
  if [ -d "$MY_Setup_PATH/vim" ]; then
    # Copy vim/vimrc to ~/.vimrc
    [ -f "$MY_Setup_PATH/vim/vimrc" ] && cp "$MY_Setup_PATH/vim/vimrc" ~/.vimrc
    # Copy every subdir configs to ~/.vim directory
    for path in "$MY_Setup_PATH/vim/autoload" "$MY_Setup_PATH/vim/backup" "$MY_Setup_PATH/vim/colors" "$MY_Setup_PATH/vim/plugged" "$MY_Setup_PATH/vim/bundle"; do
      [ "$(ls -A $path)" ] && mkdir -p ~/.vim && cp -rf $path ~/.vim
    done
  else
    # Create supported directories struct
    mkdir -p "$MY_Setup_PATH/vim/autoload" "$MY_Setup_PATH/vim/backup" "$MY_Setup_PATH/vim/colors" "$MY_Setup_PATH/vim/plugged" "$MY_Setup_PATH/vim/bundle"
    chmod 770 -R "$MY_Setup_PATH/vim"
  fi
}

function deploy_apt() {
  ##### Install custom APT packages
  if [ -d "$MY_Setup_PATH/apt" ]; then
    # Deploy custom apt repository
    cp "$MY_Setup_PATH/apt/sources.list" /etc/apt/sources.list.d/exegol_user_sources.list
    # Register custom repo's GPG keys
    mkdir /tmp/aptkeys
    grep -vE "^(\s*|#.*)$" <$MY_Setup_PATH/apt/keys.list | while IFS= read -r key_url; do
      wget -nv "$key_url" -O "/tmp/aptkeys/$(echo "$key_url" | md5sum | cut -d ' ' -f1).key"
    done
    if [ "$(ls /tmp/aptkeys/*.key 2>/dev/null)" ]; then
      gpg --no-default-keyring --keyring=/tmp/aptkeys/user_custom.gpg --batch --import /tmp/aptkeys/*.key && \
      gpg --no-default-keyring --keyring=/tmp/aptkeys/user_custom.gpg --batch --output /etc/apt/trusted.gpg.d/user_custom.gpg --export --yes && \
      chmod 644 /etc/apt/trusted.gpg.d/user_custom.gpg
    fi
    rm -r /tmp/aptkeys
    # Update package list from repos
    apt-get update
    # Install every packages listed in the file
    # shellcheck disable=SC2046
    apt-get install -y $(grep -vE "^(\s*|#.*)$" "$MY_Setup_PATH/apt/packages.list" | tr "\n" " ")
  else
    # Import file template
    mkdir "$MY_Setup_PATH/apt" && chmod 770 "$MY_Setup_PATH/apt"
    cp --preserve=mode /.exegol/skel/apt/* "$MY_Setup_PATH/apt/"
  fi
}

function deploy_python3() {
  ##### Install custom PIP3 packages
  if [ -d "$MY_Setup_PATH/python3" ]; then
    # Install every pip3 packages listed in the requirements.txt file
    python3 -m pip install -r "$MY_Setup_PATH/python3/requirements.txt"
  else
    # Import file template
    mkdir "$MY_Setup_PATH/python3" && chmod 770 "$MY_Setup_PATH/python3"
    cp --preserve=mode /.exegol/skel/python3/requirements.txt "$MY_Setup_PATH/python3/requirements.txt"
  fi
}

function run_user_setup() {
  # Executing user setup (or create the file)
  if [ -f "$MY_Setup_PATH/load_user_setup.sh" ]; then
    echo "[$(date +'%d-%m-%Y_%H-%M-%S')] ==== Loading user setup ($MY_Setup_PATH/load_user_setup.sh) ===="
    $MY_Setup_PATH/load_user_setup.sh
  else
    echo "[$(date +'%d-%m-%Y_%H-%M-%S')] ==== User setup loader missing, deploying it ($MY_Setup_PATH/load_user_setup.sh) ===="
    cp /.exegol/skel/load_user_setup.sh "$MY_Setup_PATH/load_user_setup.sh"
    chmod 760 "$MY_Setup_PATH/load_user_setup.sh"
  fi

  echo "[$(date +'%d-%m-%Y_%H-%M-%S')] ==== End of custom setups loading ===="
}

function deploy_firefox_addons() {
  ##### firefox custom addons deployment
  if [ -d "$MY_Setup_PATH/firefox/" ]; then
    if [ -d "$MY_Setup_PATH/firefox/addons" ]; then
      ADDON_FOLDER="-D $MY_Setup_PATH/firefox/addons"
    else
      mkdir "$MY_Setup_PATH/firefox/addons" && chmod 770 "$MY_Setup_PATH/firefox/addons"
    fi
    if [ -f "$MY_Setup_PATH/firefox/addons.txt" ]; then
      ADDON_LIST="-L $MY_Setup_PATH/firefox/addons.txt"
    else
      cp --preserve=mode /.exegol/skel/firefox/addons.txt "$MY_Setup_PATH/firefox/addons.txt"
    fi
    python3 /opt/tools/firefox/user-setup.py $ADDON_LIST $ADDON_FOLDER
  else
    mkdir --parents "$MY_Setup_PATH/firefox/addons" && chmod 770 -R "$MY_Setup_PATH/firefox/addons"
    cp --preserve=mode /.exegol/skel/firefox/addons.txt "$MY_Setup_PATH/firefox/addons.txt"
  fi
}

function trust_ca_burp() {
  ##### Burp CA trust
  if ! [ -d "$MY_Setup_PATH/burp/" ]; then
    mkdir "$MY_Setup_PATH/burp" && chmod 770 "$MY_Setup_PATH/burp"
  fi
  # If a CA is added by the user in my-resources, it will be trusted
  if [ -f "$MY_Setup_PATH/burp/cacert.der" ]; then
    BURP_CA_PATH="$MY_Setup_PATH/burp/cacert.der"
    certutil -A -n "PortSwigger CA" -t "TC" -i $BURP_CA_PATH -d ~/.mozilla/firefox/*.Exegol
  else
    # If no CA is present in my-resources dans BurpSuiteCommunity is installed in Exegol
    if [ -d "/opt/tools/BurpSuiteCommunity/" ]; then
      # Find an available port for Burp to listen
      BURP_PORT=8080
      LISTENING_PORTS=$(netstat -lnt|grep -Eo '(127.0.0.1|0.0.0.0):[0-9]{1,5}'|cut -d ':' -f 2)
      while [[ $LISTENING_PORTS =~ .*$BURP_PORT.* ]]
      do
        BURP_PORT=$((BURP_PORT+1))
      done
      # Edit configuration file to listen on the available port found
      sed -i "s/\"listener_port\":[0-9]\+/\"listener_port\":$BURP_PORT/g" /opt/tools/BurpSuiteCommunity/conf.json
      # Start Burp with "y" to accept policy and generate CA, keep its PID to kill it when done
      echo y|java -Djava.awt.headless=true -jar /opt/tools/BurpSuiteCommunity/BurpSuiteCommunity.jar --config-file=/opt/tools/BurpSuiteCommunity/conf.json &>/tmp/burp_logs &
      BURP_PID=$!
      # Let time to Burp to init CA
      while ! [[ $(tail /tmp/burp_logs) =~ .*y/n.* ]]
      do
          sleep 0.5
      done
      # Download the CA to /tmp and update the CA path
      wget "http://127.0.0.1:$BURP_PORT/cert" -O /tmp/cacert.der && kill $BURP_PID
      BURP_CA_PATH="/tmp/cacert.der"
      # Trust the CA in Firefox
      certutil -A -n "PortSwigger CA" -t "TC" -i $BURP_CA_PATH -d ~/.mozilla/firefox/*.Exegol
      # Remove temporary files generated by Burp
      rm -r /tmp/burp*
    fi
  fi
}

# Starting
# This procedure is supposed to be executed only once at the first startup, using a lockfile check

echo "This log file is the result of the execution of the official and personal customization script"
echo "[$(date +'%d-%m-%Y_%H-%M-%S')] ==== Loading custom setups (/.exegol/load_supported_setups.sh) ===="

# Root my-resources PATH
MY_Root_PATH="/opt/my-resources"
# Setup directory for user customization
MY_Setup_PATH="$MY_Root_PATH/setup"

init

deploy_zsh
deploy_tmux
deploy_vim
deploy_apt
deploy_python3
deploy_firefox_addons
trust_ca_burp

run_user_setup

exit 0