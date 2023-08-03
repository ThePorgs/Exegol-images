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
    grep -vE "^(\s*|#.*)$" "$MY_Setup_PATH/zsh/history" >> ~/.zsh_history || cp --preserve=mode /.exegol/skel/zsh/history "$MY_Setup_PATH/zsh/history"
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
      [ "$(ls -A "$path")" ] && mkdir -p ~/.vim && cp -rf "$path" ~/.vim
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
    grep -vE "^(\s*|#.*)$" <"$MY_Setup_PATH/apt/keys.list" | while IFS= read -r key_url; do
      wget -nv "$key_url" -O "/tmp/aptkeys/$(echo "$key_url" | md5sum | cut -d ' ' -f1).key"
    done
    if [ "$(ls /tmp/aptkeys/*.key 2>/dev/null)" ]; then
      gpg --no-default-keyring --keyring=/tmp/aptkeys/user_custom.gpg --batch --import /tmp/aptkeys/*.key &&
        gpg --no-default-keyring --keyring=/tmp/aptkeys/user_custom.gpg --batch --output /etc/apt/trusted.gpg.d/user_custom.gpg --export --yes &&
        chmod 644 /etc/apt/trusted.gpg.d/user_custom.gpg
    fi
    rm -r /tmp/aptkeys
    install_list=$(grep -vE "^(\s*|#.*)$" "$MY_Setup_PATH/apt/packages.list" | tr "\n" " ")
    # Test if there is some package to install
    if [ -n "$install_list" ]; then
      # Update package list from repos (only if there is some package to install
      apt-get update
      # Install every packages listed in the file
      # shellcheck disable=SC2086
      apt-get install -y $install_list
    fi
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
    echo "[Exegol] Installing [green]my-resources[/green] user's defined custom setup ..."
    "$MY_Setup_PATH"/load_user_setup.sh
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
    # shellcheck disable=SC2086
    python3 /opt/tools/firefox/user-setup.py $ADDON_LIST $ADDON_FOLDER
  else
    mkdir --parents "$MY_Setup_PATH/firefox/addons" && chmod 770 -R "$MY_Setup_PATH/firefox/addons"
    cp --preserve=mode /.exegol/skel/firefox/addons.txt "$MY_Setup_PATH/firefox/addons.txt"
  fi
}

function deploy_bloodhound_config() {
  [[ -f "$my_setup_bh_path/config.json" ]] && cp "$my_setup_bh_path/config.json" "$bh_config_homedir/config.json"
}

function deploy_bloodhound_customqueries_merge() {
  # Merge Exegol's customqueries.json file with the ones from my-resources
  local cq_merge_directory="$my_setup_bh_path/customqueries_merge"

  [[ ! -d "$cq_merge_directory" ]] && cp -r /.exegol/skel/bloodhound/customqueries_merge "$cq_merge_directory"

  if \
    [[ -f "$bh_config_homedir/customqueries.json" ]] && \
    [[ -n $(find "$cq_merge_directory" -type f -name "*.json") ]]; then
      bqm --verbose --ignore-default --output-path "$bqm_output_file" -i "$cq_merge_directory,$bh_config_homedir/customqueries.json"
      [[ -f "$bqm_output_file" ]] && mv "$bqm_output_file" "$bh_config_homedir/customqueries.json"
  fi
}

function deploy_bloodhound_customqueries_replacement() {
  # Replace Exegol's customqueries.json file with the merge of ones from my-resources
  local cq_replacement_directory="$my_setup_bh_path/customqueries_replacement"

  [[ ! -d "$cq_replacement_directory" ]] && cp -r /.exegol/skel/bloodhound/customqueries_replacement "$cq_replacement_directory"

  if [[ -n $(find "$cq_replacement_directory" -type f -name "*.json") ]]; then
      bqm --verbose --ignore-default --output-path "$bqm_output_file" -i "$cq_replacement_directory"
      [[ -f "$bqm_output_file" ]] && mv "$bqm_output_file" "$bh_config_homedir/customqueries.json"
  fi
}

function deploy_bloodhound() {
  local bh_config_homedir=~/.config/bloodhound
  local my_setup_bh_path="$MY_Setup_PATH/bloodhound"
  local bqm_output_file="$bh_config_homedir/customqueries.json.bqm"

  [[ ! -d "$bh_config_homedir" ]] && mkdir -p "$bh_config_homedir"
  [[ ! -d "$my_setup_bh_path" ]] && cp -r /.exegol/skel/bloodhound "$my_setup_bh_path"

  deploy_bloodhound_config

  # Clean up any unlikely pre-existing file to avoid bqm prompts
  [[ -f "$bqm_output_file" ]] && rm -f "$bqm_output_file"

  # If a user places Bloodhound json files in both folders merge and replacement,
  # replacement must be executed last to only keep the output of replacement.
  deploy_bloodhound_customqueries_merge
  deploy_bloodhound_customqueries_replacement
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
deploy_bloodhound

run_user_setup

exit 0
