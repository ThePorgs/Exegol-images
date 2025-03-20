#!/bin/zsh

# This procedure is supposed to be executed only once at the first startup, using a lockfile check
# It is called by the entrypoint of the container and is used to deploy the supported setups as well as the user's customizations

# Cannot source from a function
source "$HOME/.zshrc"

# Root my-resources PATH
MY_ROOT_PATH="/opt/my-resources"

# Setup directory for user customization
MY_SETUP_PATH="$MY_ROOT_PATH/setup"

# Log file
LOG_FILE="/var/log/exegol/load_setups.log"

# The following functions are used to log messages to the console
#   By starting with [EXEGOL], the wrapper can catch the message and forward it to the user
#   Logs that don't start with [EXEGOL] are not forwarded to the user, but they are still logged to /var/log/exegol/load_setups.log
#   Using [INFO], [VERBOSE], [WARNING], [ERROR], [SUCCESS] tags so that the wrapper can catch them and forward them to the user with the corresponding logger level

function echo2wrapper () {
  echo "[EXEGOL]$*"
}

function echo2log () {
  echo "load_supported_setups.sh $(date '+%Y-%m-%d %H:%M:%S') $*" | sed -E 's#\[/?(green|red)]##g' >> "$LOG_FILE"
}

function logger_info () {
  echo2log "INFO $*"
}

function logger_verbose () {
  echo2log "VERBOSE $*"
}

function logger_advanced () {
  echo2log "ADVANCED $*"
}

function logger_debug () {
  echo2log "DEBUG $*"
}

function logger_warning () {
  echo2log "WARNING $*"
}

function logger_error () {
  echo2log "ERROR $*"
}

function logger_success () {
  echo2log "SUCCESS $*"
}

function wrapper_info () {
  echo2wrapper "[INFO]$*"
  echo2log "INFO $*"
}

function wrapper_verbose () {
  echo2wrapper "[VERBOSE]$*"
  echo2log "VERBOSE $*"
}

function wrapper_advanced () {
  echo2wrapper "[ADVANCED]$*"
  echo2log "ADVANCED $*"
}

function wrapper_debug () {
  echo2wrapper "[DEBUG]$*"
  echo2log "DEBUG $*"
}

function wrapper_warning () {
  echo2wrapper "[WARNING]$*"
  echo2log "WARNING $*"
}

function wrapper_error () {
  echo2wrapper "[ERROR]$*"
  echo2log "ERROR $*"
}

function wrapper_success () {
  echo2wrapper "[SUCCESS]$*"
  echo2log "SUCCESS $*"
}

# The following functions are used to deploy the supported setups

function init() {
  wrapper_verbose "Initialization supported setups"
  logger_debug "Checking environment variables"
  # Print environment variables in a more readable format
  env | sort | while read -r line; do
    logger_debug "ENV: $line"
  done
  logger_debug "Deploying /opt/my-resources"
  # Deploying the /opt/my-resources/ folder if not already there
  if [[ -d "$MY_ROOT_PATH" ]]; then
    # Setup basic structure
    [[ -d "$MY_SETUP_PATH" ]] || (mkdir "$MY_SETUP_PATH" && chmod 770 "$MY_SETUP_PATH")
    [[ -d "$MY_ROOT_PATH/bin" ]] || (mkdir "$MY_ROOT_PATH/bin" && chmod 770 "$MY_ROOT_PATH/bin")
  else
    wrapper_verbose "my-resources is disabled in this container, skipping deployment"
    exit 1
  fi
  logger_debug "Deploying my-resources README.md from current image to $MY_SETUP_PATH/README.md"
  # Copying README.md to /opt/my-resources/ (first use)
  cp --preserve=mode /.exegol/skel/README.md "$MY_SETUP_PATH/README.md"
}

function deploy_zsh() {
  wrapper_verbose "Deploying zsh"
  if [[ -d "$MY_SETUP_PATH/zsh" ]]; then
    # TODO remove fallback 'cp' command
    grep -vE "^(\s*|#.*)$" "$MY_SETUP_PATH/zsh/history" >> ~/.zsh_history || cp --preserve=mode /.exegol/skel/zsh/history "$MY_SETUP_PATH/zsh/history"
  else
    mkdir -p /opt/my-resources/setup/zsh
    cp --preserve=mode /.exegol/skel/zsh/* "$MY_SETUP_PATH/zsh/"
  fi
}

function deploy_tmux() {
  wrapper_verbose "Deploying tmux"
  if [[ -d "$MY_SETUP_PATH/tmux" ]]; then
    # id define, copy tmux/tmux.conf to ~/.tmux.conf
    if [[ -f "$MY_SETUP_PATH/tmux/tmux.conf" ]]; then
      # This key must always be defined (if redefined later in the file, the user user will take precedence)
      echo 'set-option -g default-shell /bin/zsh' > ~/.tmux.conf
      # Adding custom user config
      cat "$MY_SETUP_PATH/tmux/tmux.conf" >> ~/.tmux.conf
    fi
  else
    mkdir "$MY_SETUP_PATH/tmux" && chmod 770 "$MY_SETUP_PATH/tmux"
  fi
}

function deploy_vim() {
  wrapper_verbose "Deploying vim"
  local vpath
  if [[ -d "$MY_SETUP_PATH/vim" ]]; then
    # Copy vim/vimrc to ~/.vimrc
    [[ -f "$MY_SETUP_PATH/vim/vimrc" ]] && cp "$MY_SETUP_PATH/vim/vimrc" ~/.vimrc
    # Copy every subdir configs to ~/.vim directory
    for vpath in "$MY_SETUP_PATH/vim/autoload" "$MY_SETUP_PATH/vim/backup" "$MY_SETUP_PATH/vim/colors" "$MY_SETUP_PATH/vim/plugged" "$MY_SETUP_PATH/vim/bundle"; do
      [[ "$(ls -A "$vpath")" ]] && mkdir -p ~/.vim && cp -rf "$vpath" ~/.vim
    done
  else
    # Create supported directories struct
    mkdir -p "$MY_SETUP_PATH/vim/autoload" "$MY_SETUP_PATH/vim/backup" "$MY_SETUP_PATH/vim/colors" "$MY_SETUP_PATH/vim/plugged" "$MY_SETUP_PATH/vim/bundle"
    chmod 770 -R "$MY_SETUP_PATH/vim"
  fi
}

function deploy_nvim () {
  wrapper_verbose "Deploying nvim"
  if [[ -d "$MY_SETUP_PATH/nvim" ]]; then
    mkdir -p ~/.config/
    cp -r "$MY_SETUP_PATH/nvim/" ~/.config
  else
    mkdir -p "$MY_SETUP_PATH/nvim"
  fi
}

function deploy_apt() {
  wrapper_verbose "Deploying APT packages"
  local key_url
  local install_list
  local tmpaptkeys
  tmpaptkeys=$(mktemp -d)
  if [[ -d "$MY_SETUP_PATH/apt" ]]; then
    # Deploy custom apt repository
    logger_verbose "Deploying custom apt repository"
    cp "$MY_SETUP_PATH/apt/sources.list" /etc/apt/sources.list.d/exegol_user_sources.list
    # Register custom repo's GPG keys
    grep -vE "^(\s*|#.*)$" <"$MY_SETUP_PATH/apt/keys.list" | while IFS= read -r key_url; do
      wget -nv "$key_url" -O "$tmpaptkeys/$(echo "$key_url" | md5sum | cut -d ' ' -f1).key"
    done
    if [[ -n $(find "$tmpaptkeys" -type f -name "*.key") ]]; then
      logger_verbose "Importing custom apt repository GPG keys"
      gpg --no-default-keyring --keyring="$tmpaptkeys/user_custom.gpg" --batch --import "$tmpaptkeys"/*.key &&
        gpg --no-default-keyring --keyring="$tmpaptkeys/user_custom.gpg" --batch --output /etc/apt/trusted.gpg.d/user_custom.gpg --export --yes &&
        chmod 644 /etc/apt/trusted.gpg.d/user_custom.gpg
    fi
    rm -rf "$tmpaptkeys"
    # Create a package array
    install_list=()
    # Read the my-resource package.list file
    logger_debug "Reading my resources package.list file"
    while IFS= read -r ligne
    do
        # Exclude comment line start by "#"
        if [[ "$ligne" =~ ^\#.* ]]; then
            continue
        fi
        # Add packages to the list
        # shellcheck disable=SC2191
        install_list+=( $=ligne )
    done < "$MY_SETUP_PATH/apt/packages.list"
    # Check if there is some package to install
    if [[ ${#install_list[@]} -gt 0 ]]; then
        logger_verbose "Updating package list from repos"
        # Update package list from repos (only if there is some package to install
        apt-get update
        # Install every packages listed in the file
        apt-get install -y "${install_list[@]}"
    else
        logger_verbose "No APT package to install."
    fi
  else
    # Import file template
    mkdir "$MY_SETUP_PATH/apt" && chmod 770 "$MY_SETUP_PATH/apt"
    cp --preserve=mode /.exegol/skel/apt/* "$MY_SETUP_PATH/apt/"
  fi
}

function deploy_python3() {
  wrapper_verbose "Deploying python3 packages"
  if [[ -d "$MY_SETUP_PATH/python3" ]]; then
    logger_verbose "Installing python3 packages"
    # Install every pip3 packages listed in the requirements.txt file (if any supplied)
    [[ $(sed -E "/^\s*([#;]|\/\/|).*$/d" "$MY_SETUP_PATH/python3/requirements.txt" | wc -l) -gt 0 ]] && pip3 install -r "$MY_SETUP_PATH/python3/requirements.txt"
  else
    logger_verbose "Importing file template"
    # Import file template
    mkdir "$MY_SETUP_PATH/python3" && chmod 770 "$MY_SETUP_PATH/python3"
    cp --preserve=mode /.exegol/skel/python3/requirements.txt "$MY_SETUP_PATH/python3/requirements.txt"
  fi
}

function run_user_setup() {
  wrapper_verbose "Running user setup"
  # Executing user setup (or create the file)
  if [[ -f "$MY_SETUP_PATH/load_user_setup.sh" ]]; then
    logger_verbose "Loading user setup ($MY_SETUP_PATH/load_user_setup.sh)"
    "$MY_SETUP_PATH"/load_user_setup.sh |& tee -a "$LOG_FILE"
  else
    logger_verbose "User setup loader missing, deploying it ($MY_SETUP_PATH/load_user_setup.sh)"
    cp /.exegol/skel/load_user_setup.sh "$MY_SETUP_PATH/load_user_setup.sh"
    chmod 760 "$MY_SETUP_PATH/load_user_setup.sh"
  fi
  logger_verbose "End of custom setups loading"
}

function deploy_firefox_policy() {
  wrapper_verbose "Deploying Firefox Policy"
  if [[ -f "$MY_SETUP_PATH/firefox/policies.json" ]]; then
    logger_verbose "Copying Firefox Policy"
    cp --preserve=mode "$MY_SETUP_PATH/firefox/policies.json" /usr/lib/firefox-esr/distribution/policies.json
  fi
}

function deploy_bloodhound_config() {
  logger_verbose "Deploying BloodHound User Config"
  [[ -f "$my_setup_bh_path/config.json" ]] && cp "$my_setup_bh_path/config.json" "$bh_config_homedir/config.json"
}

function deploy_bloodhound_customqueries_merge() {
  logger_verbose "Merging User Custom Queries with Exegol Custom Queries for BloodHound"
  # Merge Exegol's customqueries.json file with the ones from my-resources
  local cq_merge_directory="$my_setup_bh_path/customqueries_merge"
  [[ ! -d "$cq_merge_directory" ]] && cp -r /.exegol/skel/bloodhound/customqueries_merge "$cq_merge_directory"
  if \
    [[ -f "$bh_config_homedir/customqueries.json" ]] && \
    [[ -n $(find "$cq_merge_directory" -type f -name "*.json") ]]; then
      bqm --verbose --ignore-default --output-path "$bqm_output_file" -i "$cq_merge_directory,$bh_config_homedir/customqueries.json"
  fi
}

function deploy_bloodhound_customqueries_replacement() {
  logger_verbose "Merging User Custom Queries for BloodHound, and overwriting Exegol Custom Queries"
  local cq_replacement_directory="$my_setup_bh_path/customqueries_replacement"
  [[ ! -d "$cq_replacement_directory" ]] && cp -r /.exegol/skel/bloodhound/customqueries_replacement "$cq_replacement_directory"
  if [[ -n $(find "$cq_replacement_directory" -type f -name "*.json") ]]; then
      bqm --verbose --ignore-default --output-path "$bqm_output_file" -i "$cq_replacement_directory"
      cq_replacement_done=1
  fi
}

function deploy_bloodhound() {
  wrapper_verbose "Deploying BloodHound"
  local bh_config_homedir=~/.config/bloodhound
  local my_setup_bh_path="$MY_SETUP_PATH/bloodhound"
  local cq_replacement_done=0
  # Use the dry-run flag to not create the file as bqm prompts if it already exists, hence it only generates a random filename
  local bqm_output_file
  bqm_output_file=$(mktemp --dry-run)
  [[ ! -d "$bh_config_homedir" ]] && mkdir -p "$bh_config_homedir"
  [[ ! -d "$my_setup_bh_path" ]] && cp -r /.exegol/skel/bloodhound "$my_setup_bh_path"
  deploy_bloodhound_config
  # If a user places Bloodhound json files in both folders merge and replacement,
  # only process the replacement.
  deploy_bloodhound_customqueries_replacement
  [[ $cq_replacement_done -eq 0 ]] && deploy_bloodhound_customqueries_merge
  if [[ -f "$bqm_output_file" ]]; then
    mv "$bqm_output_file" "$bh_config_homedir/customqueries.json" &&
    logger_verbose "$bh_config_homedir/customqueries.json replaced by $bqm_output_file"
  fi
}

function trust_ca_certs_in_firefox() {
  wrapper_verbose "Trusting Burp CA certificate in Firefox"
  logger_verbose "Running Burp Suite CA installation in background to save time"
  /opt/tools/bin/trust-ca-burp &> /dev/null &
  logger_info "Trusting user CA certificates in Firefox"
  local file
  if [[ -d "$MY_SETUP_PATH/firefox/CA" ]]; then
    for file in $(find "$MY_SETUP_PATH/firefox/CA" -type f); do
      if [[ -f "$file" ]]; then
        if [[ "$file" == *.[dD][eE][rR] ]]; then
          local base_filename_without_extension
          base_filename_without_extension=$(basename "$file" | rev | cut -d. -f2- | rev)
          _trust_ca_cert_in_firefox "$file" "$base_filename_without_extension"
        else
          logger_error "File $file does not have a .der or .DER extension and will not be trusted. Not supported by Exegol's my-resources yet"
        fi
      fi
    done
  else
    mkdir --parents "$MY_SETUP_PATH/firefox/CA/" && chmod 770 -R "$MY_SETUP_PATH/firefox/CA/"
  fi
}

function _trust_ca_cert_in_firefox() {
  # internal function to trust a CA cert (.DER) given the path and the name to set
  logger_verbose "Trusting cert $2 ($1) in Firefox"
  # -n : name of the cert
  # -t : attributes
  #   TC : trusted CA to issue client & server certs
  certutil -A -n "$2" -t "TC" -i "$1" -d ~/.mozilla/firefox/*.Exegol
}

function deploy_arsenal_cheatsheet () {
  # Function to add custom cheatsheets into arsenal
  wrapper_verbose "Deploying custom arsenal cheatsheet"
  if [[ ! -d "$MY_SETUP_PATH/arsenal-cheats" ]]; then
      mkdir -p "$MY_SETUP_PATH/arsenal-cheats"
  fi
  # This specific path is fetched by default by arsenal to load custom cheatsheet
}

init

deploy_zsh
deploy_tmux
deploy_vim
deploy_nvim
deploy_apt
deploy_python3
deploy_firefox_policy
deploy_bloodhound
trust_ca_certs_in_firefox
deploy_arsenal_cheatsheet

run_user_setup

wrapper_success "Successfully deployed [green]my-resources[/green]!"
exit 0
