#!/bin/zsh

# The following functions are used to log messages to the console
#   By starting with [EXEGOL], the wrapper can catch the message and forward it to the user
#   Logs that don't start with [EXEGOL] are not forwarded to the user, but they are still logged to /var/log/exegol/load_setups.log
#   Using [INFO], [VERBOSE], [WARNING], [ERROR], [SUCCESS] tags so that the wrapper can catch them and forward them to the user with the corresponding logger level

# This script being called by load_supported_setups.sh, we're in a lower level of logging, meaning the logger_info will not be defined here and shouldn't be used

LOG_FILE="/var/log/exegol/load_setups.log"

function echo2log () {
  echo "trust-ca-burp.sh $(date '+%Y-%m-%d %H:%M:%S') $*" >> "$LOG_FILE"
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

function trust_ca_burp_in_firefox() {
  logger_verbose "Generating Burp CA and trusting in Firefox"
  if [[ -d "/opt/tools/BurpSuiteCommunity/" ]]; then
    logger_debug 'Looking for available port'
    # Find an available port for Burp to listen
    local burp_port=8080
    # TODO : add the dynamic port finder
    # TODO : when dynamic port finder used, remove the code below that iterates on 8080++ until it finds one
    local listening_ports
    listening_ports=$(netstat -lnt|grep -Eo '(127.0.0.1|0.0.0.0):[0-9]{1,5}'|cut -d ':' -f 2)
    while [[ $listening_ports =~ .*$burp_port.* ]]
    do
      burp_port=$((burp_port+1))
    done
    # Edit configuration file to listen on the available port found
    logger_debug 'Preparing burp configuration file'
    sed -i "s/\"listener_port\":[0-9]\+/\"listener_port\":$burp_port/g" /opt/tools/BurpSuiteCommunity/conf.json
    # Start Burp with "y" to accept policy and generate CA, keep its PID to kill it when done
    logger_debug 'Starting Burp and waiting for proxy to listen'
    echo y|/usr/lib/jvm/java-21-openjdk/bin/java -Djava.awt.headless=true -jar /opt/tools/BurpSuiteCommunity/BurpSuiteCommunity.jar --config-file=/opt/tools/BurpSuiteCommunity/conf.json 2>&1 > /dev/null &
    # pull the latest process's ID
    local burp_pid=$!
    # Define Timeout counter
    # TODO: Upgrade timeout with better process
    local timeout_counter
    timeout_counter=0
    # Let time to Burp to init CA
    while [[ -z $(netstat -lnt|grep -Eo "(127.0.0.1|0.0.0.0):$burp_port") ]]
    do
      if (( $timeout_counter < 30 )); then
        sleep 0.5
        timeout_counter=$((timeout_counter+1))
      else
        kill "$burp_pid"
        logger_error 'Process timed out, please trust the CA manually.'
        exit 1
      fi
    done
    # Download the CA to /tmp and update the CA path
    logger_debug 'Retrieving CA'
    local burp_ca_path="/opt/tools/firefox/cacert.der"
    local burp_ca_name="PortSwigger CA"
    if ! wget -q "http://127.0.0.1:$burp_port/cert" -O "$burp_ca_path"; then
      kill "$burp_pid"
      logger_error 'The CA cert could not be retrieved, please trust it manually'
    fi
    kill "$burp_pid"
    logger_success 'CA trusted successfully'
  fi
}

trust_ca_burp_in_firefox

exit 0
