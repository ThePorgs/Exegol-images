#!/bin/zsh

export RED='\033[1;31m'
export BLUE='\033[1;34m'
export GREEN='\033[1;32m'
export NOCOLOR='\033[0m'

### Echo functions

function infoecho () {
    echo -e "${BLUE}[*]${NOCOLOR} $*"
}

function okecho () {
    echo -e "${GREEN}[+]${NOCOLOR} $*"
}

function errorecho () {
    echo -e "${RED}[-]${NOCOLOR} $*" 2>&1
    exit 1
}

function trust_ca_burp_in_firefox() {
  infoecho "Generating Burp CA and trusting in Firefox"
  if [[ -d "/opt/tools/BurpSuiteCommunity/" ]]; then
    infoecho 'Looking for available port'
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
    infoecho 'Preparing burp configuration file'
    sed -i "s/\"listener_port\":[0-9]\+/\"listener_port\":$burp_port/g" /opt/tools/BurpSuiteCommunity/conf.json
    # Start Burp with "y" to accept policy and generate CA, keep its PID to kill it when done
    infoecho 'Starting Burp and waiting for proxy to listen'
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
        errorecho 'Process timed out, please trust the CA manually.'
      fi
    done
    # Download the CA to /tmp and update the CA path
    infoecho 'Retrieving CA'
    local burp_ca_path="/tmp/cacert.der"
    local burp_ca_name="PortSwigger CA"
    if ! wget -q "http://127.0.0.1:$burp_port/cert" -O "$burp_ca_path"; then
      kill "$burp_pid"
      errorecho 'The CA cert could not be retrieved, please trust it manually'
    fi
    kill "$burp_pid"
    _trust_ca_cert_in_firefox "$burp_ca_path" "$burp_ca_name"
    okecho 'CA trusted successfully'
  fi
}

function _trust_ca_cert_in_firefox() {
  # internal function to trust a CA cert (.DER) given the path and the name to set
  infoecho "Trusting cert $2 ($1) in Firefox"
  # -n : name of the cert
  # -t : attributes
  #   TC : trusted CA to issue client & server certs
  if ! certutil -A -n "$2" -t "TC" -i "$1" -d ~/.mozilla/firefox/*.Exegol; then
    errorecho 'Could not trust Burp CA automatically, please trust it manually.'
  fi
}

trust_ca_burp_in_firefox

exit 0
