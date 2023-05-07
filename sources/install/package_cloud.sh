#!/bin/bash
# Author: The Exegol Project

source common.sh

function install_kubectl(){
    colorecho "Installing kubectl"
    mkdir -p /opt/tools/kubectl
    cd /opt/tools/kubectl
    if [[ $(uname -m) = 'x86_64' ]]
    then
        curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
    elif [[ $(uname -m) = 'aarch64' ]]
    then
        curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/arm64/kubectl"
    elif [[ $(uname -m) = 'armv7l' ]]
    then
        curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/arm/kubectl"
    else
        criticalecho-noexit "This installation function doesn't support architecture $(uname -m)" && return
    fi
    install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl
    add-test-command "kubectl --help"
    add-to-list "kubectl,https://kubernetes.io/docs/reference/kubectl/overview/,Command-line interface for managing Kubernetes clusters."
}

function install_awscli(){
    colorecho "Installing aws cli"
    cd /tmp
    if [[ $(uname -m) = 'x86_64' ]]
    then
        curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
    elif [[ $(uname -m) = 'aarch64' ]]
    then
        curl "https://awscli.amazonaws.com/awscli-exe-linux-aarch64.zip" -o "awscliv2.zip"
    else
        criticalecho-noexit "This installation function doesn't support architecture $(uname -m)" && return
    fi
    unzip awscliv2.zip
    ./aws/install -i /opt/tools/aws-cli -b /usr/local/bin
    rm -rf aws
    rm awscliv2.zip
    add-test-command "aws --version"
    add-to-list "awscli,https://aws.amazon.com/cli/,Command-line interface for Amazon Web Services."
}

function install_scout() {
    colorecho "Installing ScoutSuite"
    python3 -m pipx install scoutsuite
    add-test-command "scout --help"
    add-to-list "scout,TODO,TODO"
}

function install_azurecli(){
  colorecho "Installing Azure cli"
  fapt azure-cli
  add-history azurecli 
  add-test-command "az version"
  add-to-list "azurecli,https://learn.microsoft.com/en-us/cli/azure/,Command-line interface for Azure."
}

# Package dedicated to cloud tools
function package_cloud() {
    install_kubectl
    install_awscli
    install_scout       # Multi-Cloud Security Auditing Tool
    install_azurecli                # Tool made by Microsoft to use Azure API 
}