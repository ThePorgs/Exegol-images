#!/bin/bash
# Author: The Exegol Project

source common.sh

function install_kubectl() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing kubectl"
    mkdir -p /opt/tools/kubectl
    cd /opt/tools/kubectl || exit
    if [[ $(uname -m) = 'x86_64' ]]
    # using $(which curl) to avoid having additional logs put in curl output being executed because of catch_and_retry
    then
        curl -LO "https://dl.k8s.io/release/$($(which curl) -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
    elif [[ $(uname -m) = 'aarch64' ]]
    then
        curl -LO "https://dl.k8s.io/release/$($(which curl) -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/arm64/kubectl"
    elif [[ $(uname -m) = 'armv7l' ]]
    then
        curl -LO "https://dl.k8s.io/release/$($(which curl) -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/arm/kubectl"
    else
        criticalecho-noexit "This installation function doesn't support architecture $(uname -m)" && return
    fi
    install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl
    add-history kubectl
    add-test-command "kubectl --help"
    add-to-list "kubectl,https://kubernetes.io/docs/reference/kubectl/overview/,Command-line interface for managing Kubernetes clusters."
}

function install_awscli() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing aws cli"
    cd /tmp || exit
    if [[ $(uname -m) = 'x86_64' ]]
    then
        curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
    elif [[ $(uname -m) = 'aarch64' ]]
    then
        curl "https://awscli.amazonaws.com/awscli-exe-linux-aarch64.zip" -o "awscliv2.zip"
    else
        criticalecho-noexit "This installation function doesn't support architecture $(uname -m)" && return
    fi
    unzip -q awscliv2.zip # -q because too much useless verbose
    ./aws/install -i /opt/tools/aws-cli -b /usr/local/bin
    rm -rf aws
    rm awscliv2.zip
    # TODO: improve history : https://www.bluematador.com/learn/aws-cli-cheatsheet
    add-history aws
    add-test-command "aws --version"
    add-to-list "awscli,https://aws.amazon.com/cli/,Command-line interface for Amazon Web Services."
}

function install_scout() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing ScoutSuite"
    pipx install --system-site-packages scoutsuite
    add-history scout
    add-test-command "scout --help"
    add-to-list "scout,https://github.com/nccgroup/ScoutSuite,Scout Suite is an open source multi-cloud security-auditing tool which enables security posture assessment of cloud environments."
}

function install_cloudsplaining() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing Cloudsplaining"
    pipx install --system-site-packages cloudsplaining
    add-history cloudsplaining
    add-test-command "cloudsplaining --help"
    add-to-list "cloudsplaining,https://github.com/salesforce/cloudsplaining,AWS IAM Security Assessment tool that identifies violations of least privilege and generates a risk-prioritized report."
}

function install_cloudsploit() {
    colorecho "Installing Cloudsploit"
    git -C /opt/tools/ clone --depth 1 https://github.com/aquasecurity/cloudsploit
    cd /opt/tools/cloudsploit && npm install && chmod +x index.js
    add-aliases cloudsploit
    add-history cloudsploit
    add-test-command "cloudsploit -h"
    add-to-list "cloudsploit,https://github.com/aquasecurity/cloudsploit,Cloud Security Posture Management"
}

function install_prowler() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing Prowler"
    pipx install --system-site-packages prowler
    add-history prowler
    add-test-command "prowler -h"
    add-to-list "prowler,https://github.com/prowler-cloud/prowler,Perform Cloud Security best practices assessments / audits / incident response / compliance / continuous monitoring / hardening and forensics readiness."
}

function install_cloudmapper() {
    colorecho "Installing Cloudmapper"
    git -C /opt/tools clone --depth 1 https://github.com/duo-labs/cloudmapper.git 
    cd /opt/tools/cloudmapper || exit
    cp -v /root/sources/assets/patches/cloudmapper.patch cloudmapper.patch
    git apply --verbose cloudmapper.patch
    python3 -m venv --system-site-packages ./venv
    source ./venv/bin/activate
    pip3 install wheel
    pip3 install -r requirements.txt
    deactivate
    add-aliases cloudmapper
    add-history cloudmapper
    add-test-command 'cloudmapper.py --help |& grep "usage"'
    add-to-list "cloudmapper,https://github.com/duo-labs/cloudmapper,CloudMapper helps you analyze your Amazon Web Services (AWS) environments."
}

function install_azure_cli() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing Azure-cli"
    # splitting curl | bash to avoid having additional logs put in curl output being executed because of catch_and_retry
    curl -sL https://aka.ms/InstallAzureCLIDeb -o /tmp/azure-cli-install.sh
    bash /tmp/azure-cli-install.sh
    rm /tmp/azure-cli-install.sh
    add-history azure-cli
    add-test-command "az version"
    add-to-list "azure-cli,https://github.com/Azure/azure-cli,A great cloud needs great tools; we're excited to introduce Azure CLI our next generation multi-platform command line experience for Azure."
}

# Package dedicated to cloud tools
function package_cloud() {
    set_env
    local start_time
    local end_time
    start_time=$(date +%s)
    install_kubectl
    install_awscli
    install_scout           # Multi-Cloud Security Auditing Tool
    install_cloudsplaining
    install_cloudsploit
    install_prowler
    install_cloudmapper
    install_azure_cli       # Command line for Azure
    post_install
    end_time=$(date +%s)
    local elapsed_time=$((end_time - start_time))
    colorecho "Package cloud completed in $elapsed_time seconds."
}
