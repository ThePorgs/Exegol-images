#!/bin/bash
# Author: The Exegol Project

source common.sh

function install_brakeman() {
    colorecho "Installing Brakeman"
    rvm use 3.2.2@brakeman --create
    gem install brakeman
    rvm use 3.2.2@default
    add-aliases brakeman
    add-history brakeman
    add-test-command "brakeman --help"
    add-to-list "brakeman,https://github.com/presidentbeef/brakeman,Static analysis tool for Ruby on Rails applications"
}

function install_semgrep() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing semgrep"
    pipx install --system-site-packages semgrep
    add-history semgrep
    add-test-command "semgrep --help"
    add-to-list "semgrep,https://github.com/returntocorp/semgrep/,Static analysis tool that supports multiple languages and can find a variety of vulnerabilities and coding errors."
}

function install_pp-finder() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing pp-finder"
    # https://github.com/yeswehack/pp-finder/issues/2
    source ~/.nvm/nvm.sh
    nvm use default
    npm install -g pp-finder
    add-history pp-finder
    add-test-command "npm ls -g|grep pp-finder"
    add-to-list "pp-finder,https://github.com/yeswehack/pp-finder,Prototype pollution finder tool for javascript. pp-finder lets you find prototype pollution candidates in your code."
}

function install_gitleaks() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing gitleaks"
    if [[ $(uname -m) = 'x86_64' ]]
    then
        local arch="x64"
    elif [[ $(uname -m) = 'aarch64' ]]
    then
        local arch="arm64"
    else
        criticalecho-noexit "This installation function doesn't support architecture $(uname -m)" && return
    fi
    local gitleaks_url
    gitleaks_url=$(curl --location --silent "https://api.github.com/repos/gitleaks/gitleaks/releases/latest" | grep 'browser_download_url.*gitleaks.*linux_'"$arch"'.*tar.gz"' | grep -o 'https://[^"]*')
    curl --location -o /tmp/gitleaks.tar.gz "$gitleaks_url"
    tar -xf /tmp/gitleaks.tar.gz --directory /tmp
    rm /tmp/gitleaks.tar.gz
    mv /tmp/gitleaks /opt/tools/bin/gitleaks
    add-history gitleaks
    add-test-command "gitleaks --help"
    add-to-list "gitleaks,https://github.com/trufflesecurity/gitleaks,Gitleaks scans hardcoded secrets in git repositories and folders."
}

function install_trufflehog() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing trufflehog"
    if [[ $(uname -m) = 'x86_64' ]]
    then
        local arch="amd64"
    elif [[ $(uname -m) = 'aarch64' ]]
    then
        local arch="arm64"
    else
        criticalecho-noexit "This installation function doesn't support architecture $(uname -m)" && return
    fi
    local trufflehog_url
    trufflehog_url=$(curl --location --silent "https://api.github.com/repos/trufflesecurity/trufflehog/releases/latest" | grep 'browser_download_url.*trufflehog.*linux_'"$arch"'.*tar.gz"' | grep -o 'https://[^"]*')
    curl --location -o /tmp/trufflehog.tar.gz "$trufflehog_url"
    tar -xf /tmp/trufflehog.tar.gz --directory /tmp
    rm /tmp/trufflehog.tar.gz
    mv /tmp/trufflehog /opt/tools/bin/trufflehog
    add-history trufflehog
    add-test-command "trufflehog --help"
    add-to-list "trufflehog,https://github.com/trufflesecurity/trufflehog,Find verify and analyze hardcoded secrets in git repositories folders buckets and more."
}

# Package dedicated to SAST and DAST tools
function package_code_analysis() {
    set_env
    local start_time
    local end_time
    start_time=$(date +%s)
    install_brakeman		            # Checks Ruby on Rails applications for security vulnerabilities
    install_semgrep                     # Static analysis engine for finding bugs and vulnerabilities
    install_pp-finder                   # Prototype pollution finder tool for javascript
    install_gitleaks
    install_trufflehog
    post_install
    end_time=$(date +%s)
    local elapsed_time=$((end_time - start_time))
    colorecho "Package code_analysis completed in $elapsed_time seconds."
}
