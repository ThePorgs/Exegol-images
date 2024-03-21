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

# Package dedicated to SAST and DAST tools
function package_code_analysis() {
    set_env
    local start_time
    local end_time
    start_time=$(date +%s)
    install_brakeman		            # Checks Ruby on Rails applications for security vulnerabilities
    install_semgrep                     # Static analysis engine for finding bugs and vulnerabilities
    install_pp-finder                   # Prototype pollution finder tool for javascript
    end_time=$(date +%s)
    local elapsed_time=$((end_time - start_time))
    colorecho "Package code_analysis completed in $elapsed_time seconds."
}
