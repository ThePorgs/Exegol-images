#!/bin/bash
# Author: The Exegol Project

source common.sh

function install_vulny-code-static-analysis() {
    colorecho "Installing Vulny Code Static Analysis"
    git -C /opt/tools/ clone --depth 1 https://github.com/swisskyrepo/Vulny-Code-Static-Analysis
    add-aliases vulny-code-static-analysis
    add-history vulny-code-static-analysis
    add-test-command "vulny-code-static-analysis.py --help"
    add-to-list "vulny-code-static-analysis,https://github.com/swisskyrepo/Vulny-Code-Static-Analysis,Static analysis tool for C code"
}

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
    pipx install semgrep
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
    set_ruby_env
    set_python_env
    install_vulny-code-static-analysis
    install_brakeman		            # Checks Ruby on Rails applications for security vulnerabilities
    install_semgrep                     # Static analysis engine for finding bugs and vulnerabilities
    install_pp-finder                   # Prototype pollution finder tool for javascript
}
