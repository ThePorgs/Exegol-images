#!/bin/bash
# Author: The Exegol Project

source common.sh

function install_vulny-code-static-analysis() {
    colorecho "Installing Vulny Code Static Analysis"
    git -C /opt/tools/ clone --depth=1 https://github.com/swisskyrepo/Vulny-Code-Static-Analysis
    add-aliases vulny-code-static-analysis
    add-history vulny-code-static-analysis
    add-test-command "vulny-code-static-analysis --help"
    add-to-list "vulny-code-static-analysis,https://github.com/swisskyrepo/Vulny-Code-Static-Analysis,Static analysis tool for C code"
}

function install_brakeman() {
    colorecho "Installing Brakeman"
    # TODO: gem venv
    gem install brakeman
    add-history brakeman
    add-test-command "brakeman --help"
    add-to-list "brakeman,https://github.com/presidentbeef/brakeman,Static analysis tool for Ruby on Rails applications"
}

function install_semgrep() {
    colorecho "Installing semgrep"
    python3 -m pipx install semgrep
    add-history semgrep
    add-test-command "semgrep --help"
    add-to-list "semgrep,https://github.com/returntocorp/semgrep/,Static analysis tool that supports multiple languages and can find a variety of vulnerabilities and coding errors."
}

# Package dedicated to SAST and DAST tools
function package_code_analysis() {
    install_vulny-code-static-analysis
    install_brakeman		            # Checks Ruby on Rails applications for security vulnerabilities
    install_semgrep                     # Static analysis engine for finding bugs and vulnerabilities
}