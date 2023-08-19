#!/bin/bash
# Author: The Exegol Project

source common.sh

function install_wordlists_apt_tools() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing wordlists apt tools"
    fapt crunch cupp 

    add-history cupp
    add-history crunch

    add-test-command "crunch --help" # Wordlist generator
    add-test-command "cupp --help"   # User password profiler

    add-to-list "crunch,https://github.com/crunchsec/crunch,A wordlist generator where you can specify a standard character set or a character set you specify."
    add-to-list "cupp,https://github.com/Mebus/cupp,Cupp is a tool used to generate personalized password lists based on target information."
}

function install_cewl() {
    colorecho "Installing cewl"
    rvm use 3.0.0@cewl --create
    gem install mime mime-types mini_exiftool nokogiri rubyzip spider
    git -C /opt/tools clone --depth 1 https://github.com/digininja/CeWL.git
    bundle install --gemfile /opt/tools/CeWL/Gemfile
    rvm use 3.0.0@default
    add-aliases cewl
    add-history cewl
    add-test-command "cewl --help"
    add-to-list "cewl,https://digi.ninja/projects/cewl.php,Generates custom wordlists by spidering a target's website and parsing the results"
}

function install_seclists() {
    # CODE-CHECK-WHITELIST=add-aliases,add-history
    colorecho "Installing seclists"
    git -C /opt clone --single-branch --branch master --depth 1 https://github.com/danielmiessler/SecLists.git seclists
    cd /opt/seclists
    rm -r LICENSE .git* CONTRIBUT* .bin
    add-test-command "[ -d '/opt/seclists/Discovery/' ]"
    add-to-list "seclists,https://github.com/danielmiessler/SecLists,A collection of multiple types of lists used during security assessments"
}

function configure_seclists() {
    colorecho "Configuring seclists"
    mkdir -p /usr/share/wordlists
    ln -v -s /opt/seclists /usr/share/seclists
    ln -v -s /opt/seclists /usr/share/wordlists/seclists
}

function configure_rockyou() {
    colorecho "Configuring rockyou"
    ls -la /opt/
    tar -xvf /opt/seclists/Passwords/Leaked-Databases/rockyou.txt.tar.gz -C /opt/
    ln -v -s /opt/rockyou.txt /usr/share/wordlists/rockyou.txt
    add-test-command "[ -f '/usr/share/wordlists/rockyou.txt' ]"
    add-to-list "rockyou,https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt,A password dictionary used by most hackers"
}

function install_pass_station() {
    colorecho "Installing Pass Station"
    rvm use 3.0.0@pass-station --create
    gem install pass-station
    rvm use 3.0.0@default
    add-aliases pass-station
    add-history pass-station
    add-test-command "pass-station --help"
    add-to-list "pass,https://github.com/hashcat/hashcat,TODO"
}

function install_username-anarchy() {
    colorecho "Installing Username-Anarchy"
    git -C /opt/tools/ clone --depth 1 https://github.com/urbanadventurer/username-anarchy
    add-aliases username-anarchy
    add-history username-anarchy
    add-test-command "username-anarchy --help"
    add-to-list "username-anarchy,https://github.com/urbanadventurer/username-anarchy,Tools for generating usernames when penetration testing. Usernames are half the password brute force problem."
}

function install_genusernames() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing genusernames"
    mkdir -p /opt/tools/genusernames
    wget -O /opt/tools/genusernames/genusernames.function https://gitlab.com/-/snippets/2480505/raw/main/bash
    sed -i 's/genadname/genusernames/g' /opt/tools/genusernames/genusernames.function
    add-history genusernames
    add-test-command "genusernames 'john doe'"
    add-to-list "genusernames,https://gitlab.com/-/snippets/2480505/raw/main/bash,GenUsername is a Python tool for generating a list of usernames based on a name or email address."
}

function configure_genusernames() {
    colorecho "Configuring genusernames"
    echo 'source /opt/tools/genusernames/genusernames.function' >> ~/.zshrc
}

# Package dedicated to the installation of wordlists and tools like wl generators
function package_wordlists() {
    set_ruby_env
    install_wordlists_apt_tools
    install_cewl                    # Wordlist generator
    install_seclists                # Awesome wordlists
    install_pass_station            # Default credentials database
    install_username-anarchy        # Generate possible usernames based on heuristics
    install_genusernames
}

function package_wordlists_configure() {
    configure_seclists
    configure_rockyou
    configure_genusernames
}