#!/bin/bash
# Author: The Exegol Project

source common.sh
# sourcing package_ad.sh for the install_powershell() function
source package_ad.sh

function install_pwncat() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing pwncat-vl"
    pipx install --system-site-packages pwncat-vl
    # Because Blowfish has been deprecated, downgrade cryptography version - https://github.com/paramiko/paramiko/issues/2038
    pipx inject pwncat-vl cryptography==36.0.2
    add-history pwncat
    add-test-command "pwncat-vl --version"
    local version
    version="$(pipx_version pwncat-vl)"
    add-to-list "pwncat-vl,${version},https://github.com/Chocapikk/pwncat-vl,Maintained fork of pwncat-cs with recent fixes and enhancements."
}

function install_metasploit() {
    colorecho "Installing Metasploit"
    fapt libpcap-dev libpq-dev zlib1g-dev libsqlite3-dev
    git -C /opt/tools clone --depth 1 https://github.com/rapid7/metasploit-framework.git
    cd /opt/tools/metasploit-framework || exit  # rvm gemset ruby-3.1.5@metasploit-framework should be auto setup here

    # Fix msfupdate git config requirements
    git config user.name "exegol"
    git config user.email "exegol@localhost"

    rvm use 3.3.8@metasploit-framework --create

    # install dep manager
    gem install bundler
    bundle install

    # Add missing deps
    gem install rex
    gem install rex-text

    # fixes 'You have already activated timeout 0.2.0, but your Gemfile requires timeout 0.4.1. Since timeout is a default gem, you can either remove your dependency on it or try updating to a newer version of bundler that supports timeout as a default gem.'
    # 2026-09-21: still needed until a full msf rebuild proves bundler/timeout is fine without it
    local temp_fix_limit="2027-03-21"
    if check_temp_fix_expiry "$temp_fix_limit"; then
      gem install timeout --version 0.4.1
    fi
    rvm use 3.2.2@default

    # msfdb setup
    fapt postgresql
    cp -r /root/.bundle /var/lib/postgresql
    chown -R postgres:postgres /var/lib/postgresql/.bundle
    chmod -R o+rx /opt/tools/metasploit-framework/
    chmod 444 /opt/tools/metasploit-framework/.git/index # fatal: .git/index: index file open failed: Permission denied
    sudo -u postgres sh -c "git config --global --add safe.directory /opt/tools/metasploit-framework && /usr/local/rvm/gems/ruby-3.3.8@metasploit-framework/wrappers/bundle exec /opt/tools/metasploit-framework/msfdb init"
    cp -r /var/lib/postgresql/.msf4 /root

    # Install the PEASS Ruby MSF module (https://github.com/peass-ng/PEASS-ng/tree/master/metasploit)
    wget https://raw.githubusercontent.com/peass-ng/PEASS-ng/master/metasploit/peass.rb -O /opt/tools/metasploit-framework/modules/post/multi/gather/peass.rb

    add-aliases metasploit
    add-history metasploit
    add-test-command "msfconsole --help"
    add-test-command "msfconsole --version"
    add-test-command "msfdb --help"
    add-test-command "msfdb status"
    add-test-command "msfvenom --list platforms"
    add-test-command "msfvenom -p windows/meterpreter/reverse_tcp LHOST=127.0.0.1 LPORT=4444 -f exe > /tmp/test.exe && file /tmp/test.exe|grep 'PE32 executable' && rm /tmp/test.exe"
    local version
    version="$(git_version /opt/tools/metasploit-framework)"
    add-to-list "metasploit,${version},https://github.com/rapid7/metasploit-framework,A popular penetration testing framework that includes many exploits and payloads"
}

function install_routersploit() {
    # CODE-CHECK-WHITELIST=add-history
    colorecho "Installing RouterSploit"
    pipx install --system-site-packages routersploit
    pipx inject routersploit colorama
    add-aliases routersploit
    add-test-command "routersploit --help"
    local version
    version="$(pipx_version routersploit)"
    add-to-list "routersploit,${version},https://github.com/threat9/routersploit,Security audit tool for routers."
}

function install_sliver() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing Sliver"
    if [[ $(uname -m) = 'x86_64' ]]
    then
        local arch="amd64"
    elif [[ $(uname -m) = 'aarch64' ]]
    then
        local arch="arm64"
    else
        criticalecho-noexit "This installation function doesn't support architecture $(uname -m)" && return
    fi
    server_url=$(curl --location --silent "https://api.github.com/repos/BishopFox/sliver/releases/latest" | grep 'browser_download_url.*sliver-server.*linux.*'"$arch"'"' | grep -o 'https://[^"]*')
    client_url=$(curl --location --silent "https://api.github.com/repos/BishopFox/sliver/releases/latest" | grep 'browser_download_url.*sliver-client.*linux.*'"$arch"'"' | grep -o 'https://[^"]*')
    curl --location -o /tmp/sliver-server "$server_url"
    curl --location -o /tmp/sliver-client "$client_url"
    chmod +x /tmp/sliver-server
    chmod +x /tmp/sliver-client
    mv "/tmp/sliver-server" "/opt/tools/bin/sliver-server"
    mv "/tmp/sliver-client" "/opt/tools/bin/sliver-client"
    add-history sliver
    add-test-command "sliver-server help"
    add-test-command "sliver-client help"
    local version
    version="$(cli_version sliver --version)"
    add-to-list "sliver,${version},https://github.com/BishopFox/sliver,Open source / cross-platform and extensible C2 framework"
}

function install_empire() {
    colorecho "Installing Empire"
    wget -O /tmp/packages-microsoft-prod.deb https://packages.microsoft.com/config/debian/13/packages-microsoft-prod.deb
    dpkg -i /tmp/packages-microsoft-prod.deb
    fapt apt-transport-https libicu-dev xclip zip
    install_powershell
    git -C /opt/tools/ clone --depth 1 --recursive --shallow-submodules https://github.com/BC-SECURITY/Empire
    cd /opt/tools/Empire || exit
    python3 -m venv --system-site-packages ./venv
    source ./venv/bin/activate
    pip3 install .
    deactivate
    # TODO : use mysql instead, need to configure that
    sed -i 's/use: mysql/use: sqlite/g' empire/server/config.yaml
    sed -i 's/password: password123/password: exegol4thewin/g' empire/server/config.yaml
    cp -r -v ./empire/server/data/Invoke-Obfuscation /opt/tools/powershell/7/Modules/
    add-aliases empire
    add-history empire
    add-test-command "ps-empire server --help"
    local version
    version="$(git_version /opt/tools/Empire)"
    add-to-list "empire,${version},https://github.com/BC-SECURITY/Empire,post-exploitation and adversary emulation framework"
    # exit the Empire workdir, since it sets the python version to 3.12 and could mess up later installs
    cd || exit
}

function install_villain() {
    colorecho "Installing Villain"
    git -C /opt/tools/ clone --depth 1 https://github.com/t3l3machus/Villain
    cd /opt/tools/Villain || exit
    python3 -m venv --system-site-packages ./venv
    source ./venv/bin/activate
    pip3 install -r ./requirements.txt
    deactivate
    add-aliases villain
    add-history villain
    add-test-command "Villain.py -h"
    local version
    version="$(git_version /opt/tools/Villain)"
    add-to-list "Villain,${version},https://github.com/t3l3machus/Villain,Command & Control Framework"
}

# Package dedicated to command & control frameworks
function package_c2() {
    set_env
    local start_time
    local end_time
    start_time=$(date +%s)
    install_empire                  # Post-ex and adversary simulation framework
    install_pwncat                  # netcat and rlwrap on steroids to handle revshells, automates a few things too
    install_metasploit              # Offensive framework
    install_routersploit            # Exploitation Framework for Embedded Devices
    install_sliver                  # Sliver is an open source cross-platform adversary emulation/red team framework
    install_villain                 # C2 using hoaxShell in Python
    post_install
    end_time=$(date +%s)
    local elapsed_time=$((end_time - start_time))
    colorecho "Package c2 completed in $elapsed_time seconds."
}
