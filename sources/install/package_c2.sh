#!/bin/bash
# Author: The Exegol Project

source common.sh
# sourcing package_ad.sh for the install_powershell() function
source package_ad.sh

function install_pwncat() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing pwncat"
    pipx install --system-site-packages pwncat-cs
    # Because Blowfish has been deprecated, downgrade cryptography version - https://github.com/paramiko/paramiko/issues/2038
    pipx inject pwncat-cs cryptography==36.0.2
    add-history pwncat
    add-test-command "pwncat-cs --version"
    add-to-list "pwncat,https://github.com/calebstewart/pwncat,A lightweight and versatile netcat alternative that includes various additional features."
}

function install_metasploit() {
    colorecho "Installing Metasploit"
    fapt libpcap-dev libpq-dev zlib1g-dev libsqlite3-dev
    git -C /opt/tools clone --depth 1 https://github.com/rapid7/metasploit-framework.git
    cd /opt/tools/metasploit-framework || exit  # rvm gemset ruby-3.1.5@metasploit-framework should be auto setup here

    # Fix msfupdate git config requirements
    git config user.name "exegol"
    git config user.email "exegol@localhost"

    rvm use 3.1.5@metasploit-framework --create

    # install dep manager
    gem install bundler
    bundle install

    # Add missing deps
    gem install rex
    gem install rex-text

    # fixes 'You have already activated timeout 0.2.0, but your Gemfile requires timeout 0.4.1. Since timeout is a default gem, you can either remove your dependency on it or try updating to a newer version of bundler that supports timeout as a default gem.'
    local temp_fix_limit="2025-06-01"
    if [[ "$(date +%Y%m%d)" -gt "$(date -d $temp_fix_limit +%Y%m%d)" ]]; then
      criticalecho "Temp fix expired. Exiting."
    else
      gem install timeout --version 0.4.1
    fi
    rvm use 3.2.2@default

    # msfdb setup
    fapt postgresql
    cp -r /root/.bundle /var/lib/postgresql
    chown -R postgres:postgres /var/lib/postgresql/.bundle
    chmod -R o+rx /opt/tools/metasploit-framework/
    chmod 444 /opt/tools/metasploit-framework/.git/index # fatal: .git/index: index file open failed: Permission denied
    sudo -u postgres sh -c "git config --global --add safe.directory /opt/tools/metasploit-framework && /usr/local/rvm/gems/ruby-3.1.5@metasploit-framework/wrappers/bundle exec /opt/tools/metasploit-framework/msfdb init"
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
    add-to-list "metasploit,https://github.com/rapid7/metasploit-framework,A popular penetration testing framework that includes many exploits and payloads"
}

function install_routersploit() {
    # CODE-CHECK-WHITELIST=add-history
    colorecho "Installing RouterSploit"
    pipx install --system-site-packages routersploit
    pipx inject routersploit colorama
    add-aliases routersploit
    add-test-command "routersploit --help"
    add-to-list "routersploit,https://github.com/threat9/routersploit,Security audit tool for routers."
}

function install_sliver() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing Sliver"
    # making the static version checkout a temporary thing
    # function below will serve as a reminder to update sliver's version regularly
    # when the pipeline fails because the time limit is reached: update the version and the time limit
    # or check if it's possible to make this dynamic
    local temp_fix_limit="2025-04-01"
    if [[ "$(date +%Y%m%d)" -gt "$(date -d $temp_fix_limit +%Y%m%d)" ]]; then
      criticalecho "Temp fix expired. Exiting."
    else
      # Add branch v1.5.41 due to installation of stable branch
      git -C /opt/tools/ clone --branch v1.5.42 --depth 1 https://github.com/BishopFox/sliver.git
      cd /opt/tools/sliver || exit
    fi
    asdf set golang 1.19
    make
    ln -s /opt/tools/sliver/sliver-server /opt/tools/bin/sliver-server
    ln -s /opt/tools/sliver/sliver-client /opt/tools/bin/sliver-client
    add-history sliver
    add-test-command "sliver-server help"
    add-test-command "sliver-client help"
    add-to-list "sliver,https://github.com/BishopFox/sliver,Open source / cross-platform and extensible C2 framework"
}

function install_empire() {
    colorecho "Installing Empire"
    wget -O /tmp/packages-microsoft-prod.deb https://packages.microsoft.com/config/debian/12/packages-microsoft-prod.deb
    dpkg -i /tmp/packages-microsoft-prod.deb
    fapt apt-transport-https libicu-dev xclip zip
    # Installing .NET 6.0 SDK
    wget -O /tmp/dotnet-install.sh https://dot.net/v1/dotnet-install.sh
    chmod +x /tmp/dotnet-install.sh
    /tmp/dotnet-install.sh --channel 6.0
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
    add-test-command "ps-empire client --help"
    add-to-list "empire,https://github.com/BC-SECURITY/Empire,post-exploitation and adversary emulation framework"
    # exit the Empire workdir, since it sets the python version to 3.12 and could mess up later installs
    cd || exit
}

function install_havoc() {
    colorecho "Installing Havoc"
    git -C /opt/tools/ clone --depth 1 https://github.com/HavocFramework/Havoc
    # https://github.com/HavocFramework/Havoc/issues/516 (seems fixed but keeping commented tempfix just in case)
    #    local temp_fix_limit="YYYY-MM-DD"
    #    if [ "$(date +%Y%m%d)" -gt "$(date -d $temp_fix_limit +%Y%m%d)" ]; then
    #      criticalecho "Temp fix expired. Exiting."
    #    else
    #      git -C /opt/tools/ clone https://github.com/HavocFramework/Havoc
    #      git -C /opt/tools/Havoc checkout ea3646e055eb1612dcc956130fd632029dbf0b86
    #      go mod download golang.org/x/sys
    #      go mod download github.com/ugorji/go
    #    fi
    # Building Team Server
    cd /opt/tools/Havoc/teamserver || exit
    cd /opt/tools/Havoc || exit
    sed -i 's/golang-go//' teamserver/Install.sh
    make ts-build
    # ln -v -s /opt/tools/Havoc/havoc /opt/tools/bin/havoc
    # Symbolic link above not needed because Havoc relies on absolute links, the user needs be changed directory when running havoc
    # Building Client
    fapt qtmultimedia5-dev libqt5websockets5-dev
    make client-build || cat /opt/tools/Havoc/client/Build/CMakeFiles/CMakeOutput.log
    add-aliases havoc
    add-history havoc
    add-test-command "havoc "
    add-to-list "Havoc,https://github.com/HavocFramework/Havoc,Command & Control Framework"
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
    add-to-list "Villain,https://github.com/t3l3machus/Villain,Command & Control Framework"
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
    install_havoc                   # C2 in Go
    install_villain                 # C2 using hoaxShell in Python
    post_install
    end_time=$(date +%s)
    local elapsed_time=$((end_time - start_time))
    colorecho "Package c2 completed in $elapsed_time seconds."
}
