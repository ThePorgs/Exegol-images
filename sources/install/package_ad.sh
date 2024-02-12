#!/bin/bash
# Author: The Exegol Project

source common.sh

function install_ad_apt_tools() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing AD apt tools"
    fapt samdump2 smbclient onesixtyone nbtscan ldap-utils

    add-history samdump2
    add-history smbclient
    add-history onesixtyone
    add-history nbtscan
    add-history ldapsearch

    add-test-command "samdump2 -h|& grep 'enable debugging'"        # Dumps Windows 2k/NT/XP/Vista password hashes
    add-test-command "smbclient --help"                             # Small dynamic library that allows iOS apps to access SMB/CIFS file servers
    add-test-command "onesixtyone 127.0.0.1 public"                 # SNMP scanning
    add-test-command "nbtscan 127.0.0.1"                            # NetBIOS scanning tool
    add-test-command "ldapsearch --help|& grep 'Search options'"    # Perform queries on a LDAP server

    local version
    version=$(samdump2 -h | head -n 1 | awk '{print $2}')
    local version
    version=$(smbclient --version | awk '{print $2}')
    local version
    version=$(onesixtyone | head -n 1 | awk '{print $2}')
    local version
    version=$(nbtscan | grep NBTscan | head -n 1 | awk '{print $3}' | sed 's/\.$//')

    add-to-list "samdump2,https://github.com/azan121468/SAMdump2,A tool to dump Windows NT/2k/XP/Vista password hashes from SAM files,$version"
    add-to-list "smbclient,https://github.com/samba-team/samba,SMBclient is a command-line utility that allows you to access Windows shared resources,$version"
    add-to-list "onesixtyone,https://github.com/trailofbits/onesixtyone,onesixtyone is an SNMP scanner which utilizes a sweep technique to achieve very high performance.,$version"
    add-to-list "nbtscan,https://github.com/charlesroelli/nbtscan,NBTscan is a program for scanning IP networks for NetBIOS name information.,$version"
    add-to-list "ldapsearch,https://wiki.debian.org/LDAP/LDAPUtils,Search for and display entries (ldap),$version"
}

function install_pretender() {
    # CODE-CHECK-WHITELIST=add-aliases,add-version
    colorecho "Installing Pretender"
    go install -v github.com/RedTeamPentesting/pretender@latest
    asdf reshim golang
    add-history pretender
    add-test-command "pretender --help |& grep pretender"
    add-to-list "pretender,https://github.com/RedTeamPentesting/pretender,an mitm tool for helping with relay attacks.,$version"
}

function install_responder() {
    colorecho "Installing Responder"
    git -C /opt/tools/ clone --depth 1 https://github.com/lgandx/Responder
    cd /opt/tools/Responder || exit
    fapt gcc-mingw-w64-x86-64
    python3 -m venv ./venv
    source ./venv/bin/activate
    pip3 install -r requirements.txt
    # following requirements needed by MultiRelay.py
    pip3 install pycryptodome pycryptodomex six
    deactivate
    sed -i 's/ Random/ 1122334455667788/g' /opt/tools/Responder/Responder.conf
    sed -i 's/files\/AccessDenied.html/\/opt\/tools\/Responder\/files\/AccessDenied.html/g' /opt/tools/Responder/Responder.conf
    sed -i 's/files\/BindShell.exe/\/opt\/tools\/Responder\/files\/BindShell.exe/g' /opt/tools/Responder/Responder.conf
    sed -i 's/certs\/responder.crt/\/opt\/tools\/Responder\/certs\/responder.crt/g' /opt/tools/Responder/Responder.conf
    sed -i 's/certs\/responder.key/\/opt\/tools\/Responder\/certs\/responder.key/g' /opt/tools/Responder/Responder.conf
    x86_64-w64-mingw32-gcc /opt/tools/Responder/tools/MultiRelay/bin/Runas.c -o /opt/tools/Responder/tools/MultiRelay/bin/Runas.exe -municode -lwtsapi32 -luserenv
    x86_64-w64-mingw32-gcc /opt/tools/Responder/tools/MultiRelay/bin/Syssvc.c -o /opt/tools/Responder/tools/MultiRelay/bin/Syssvc.exe -municode
    /opt/tools/Responder/certs/gen-self-signed-cert.sh
    add-aliases responder
    add-history responder
    local version
    version=$(Responder.py --version | grep Responder | head -n 1 | awk '{print $6}')
    add-test-command "Responder.py --version"
    add-test-command "RunFinger.py --help"
    add-test-command "MultiRelay.py --help"
    add-to-list "responder,https://github.com/lgandx/Responder,a LLMNR / NBT-NS and MDNS poisoner.,$version"
}

function install_sprayhound() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing sprayhound"
    pipx install git+https://github.com/Hackndo/sprayhound
    add-history sprayhound
    local version
    version=$(sprayhound --help | grep spraying | head -n 1 | awk '{print $2}')
    add-test-command "sprayhound --help"
    add-to-list "sprayhound,https://github.com/Hackndo/Sprayhound,Active Directory password audit tool.,$version"
}

function install_smartbrute() {
    # CODE-CHECK-WHITELIST=add-aliases,add-version
    colorecho "Installing smartbrute"
    pipx install git+https://github.com/ShutdownRepo/smartbrute
    add-history smartbrute
    add-test-command "smartbrute --help"
    add-to-list "smartbrute,https://github.com/ShutdownRepo/SmartBrute,The smart password spraying and bruteforcing tool for Active Directory Domain Services.,$version"
}

function install_ldapdomaindump() {
    # CODE-CHECK-WHITELIST=add-aliases,add-version
    colorecho "Installing ldapdomaindump"
    pipx install git+https://github.com/dirkjanm/ldapdomaindump
    add-history ldapdomaindump
    add-test-command "ldapdomaindump --help"
    add-to-list "ldapdomaindump,https://github.com/dirkjanm/ldapdomaindump,A tool for dumping domain data from an LDAP service,$version"
}

function install_crackmapexec() {
    colorecho "Installing CrackMapExec"
    git -C /opt/tools/ clone --depth 1 https://github.com/Porchetta-Industries/CrackMapExec
    pipx install /opt/tools/CrackMapExec/
    mkdir -p ~/.cme
    [[ -f ~/.cme/cme.conf ]] && mv ~/.cme/cme.conf ~/.cme/cme.conf.bak
    cp -v /root/sources/assets/crackmapexec/cme.conf ~/.cme/cme.conf
    # below is for having the ability to check the source code when working with modules and so on
    cp -v /root/sources/assets/grc/conf.cme /usr/share/grc/conf.cme
    add-aliases crackmapexec
    add-history crackmapexec
    local version
    version=$(crackmapexec --version | grep - | awk '{print $1}')
    add-test-command "crackmapexec --help"
    add-to-list "crackmapexec,https://github.com/Porchetta-Industries/CrackMapExec,Network scanner.,$version"
}

function install_bloodhound-py() {
    # CODE-CHECK-WHITELIST=add-version
    colorecho "Installing and Python ingestor for BloodHound"
    pipx install git+https://github.com/fox-it/BloodHound.py
    add-aliases bloodhound-py
    add-history bloodhound-py
    add-test-command "bloodhound.py --help"
    add-to-list "bloodhound.py,https://github.com/fox-it/BloodHound.py,BloodHound ingestor in Python.,$version"
}


function install_bloodhound-ce-py() {
    # CODE-CHECK-WHITELIST=add-aliases,add-version
    colorecho "Installing and Python ingestor for BloodHound-CE"
    git -C /opt/tools/ clone https://github.com/dirkjanm/BloodHound.py BloodHound-CE.py
    cd /opt/tools/BloodHound-CE.py || exit
    git checkout bloodhound-ce
    python3 -m venv ./venv
    source ./venv/bin/activate
    pip3 install .
    deactivate
    ln -v -s /opt/tools/BloodHound-CE.py/venv/bin/bloodhound-python /opt/tools/bin/bloodhound-ce.py
    add-history bloodhound-ce-py
    add-test-command "bloodhound-ce.py --help"
    add-to-list "bloodhound-ce.py,https://github.com/fox-it/BloodHound.py,BloodHound-CE ingestor in Python.,$version"
}

function install_bloodhound() {
    # CODE-CHECK-WHITELIST=add-version
    colorecho "Installing BloodHound from sources"
    git -C /opt/tools/ clone --depth 1 https://github.com/BloodHoundAD/BloodHound/
    mv /opt/tools/BloodHound /opt/tools/BloodHound4
    zsh -c "source ~/.zshrc && cd /opt/tools/BloodHound4 && nvm install 16.13.0 && nvm use 16.13.0 && npm install -g electron-packager && npm install && npm run build:linux && nvm use default"
    if [[ $(uname -m) = 'x86_64' ]]
    then
        ln -s /opt/tools/BloodHound4/BloodHound-linux-x64/BloodHound /opt/tools/BloodHound4/BloodHound
    elif [[ $(uname -m) = 'aarch64' ]]
    then
        fapt libgbm1
        ln -s /opt/tools/BloodHound4/BloodHound-linux-arm64/BloodHound /opt/tools/BloodHound4/BloodHound
    elif [[ $(uname -m) = 'armv7l' ]]
    then
        fapt libgbm1
        ln -s /opt/tools/BloodHound4/BloodHound-linux-armv7l/BloodHound /opt/tools/BloodHound4/BloodHound
    else
        criticalecho-noexit "This installation function doesn't support architecture $(uname -m)" && return
    fi
    mkdir -p ~/.config/bloodhound
    cp -v /root/sources/assets/bloodhound/config.json ~/.config/bloodhound/config.json
    cp -v /root/sources/assets/bloodhound/customqueries.json ~/.config/bloodhound/customqueries.json
    add-aliases bloodhound
    add-history bloodhound
    add-test-command "ldd /opt/tools/BloodHound4/BloodHound"
    add-to-list "bloodhound,https://github.com/BloodHoundAD/BloodHound,Active Directory security tool for reconnaissance and attacking AD environments.,$version"
}

function install_bloodhound-ce() {
    # CODE-CHECK-WHITELIST=add-aliases,add-history
    colorecho "Installing BloodHound-CE"

    # Installing & Configuring the database
    fapt postgresql postgresql-client
    # only expose postgresql on localhost
    sed -i 's/#listen_addresse/listen_addresse/' /etc/postgresql/15/main/postgresql.conf
    service postgresql start
    # avoid permissions issues when impersonating postgres
    cd /tmp || exit
    sudo -u postgres psql -c "CREATE USER bloodhound WITH PASSWORD 'exegol4thewin';"
    sudo -u postgres psql -c "CREATE DATABASE bloodhound;"
    sudo -u postgres psql -c "ALTER DATABASE bloodhound OWNER TO bloodhound;"
    service postgresql stop

    # Build BloodHound-CE
    mkdir -p /opt/tools/BloodHound-CE/
    git -C /opt/tools/BloodHound-CE/ clone --depth 1 https://github.com/SpecterOps/BloodHound.git src
    cd /opt/tools/BloodHound-CE/src/packages/javascript/bh-shared-ui || exit
    zsh -c "source ~/.zshrc && nvm install 18 && nvm use 18 && yarn install --immutable && yarn build"
    cd /opt/tools/BloodHound-CE/src/ || exit
    catch_and_retry VERSION=v999.999.999 CHECKOUT_HASH="" python3 ./packages/python/beagle/main.py build --verbose --ci

    # Ingestors: bloodhound-ce requires the ingestors to be in a specific directory and checks that when starting, they need to be downloaded here
    mkdir -p /opt/tools/BloodHound-CE/collectors/sharphound
    mkdir -p /opt/tools/BloodHound-CE/collectors/azurehound
    ## SharpHound
    local SHARPHOUND_URL
    SHARPHOUND_URL=$(curl --location --silent "https://api.github.com/repos/BloodHoundAD/SharpHound/releases/latest" | grep 'SharpHound-.*.zip' | grep -v 'debug' | grep -o 'https://[^"]*')
    wget --directory-prefix /opt/tools/BloodHound-CE/collectors/sharphound/ "$SHARPHOUND_URL"
    local SHARPHOUND_NAME
    SHARPHOUND_NAME=$(curl --location --silent "https://api.github.com/repos/BloodHoundAD/SharpHound/releases/latest" | grep -o 'SharpHound-.*.zip' | grep -v debug | uniq)
    sha256sum "/opt/tools/BloodHound-CE/collectors/sharphound/$SHARPHOUND_NAME" > "/opt/tools/BloodHound-CE/collectors/sharphound/$SHARPHOUND_NAME.sha256"
    ## AzureHound
    local AZUREHOUND_URL_AMD64
    local AZUREHOUND_URL_ARM64
    AZUREHOUND_URL_AMD64=$(curl --location --silent "https://api.github.com/repos/BloodHoundAD/AzureHound/releases/latest" | grep 'azurehound-linux-arm64.zip' | grep -v 'sha' | grep -o 'https://[^"]*')
    AZUREHOUND_URL_ARM64=$(curl --location --silent "https://api.github.com/repos/BloodHoundAD/AzureHound/releases/latest" | grep 'azurehound-linux-amd64.zip' | grep -v 'sha' | grep -o 'https://[^"]*')
    wget --directory-prefix /opt/tools/BloodHound-CE/collectors/azurehound/ "$AZUREHOUND_URL_AMD64"
    wget --directory-prefix /opt/tools/BloodHound-CE/collectors/azurehound/ "$AZUREHOUND_URL_ARM64"

    # Files and directories
    # work directory required by bloodhound
    mkdir /opt/tools/BloodHound-CE/work
    ln -v -s /opt/tools/BloodHound-CE/src/artifacts/bhapi /opt/tools/BloodHound-CE/bloodhound
    cp -v /opt/tools/BloodHound-CE/src/dockerfiles/configs/bloodhound.config.json /opt/tools/BloodHound-CE/
    cp -v /root/sources/assets/bloodhound-ce/* /opt/tools/bin/
    chmod +x /opt/tools/bin/bloodhound*

    # Configuration
    sed -i "s#app-db#127.0.0.1##" /opt/tools/BloodHound-CE/bloodhound.config.json
    sed -i "s#graph-db#127.0.0.1##" /opt/tools/BloodHound-CE/bloodhound.config.json
    sed -i "s#8080#1030##" /opt/tools/BloodHound-CE/bloodhound.config.json
    sed -i "s#0.0.0.0#127.0.0.1##" /opt/tools/BloodHound-CE/bloodhound.config.json
    sed -i "s#neo4j:bloodhoundcommunityedition#neo4j:exegol4thewin##" /opt/tools/BloodHound-CE/bloodhound.config.json
    sed -i "s#user=bloodhound password=bloodhoundcommunityedition#user=bloodhound password=exegol4thewin##" /opt/tools/BloodHound-CE/bloodhound.config.json
    sed -i "s#/etc/bloodhound/collectors#/opt/tools/BloodHound-CE/collectors##" /opt/tools/BloodHound-CE/bloodhound.config.json
    sed -i "s#/opt/bloodhound/work#/opt/tools/BloodHound-CE/work##" /opt/tools/BloodHound-CE/bloodhound.config.json

    local version
    version=$(/opt/tools/BloodHound-CE/bloodhound -version | awk '{print $4}')
    # the following test command probably needs to be changed. No idea how we can make sure bloodhound-ce works as intended.
    add-test-command "/opt/tools/BloodHound-CE/bloodhound -version"
    add-to-list "BloodHound-CE,https://github.com/SpecterOps/BloodHound,Active Directory security tool for reconnaissance and attacking AD environments (Community Edition),$version"
}

function install_cypheroth() {
    # CODE-CHECK-WHITELIST=add-version
    colorecho "Installing cypheroth"
    git -C /opt/tools/ clone --depth 1 https://github.com/seajaysec/cypheroth
    add-aliases cypheroth
    add-history cypheroth
    add-test-command "cypheroth.sh --help|& grep 'Example with Defaults:'"
    add-to-list "cyperoth,https://github.com/seajaysec/cypheroth,Automated extensible toolset that runs cypher queries against Bloodhound's Neo4j backend and saves output to spreadsheets.,$version"
}

function install_mitm6_pip() {
    # CODE-CHECK-WHITELIST=add-aliases,add-version
    colorecho "Installing mitm6 with pip"
    pipx install mitm6
    add-history mitm6
    add-test-command "mitm6 --help"
    add-to-list "mitm6,https://github.com/fox-it/mitm6,Tool to conduct a man-in-the-middle attack against IPv6 protocols.,$version"
}

function install_aclpwn() {
    # CODE-CHECK-WHITELIST=add-aliases,add-version
    colorecho "Installing aclpwn with pip"
    pipx install git+https://github.com/aas-n/aclpwn.py
    add-history aclpwn
    add-test-command "aclpwn -h"
    add-to-list "aclpwn,https://github.com/aas-n/aclpwn.py,Tool for testing the security of Active Directory access controls.,$version"
}

function install_impacket() {
    colorecho "Installing Impacket scripts"
    pipx install git+https://github.com/ThePorgs/impacket
    pipx inject impacket chardet
    local temp_fix_limit="2024-03-20"
    if [[ "$(date +%Y%m%d)" -gt "$(date -d $temp_fix_limit +%Y%m%d)" ]]; then
      criticalecho "Temp fix expired. Exiting."
    else
      pipx inject impacket pycryptodome
    fi
    cp -v /root/sources/assets/grc/conf.ntlmrelayx /usr/share/grc/conf.ntlmrelayx
    cp -v /root/sources/assets/grc/conf.secretsdump /usr/share/grc/conf.secretsdump
    cp -v /root/sources/assets/grc/conf.getgpppassword /usr/share/grc/conf.getgpppassword
    cp -v /root/sources/assets/grc/conf.rbcd /usr/share/grc/conf.rbcd
    cp -v /root/sources/assets/grc/conf.describeTicket /usr/share/grc/conf.describeTicket
    add-aliases impacket
    add-history impacket
    local version
    version=$(ntlmrelayx.py --help | head -n 1 | awk '{print $5}')
    add-test-command "ntlmrelayx.py --help"
    add-test-command "secretsdump.py --help"
    add-test-command "Get-GPPPassword.py --help"
    add-test-command "getST.py --help |& grep 'u2u'"
    add-test-command "ticketer.py --help |& grep impersonate"
    add-test-command "ticketer.py --help |& grep hours"
    add-test-command "ticketer.py --help |& grep extra-pac"
    add-test-command "dacledit.py --help"
    add-test-command "describeTicket.py --help"
    add-to-list "impacket,https://github.com/ThePorgs/impacket,Set of tools for working with network protocols (ThePorgs version).,$version"
}

function install_pykek() {
    # CODE-CHECK-WHITELIST=add-version
    colorecho "Installing Python Kernel Exploit Kit (pykek) for MS14-068"
    git -C /opt/tools/ clone --depth 1 https://github.com/preempt/pykek
    add-aliases pykek
    add-history pykek
    add-test-command "ms14-068.py |& grep '<clearPassword>'"
    add-to-list "pykek,https://github.com/preempt/pykek,PyKEK (Python Kerberos Exploitation Kit) a python library to manipulate KRB5-related data.,$version"
}

function install_lsassy() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing lsassy"
    pipx install lsassy
    add-history lsassy
    local version
    version=$(lsassy --version | awk '{print $3}' | tr -d ')')
    add-test-command "lsassy --version"
    add-to-list "lsassy,https://github.com/Hackndo/lsassy,Windows secrets and passwords extraction tool.,$version"
}

function install_privexchange() {
    # CODE-CHECK-WHITELIST=add-version
    colorecho "Installing privexchange"
    git -C /opt/tools/ clone --depth 1 https://github.com/dirkjanm/PrivExchange
    cd /opt/tools/PrivExchange || exit
    python3 -m venv ./venv
    source ./venv/bin/activate
    pip3 install impacket
    deactivate
    add-aliases privexchange
    add-history privexchange
    add-test-command "privexchange.py --help"
    add-to-list "privexchange,https://github.com/dirkjanm/PrivExchange,a tool to perform attacks against Microsoft Exchange server using NTLM relay techniques,$version"
}

function install_ruler() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Downloading ruler and form templates"
    go install -v github.com/sensepost/ruler@latest
    asdf reshim golang
    add-history ruler
    local version
    version=$(ruler --version | awk '{print $3}')
    add-test-command "ruler --version"
    add-to-list "ruler,https://github.com/sensepost/ruler,Outlook Rules exploitation framework.,$version"
}

function install_upx() {
    # CODE-CHECK-WHITELIST=add-aliases,add-history
    colorecho "Installing upx"
    if [[ $(uname -m) = 'x86_64' ]]
    then
        local arch="amd64"

    elif [[ $(uname -m) = 'aarch64' ]]
    then
        local arch="arm64"
    else
        criticalecho-noexit "This installation function doesn't support architecture $(uname -m)" && return
    fi
    local upx_url
    upx_url=$(curl --location --silent "https://api.github.com/repos/upx/upx/releases/latest" | grep 'browser_download_url.*upx.*'"$arch"'.*tar.xz"' | grep -o 'https://[^"]*')
    curl --location -o /tmp/upx.tar.xz "$upx_url"
    tar -xf /tmp/upx.tar.xz --directory /tmp
    rm /tmp/upx.tar.xz
    mv /tmp/upx* /opt/tools/upx
    ln -v -s /opt/tools/upx/upx /opt/tools/bin/upx
    ln -v -s upx /opt/tools/bin/upx-ucl
    local version
    version=$(upx --version | head -n 1 | awk '{print $2}')
    add-test-command "upx --help"
    add-to-list "upx,https://github.com/upx/upx,UPX is an advanced executable packer,$version"
}

function install_darkarmour() {
    colorecho "Installing darkarmour"
    fapt mingw-w64-tools mingw-w64-common g++-mingw-w64 gcc-mingw-w64 osslsigncode
    install_upx
    git -C /opt/tools/ clone --depth 1 https://github.com/bats3c/darkarmour
    add-aliases darkarmour
    add-history darkarmour
    local version
    version=$(darkarmour.py --help | grep Version | awk '{print $12}')
    add-test-command "darkarmour.py --help"
    add-to-list "darkarmour,https://github.com/bats3c/darkarmour,a tool to detect and evade common antivirus products,$version"
}

function install_amber() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing amber"
    # Installing keystone requirement
    git -C /opt/tools/ clone --depth 1 https://github.com/EgeBalci/keystone
    cd /opt/tools/keystone || exit
    mkdir build && cd build || exit
    ../make-lib.sh
    cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF -DLLVM_TARGETS_TO_BUILD="AArch64;X86" -G "Unix Makefiles" ..
    make -j8
    make install && ldconfig
    # Installing amber
    go install -v github.com/EgeBalci/amber@latest
    asdf reshim golang
    add-history amber
    local version
    version=$(amber --version | tail -n 1)
    add-test-command "amber --help"
    add-to-list "amber,https://github.com/EgeBalci/amber,Forensic tool to recover browser history / cookies and credentials,$version"
}

function install_powershell() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing powershell"
    if /opt/tools/bin/powershell -Version; then
        colorecho "powershell seems already installed, skipping..."
        return
    else
        if [[ $(uname -m) = 'x86_64' ]]
        then
            curl -L -o /tmp/powershell.tar.gz https://github.com/PowerShell/PowerShell/releases/download/v7.3.4/powershell-7.3.4-linux-x64.tar.gz
        elif [[ $(uname -m) = 'aarch64' ]]
        then
            curl -L -o /tmp/powershell.tar.gz https://github.com/PowerShell/PowerShell/releases/download/v7.3.4/powershell-7.3.4-linux-arm64.tar.gz
        elif [[ $(uname -m) = 'armv7l' ]]
        then
            curl -L -o /tmp/powershell.tar.gz https://github.com/PowerShell/PowerShell/releases/download/v7.3.4/powershell-7.3.4-linux-arm32.tar.gz
        else
            criticalecho-noexit "This installation function doesn't support architecture $(uname -m)" && return
        fi
        mkdir -v -p /opt/tools/powershell/7
        tar xvfz /tmp/powershell.tar.gz -C /opt/tools/powershell/7
        chmod -v +x /opt/tools/powershell/7/pwsh
        rm -v /tmp/powershell.tar.gz
        ln -v -s /opt/tools/powershell/7/pwsh /opt/tools/bin/pwsh
        ln -v -s /opt/tools/powershell/7/pwsh /opt/tools/bin/powershell
        add-history powershell
        local version
    version=$(powershell -Version | awk '{print $2}')
        add-test-command "powershell -Version"
        add-to-list "powershell,https://github.com/PowerShell/PowerShell,a command-line shell and scripting language designed for system administration and automation,$version"
    fi
}

function install_krbrelayx() {
    # CODE-CHECK-WHITELIST=add-version
    colorecho "Installing krbrelayx"
    git -C /opt/tools/ clone --depth 1 https://github.com/dirkjanm/krbrelayx
    cd /opt/tools/krbrelayx || exit
    python3 -m venv ./venv
    source ./venv/bin/activate
    pip3 install dnspython ldap3 impacket dsinternals pycryptodome
    deactivate
    cp -v /root/sources/assets/grc/conf.krbrelayx /usr/share/grc/conf.krbrelayx
    add-aliases krbrelayx
    add-history krbrelayx
    add-test-command "krbrelayx.py --help"
    add-test-command "addspn.py --help"
    add-test-command "addspn.py --help"
    add-test-command "printerbug.py --help"
    add-to-list "krbrelayx,https://github.com/dirkjanm/krbrelayx,a tool for performing Kerberos relay attacks,$version"
}

function install_evilwinrm() {
    colorecho "Installing evil-winrm"
    rvm use 3.2.2@evil-winrm --create
    gem install evil-winrm
    rvm use 3.2.2@default
    add-aliases evil-winrm
    add-history evil-winrm
    local version
    version=$(evil-winrm --version)
    add-test-command "evil-winrm --help"
    add-to-list "evilwinrm,https://github.com/Hackplayers/evil-winrm,Tool to connect to a remote Windows system with WinRM.,$version"
}

function install_pypykatz() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing pypykatz"
    # without following fix, tool raises "oscrypto.errors.LibraryNotFoundError: Error detecting the version of libcrypto"
    # see https://github.com/wbond/oscrypto/issues/78 and https://github.com/wbond/oscrypto/issues/75
    local temp_fix_limit="2024-03-20"
    if [[ "$(date +%Y%m%d)" -gt "$(date -d $temp_fix_limit +%Y%m%d)" ]]; then
      criticalecho "Temp fix expired. Exiting."
    else
      git -C /opt/tools/ clone --depth 1 https://github.com/skelsec/pypykatz
      cd /opt/tools/pypykatz || exit
      python3 -m venv ./venv/
      source ./venv/bin/activate
      pip3 install .
      pip3 install --force oscrypto@git+https://github.com/wbond/oscrypto.git
      ln -v -s /opt/tools/pypykatz/venv/bin/pypykatz /opt/tools/bin/pypykatz
      deactivate
    fi
    # pipx install pypykatz
    add-history pypykatz
    local version
    version=$(pypykatz version)
    add-test-command "pypykatz version"
    add-test-command "pypykatz crypto nt 'exegol4thewin'"
    add-to-list "pypykatz,https://github.com/skelsec/pypykatz,a Python library for mimikatz-like functionality,$version"
}

function install_krbjack() {
    # CODE-CHECK-WHITELIST=add-aliases,add-history,add-version
    colorecho "Installing krbjack"
    pipx install krbjack
    add-test-command "krbjack --help"
    add-to-list "krbjack,https://github.com/almandin/krbjack,A Kerberos AP-REQ hijacking tool with DNS unsecure updates abuse.,$version"
}

function install_enyx() {
    # CODE-CHECK-WHITELIST=add-version
    colorecho "Installing enyx"
    git -C /opt/tools/ clone --depth 1 https://github.com/trickster0/Enyx
    add-aliases enyx
    add-history enyx
    add-test-command "enyx.py"
    add-to-list "enyx,https://github.com/trickster0/enyx,Framework for building offensive security tools.,$version"
}

function install_enum4linux-ng() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing enum4linux-ng"
    pipx install git+https://github.com/cddmp/enum4linux-ng
    add-history enum4linux-ng
    local version
    version=$(enum4linux-ng --help | grep ENUM4LINUX | awk '{print $5}' | tr -d '()')
    add-test-command "enum4linux-ng --help"
    add-to-list "enum4linux-ng,https://github.com/cddmp/enum4linux-ng,Tool for enumerating information from Windows and Samba systems.,$version"
}

function install_zerologon() {
    # CODE-CHECK-WHITELIST=add-version
    colorecho "Pulling CVE-2020-1472 exploit and scan scripts"
    mkdir /opt/tools/zerologon
    cd /opt/tools/zerologon || exit
    python3 -m venv ./venv
    source ./venv/bin/activate
    pip3 install impacket
    deactivate
    git -C /opt/tools/zerologon clone --depth 1 https://github.com/SecuraBV/CVE-2020-1472 zerologon-scan
    git -C /opt/tools/zerologon clone --depth 1 https://github.com/dirkjanm/CVE-2020-1472 zerologon-exploit
    add-aliases zerologon
    add-history zerologon
    add-test-command "zerologon-scan.py |& grep Usage"
    add-to-list "zerologon,https://github.com/SecuraBV/CVE-2020-1472,Exploit for the Zerologon vulnerability (CVE-2020-1472).,$version"
}

function install_libmspack() {
    # CODE-CHECK-WHITELIST=add-version
    colorecho "Installing libmspack"
    git -C /opt/tools/ clone --depth 1 https://github.com/kyz/libmspack.git
    cd /opt/tools/libmspack/libmspack || exit
    ./rebuild.sh
    ./configure
    make
    add-aliases libmspack
    add-history libmspack
    add-test-command "oabextract"
    add-to-list "libmspack,https://github.com/kyz/libmspack,C library for Microsoft compression formats.,$version"
}

function install_windapsearch-go() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing Go windapsearch"
    # Install mage dependency
    git -C /opt/tools/ clone --depth 1 https://github.com/magefile/mage
    cd /opt/tools/mage || exit
    go run bootstrap.go
    asdf reshim golang
    # Install windapsearch tool
    git -C /opt/tools/ clone --depth 1 https://github.com/ropnop/go-windapsearch
    cd /opt/tools/go-windapsearch || exit
    mage build
    ln -v -s /opt/tools/go-windapsearch/windapsearch /opt/tools/bin/windapsearch
    add-history windapsearch
    local version
    version=$(windapsearch --version | awk '{print $2}' | sed '$ d')
    add-test-command "windapsearch --version"
    add-to-list "windapsearch-go,https://github.com/ropnop/go-windapsearch/,Active Directory enumeration tool.,$version"
}

function install_oaburl() {
    # CODE-CHECK-WHITELIST=add-version
    colorecho "Downloading oaburl.py"
    mkdir /opt/tools/OABUrl
    wget -O /opt/tools/OABUrl/oaburl.py "https://gist.githubusercontent.com/snovvcrash/4e76aaf2a8750922f546eed81aa51438/raw/96ec2f68a905eed4d519d9734e62edba96fd15ff/oaburl.py"
    cd /opt/tools/OABUrl/ || exit
    python3 -m venv ./venv
    source ./venv/bin/activate
    pip3 install requests
    deactivate
    add-aliases oaburl
    add-history oaburl
    add-test-command "oaburl.py --help"
    add-to-list "oaburl,https://gist.githubusercontent.com/snovvcrash/4e76aaf2a8750922f546eed81aa51438/raw/96ec2f68a905eed4d519d9734e62edba96fd15ff/oaburl.py,Find Open redirects and other vulnerabilities.,$version"
}

function install_lnkup() {
    # CODE-CHECK-WHITELIST=add-version
    colorecho "Installing LNKUp"
    git -C /opt/tools/ clone --depth 1 https://github.com/Plazmaz/LNKUp
    cd /opt/tools/LNKUp || exit
    virtualenv --python python2 ./venv
    source ./venv/bin/activate
    pip2 install -r requirements.txt
    deactivate
    add-aliases lnkup
    add-history lnkup
    add-test-command "lnk-generate.py --help"
    add-to-list "lnkup,https://github.com/Plazmaz/lnkUp,This tool will allow you to generate LNK payloads. Upon rendering or being run they will exfiltrate data.,$version"
}

function install_polenum() {
    # CODE-CHECK-WHITELIST=add-version
    colorecho "Installing polenum"
    git -C /opt/tools/ clone --depth 1 https://github.com/Wh1t3Fox/polenum
    cd /opt/tools/polenum || exit
    python3 -m venv ./venv/
    source ./venv/bin/activate
    pip3 install impacket
    deactivate
    add-aliases polenum
    add-history polenum
    add-test-command "polenum.py --help"
    add-to-list "polenum,https://github.com/Wh1t3Fox/polenum,Polenum is a Python script which uses the Impacket library to extract user information through the SMB protocol.,$version"
}

function install_smbmap() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing smbmap"
    git -C /opt/tools clone --depth 1 https://github.com/ShawnDEvans/smbmap
    cd /opt/tools/smbmap || exit
    pipx install .
    add-history smbmap
    local version
    version=$(smbmap --help | grep Samba | awk '{print $6}')
    add-test-command "smbmap --help"
    add-to-list "smbmap,https://github.com/ShawnDEvans/smbmap,A tool to enumerate SMB shares and check for null sessions,$version"
}

function install_pth-tools() {
    colorecho "Installing pth-tools"
    if [[ $(uname -m) = 'x86_64' ]]
    then
        fapt libreadline8 libreadline-dev
        git -C /opt/tools clone --depth 1 https://github.com/byt3bl33d3r/pth-toolkit
        ln -s /usr/lib/x86_64-linux-gnu/libreadline.so /opt/tools/pth-toolkit/lib/libreadline.so.6
        add-aliases pth-tools
        add-history pth-tools
        local version
    version=$(pth-net --version | awk '{print $2}')
        add-test-command "pth-net --version"
        add-test-command "pth-rpcclient --version"
        add-test-command "pth-smbclient --version"
        add-test-command "pth-smbget --version"
        add-test-command "pth-winexe --help"
        add-test-command "pth-wmic --help"
        add-test-command "pth-wmis --help"
        add-to-list "pth-tools,https://github.com/byt3bl33d3r/pth-toolkit,A toolkit to perform pass-the-hash attacks,$version"
    elif [[ $(uname -m) = 'aarch64' ]]
    then
        criticalecho-noexit "This installation function doesn't support architecture $(uname -m)" && return
    fi
}

function install_smtp-user-enum() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing smtp-user-enum"
    pipx install smtp-user-enum
    add-history smtp-user-enum
    local version
    version=$(smtp-user-enum --version | awk '{print $2}')
    add-test-command "smtp-user-enum --help"
    add-to-list "smtp-user-enum,https://github.com/pentestmonkey/smtp-user-enum,A tool to enumerate email addresses via SMTP,$version"
}

function install_gpp-decrypt() {
    colorecho "Installing gpp-decrypt"
    git -C /opt/tools/ clone --depth 1 https://github.com/t0thkr1s/gpp-decrypt
    cd /opt/tools/gpp-decrypt || exit
    python3 -m venv ./venv/
    source ./venv/bin/activate
    pip3 install pycryptodome colorama
    deactivate
    add-aliases gpp-decrypt
    add-history gpp-decrypt
    local version
    version=$(gpp-decrypt.py --version | grep gpp-decrypt | awk '{print $2}')
    add-test-command "gpp-decrypt.py -f /opt/tools/gpp-decrypt/groups.xml"
    add-to-list "gpp-decrypt,https://github.com/t0thkr1s/gpp-decrypt,A tool to decrypt Group Policy Preferences passwords,$version"
}

function install_ntlmv1-multi() {
    # CODE-CHECK-WHITELIST=add-version
    colorecho "Installing ntlmv1 multi tool"
    git -C /opt/tools clone --depth 1 https://github.com/evilmog/ntlmv1-multi
    add-aliases ntlmv1-multi
    add-history ntlmv1-multi
    add-test-command "ntlmv1-multi.py --ntlmv1 a::a:a:a:a"
    add-to-list "ntlmv1-multi,https://github.com/evilmog/ntlmv1-multi,Exploit a vulnerability in Microsoft Windows to gain system-level access.,$version"
}

function install_hashonymize() {
    # CODE-CHECK-WHITELIST=add-aliases,add-version
    colorecho "Installing hashonymizer"
    pipx install git+https://github.com/ShutdownRepo/hashonymize
    add-history hashonymize
    add-test-command "hashonymize --help"
    add-to-list "hashonymize,https://github.com/ShutdownRepo/hashonymize,This small tool is aimed at anonymizing hashes files for offline but online cracking like Google Collab for instance (see https://github.com/ShutdownRepo/google-colab-hashcat).,$version"
}

function install_gosecretsdump() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing gosecretsdump"
    go install -v github.com/C-Sto/gosecretsdump@latest
    asdf reshim golang
    add-history gosecretsdump
    local version
    version=$(gosecretsdump -version | awk '{print $2}')
    add-test-command "gosecretsdump -version"
    add-to-list "gosecretsdump,https://github.com/c-sto/gosecretsdump,Implements NTLMSSP network authentication protocol in Go,$version"
}

function install_adidnsdump() {
    # CODE-CHECK-WHITELIST=add-aliases,add-version
    colorecho "Installing adidnsdump"
    pipx install git+https://github.com/dirkjanm/adidnsdump
    pipx inject adidnsdump pycryptodome
    add-history adidnsdump
    add-test-command "adidnsdump --help"
    add-to-list "adidnsdump,https://github.com/dirkjanm/adidnsdump,Active Directory Integrated DNS dump utility,$version"
}

function install_pygpoabuse() {
    # CODE-CHECK-WHITELIST=add-version
    colorecho "Installing pyGPOabuse"
    git -C /opt/tools/ clone --depth 1 https://github.com/Hackndo/pyGPOAbuse
    cd /opt/tools/pyGPOAbuse || exit
    python3 -m venv ./venv/
    source ./venv/bin/activate
    pip3 install -r requirements.txt
    # without following fix, tool raises "oscrypto.errors.LibraryNotFoundError: Error detecting the version of libcrypto"
    # see https://github.com/wbond/oscrypto/issues/78 and https://github.com/wbond/oscrypto/issues/75
    local temp_fix_limit="2024-03-20"
    if [[ "$(date +%Y%m%d)" -gt "$(date -d $temp_fix_limit +%Y%m%d)" ]]; then
      criticalecho "Temp fix expired. Exiting."
    else
      pip3 install --force oscrypto@git+https://github.com/wbond/oscrypto.git
    fi
    deactivate
    add-aliases pygpoabuse
    add-history pygpoabuse
    add-test-command "pygpoabuse.py --help"
    add-to-list "pygpoabuse,https://github.com/Hackndo/pyGPOAbuse,A tool for abusing GPO permissions to escalate privileges,$version"
}

function install_bloodhound-import() {
    # CODE-CHECK-WHITELIST=add-aliases,add-version
    colorecho "Installing bloodhound-import"
    pipx install bloodhound-import
    add-history bloodhound-import
    add-test-command "bloodhound-import --help"
    add-to-list "bloodhound-import,https://github.com/fox-it/BloodHound.py,Import data into BloodHound for analyzing active directory trust relationships,$version"
}

function install_bloodhound-quickwin() {
    # CODE-CHECK-WHITELIST=add-version
    colorecho "Installing bloodhound-quickwin"
    git -C /opt/tools/ clone --depth 1 https://github.com/kaluche/bloodhound-quickwin
    cd /opt/tools/bloodhound-quickwin || exit
    python3 -m venv ./venv/
    source ./venv/bin/activate
    pip3 install -r requirements.txt
    deactivate
    add-aliases bloodhound-quickwin
    add-history bloodhound-quickwin
    add-test-command "bloodhound-quickwin --help"
    add-to-list "bloodhound-quickwin,https://github.com/kaluche/bloodhound-quickwin,A tool for BloodHounding on Windows machines without .NET or Powershell installed,$version"
}

function install_ldapsearch-ad() {
    colorecho "Installing ldapsearch-ad"
    git -C /opt/tools/ clone --depth 1 https://github.com/yaap7/ldapsearch-ad
    cd /opt/tools/ldapsearch-ad || exit
    python3 -m venv ./venv/
    source ./venv/bin/activate
    pip3 install -r requirements.txt
    deactivate
    add-aliases ldapsearch-ad
    add-history ldapsearch-ad
    local version
    version=$(ldapsearch-ad.py --version | awk '{print $2}')
    add-test-command "ldapsearch-ad.py --version"
    add-to-list "ldapsearch-ad,https://github.com/yaap7/ldapsearch-ad,LDAP search utility with AD support,$version"
}

function install_petitpotam() {
    # CODE-CHECK-WHITELIST=add-version
    colorecho "Installing PetitPotam"
    git -C /opt/tools/ clone --depth 1 https://github.com/ly4k/PetitPotam
    cd /opt/tools/PetitPotam || exit
    python3 -m venv ./venv
    source ./venv/bin/activate
    pip3 install impacket
    deactivate
    mv /opt/tools/PetitPotam /opt/tools/PetitPotam_alt
    git -C /opt/tools/ clone --depth 1 https://github.com/topotam/PetitPotam
    cd /opt/tools/PetitPotam || exit
    python3 -m venv ./venv
    source ./venv/bin/activate
    pip3 install impacket
    deactivate
    add-aliases petitpotam
    add-history petitpotam
    add-test-command "petitpotam.py --help"
    add-to-list "petitpotam,https://github.com/topotam/PetitPotam,Windows machine account manipulation,$version"
}

function install_dfscoerce() {
    # CODE-CHECK-WHITELIST=add-version
    colorecho "Installing DfsCoerce"
    git -C /opt/tools/ clone --depth 1 https://github.com/Wh04m1001/DFSCoerce
    cd /opt/tools/DFSCoerce || exit
    python3 -m venv ./venv
    source ./venv/bin/activate
    pip3 install impacket
    deactivate
    add-aliases dfscoerce
    add-history dfscoerce
    add-test-command "dfscoerce.py --help"
    add-to-list "dfscoerce,https://github.com/Wh04m1001/dfscoerce,DFS-R target coercion tool,$version"
}

function install_coercer() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing Coercer"
    pipx install git+https://github.com/p0dalirius/Coercer
    add-history coercer
    local version
    version=$(coercer --help | grep v | head -n 1 | awk '{print $11}')
    add-test-command "coercer --help"
    add-to-list "coercer,https://github.com/p0dalirius/coercer,DFS-R target coercion tool,$version"
}

function install_pkinittools() {
    # CODE-CHECK-WHITELIST=add-version
    colorecho "Installing PKINITtools"
    git -C /opt/tools/ clone --depth 1 https://github.com/dirkjanm/PKINITtools
    cd /opt/tools/PKINITtools || exit
    python3 -m venv ./venv
    source ./venv/bin/activate
    pip3 install -r requirements.txt
    # without following fix, tool raises "oscrypto.errors.LibraryNotFoundError: Error detecting the version of libcrypto"
    # see https://github.com/wbond/oscrypto/issues/78 and https://github.com/wbond/oscrypto/issues/75
    local temp_fix_limit="2024-03-20"
    if [[ "$(date +%Y%m%d)" -gt "$(date -d $temp_fix_limit +%Y%m%d)" ]]; then
      criticalecho "Temp fix expired. Exiting."
    else
      pip3 install --force oscrypto@git+https://github.com/wbond/oscrypto.git
    fi
    deactivate
    add-aliases pkinittools
    add-history pkinittools
    add-test-command "gettgtpkinit.py --help"
    add-to-list "pkinittools,https://github.com/dirkjanm/PKINITtools,Pkinit support tools,$version"
}

function install_pywhisker() {
    # CODE-CHECK-WHITELIST=add-version
    colorecho "Installing pyWhisker"
    git -C /opt/tools/ clone --depth 1 https://github.com/ShutdownRepo/pywhisker
    cd /opt/tools/pywhisker || exit
    python3 -m venv ./venv/
    source ./venv/bin/activate
    pip3 install -r requirements.txt
    deactivate
    add-aliases pywhisker
    add-history pywhisker
    add-test-command "pywhisker.py --help"
    add-to-list "pywhisker,https://github.com/ShutdownRepo/pywhisker,PyWhisker is a Python equivalent of the original Whisker made by Elad Shamir and written in C#. This tool allows users to manipulate the msDS-KeyCredentialLink attribute of a target user/computer to obtain full control over that object. It's based on Impacket and on a Python equivalent of Michael Grafnetter's DSInternals called PyDSInternals made by podalirius.,$version"
}

function install_manspider() {
    # CODE-CHECK-WHITELIST=add-version
    colorecho "Installing Manspider"
    git -C /opt/tools clone --depth 1 https://github.com/blacklanternsecurity/MANSPIDER.git
    cd /opt/tools/MANSPIDER || exit
    python3 -m venv ./venv
    source ./venv/bin/activate
    pip3 install .
    deactivate
    touch ./man_spider/lib/init.py
    sed -i "s#from .lib import#from lib import##" man_spider/manspider.py
    add-aliases manspider
    add-history manspider
    add-test-command "manspider.py --help"
    add-to-list "manspider,https://github.com/blacklanternsecurity/MANSPIDER,Manspider will crawl every share on every target system. If provided creds don't work it will fall back to 'guest' then to a null session.,$version"
}

function install_targetedKerberoast() {
    # CODE-CHECK-WHITELIST=add-version
    colorecho "Installing targetedKerberoast"
    git -C /opt/tools/ clone --depth 1 https://github.com/ShutdownRepo/targetedKerberoast
    cd /opt/tools/targetedKerberoast || exit
    python3 -m venv ./venv/
    source ./venv/bin/activate
    pip3 install -r requirements.txt
    deactivate
    add-aliases targetedkerberoast
    add-history targetedkerberoast
    add-test-command "targetedKerberoast.py --help"
    add-to-list "targetedKerberoast,https://github.com/ShutdownRepo/targetedKerberoast,Kerberoasting against specific accounts,$version"
}

function install_pcredz() {
    colorecho "Installing PCredz"
    fapt libpcap-dev
    git -C /opt/tools/ clone --depth 1 https://github.com/lgandx/PCredz
    cd /opt/tools/PCredz || exit
    python3 -m venv ./venv
    source ./venv/bin/activate
    pip3 install Cython python-libpcap
    deactivate
    add-aliases pcredz
    add-history pcredz
    local version
    version=$(PCredz --help | grep Author | awk '{print $2}')
    add-test-command "PCredz --help"
    add-to-list "pcredz,https://github.com/lgandx/PCredz,PowerShell credential dumper,$version"
}

function install_pywsus() {
    # CODE-CHECK-WHITELIST=add-version
    colorecho "Installing pywsus"
    fapt libxml2-dev libxslt-dev
    git -C /opt/tools/ clone --depth 1 https://github.com/GoSecure/pywsus
    cd /opt/tools/pywsus || exit
    python3 -m venv ./venv/
    # https://github.com/GoSecure/pywsus/pull/12
    echo -e "beautifulsoup4==4.9.1\nlxml==4.9.1\nsoupsieve==2.0.1" > requirements.txt
    source ./venv/bin/activate
    pip3 install -r requirements.txt
    deactivate
    add-aliases pywsus
    add-history pywsus
    add-test-command "pywsus.py --help"
    add-to-list "pywsus,https://github.com/GoSecure/pywsus,Python implementation of a WSUS client,$version"
}

function install_donpapi() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing DonPAPI"
    fapt swig
    pipx install git+https://github.com/login-securite/DonPAPI
    add-history donpapi
    local version
    version=$(DonPAPI --help | grep version | awk '{print $3}')
    add-test-command "DonPAPI --help"
    add-to-list "donpapi,https://github.com/login-securite/DonPAPI,Dumping revelant information on compromised targets without AV detection,$version"
}

function install_webclientservicescanner() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing webclientservicescanner"
    pipx install git+https://github.com/Hackndo/WebclientServiceScanner
    add-history webclientservicescanner
    local version
    version=$(webclientservicescanner --help | head -n 1 | awk '{print $4}')
    add-test-command "webclientservicescanner --help"
    add-to-list "webclientservicescanner,https://github.com/Hackndo/webclientservicescanner,Scans for web service endpoints,$version"
}

function install_certipy() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing Certipy"
    pipx install git+https://github.com/ly4k/Certipy
    add-history certipy
    local version
    version=$(certipy --version |& head -n 1 | awk '{print $2}')
    add-test-command "certipy --version"
    add-to-list "certipy,https://github.com/ly4k/Certipy,Python tool to create and sign certificates,$version"
}

function install_shadowcoerce() {
    # CODE-CHECK-WHITELIST=add-version
    colorecho "Installing ShadowCoerce PoC"
    git -C /opt/tools/ clone --depth 1 https://github.com/ShutdownRepo/ShadowCoerce
    cd /opt/tools/ShadowCoerce || exit
    python3 -m venv ./venv
    source ./venv/bin/activate
    pip3 install impacket
    deactivate
    add-aliases shadowcoerce
    add-history shadowcoerce
    add-test-command "shadowcoerce.py --help"
    add-to-list "shadowcoerce,https://github.com/ShutdownRepo/shadowcoerce,Utility for bypassing the Windows Defender antivirus by hiding a process within a legitimate process.,$version"
}

function install_gmsadumper() {
    # CODE-CHECK-WHITELIST=add-version
    colorecho "Installing gMSADumper"
    git -C /opt/tools/ clone --depth 1 https://github.com/micahvandeusen/gMSADumper
    cd /opt/tools/gMSADumper || exit
    python3 -m venv ./venv
    source ./venv/bin/activate
    pip3 install -r requirements.txt
    # https://github.com/micahvandeusen/gMSADumper/issues/12
    local temp_fix_limit="2024-03-20"
    if [[ "$(date +%Y%m%d)" -gt "$(date -d $temp_fix_limit +%Y%m%d)" ]]; then
      criticalecho "Temp fix expired. Exiting."
    else
      pip3 install pycryptodome
    fi
    deactivate
    add-aliases gmsadumper
    add-history gmsadumper
    add-test-command "gMSADumper.py --help"
    add-to-list "gmsadumper,https://github.com/micahvandeusen/gMSADumper,A tool for extracting credentials and other information from a Microsoft Active Directory domain.,$version"
}

function install_pylaps() {
    colorecho "Installing pyLAPS"
    git -C /opt/tools/ clone --depth 1 https://github.com/p0dalirius/pyLAPS
    cd /opt/tools/pyLAPS || exit
    python3 -m venv ./venv
    source ./venv/bin/activate
    pip3 install impacket
    deactivate
    add-aliases pylaps
    add-history pylaps
    local version
    version=$(pyLAPS.py --help | grep v | head -n 1 | awk '{print $6}')
    add-test-command "pyLAPS.py --help"
    add-to-list "pylaps,https://github.com/p0dalirius/pylaps,Utility for enumerating and querying LDAP servers.,$version"
}

function install_finduncommonshares() {
    colorecho "Installing FindUncommonShares"
    git -C /opt/tools/ clone --depth 1 https://github.com/p0dalirius/FindUncommonShares
    cd /opt/tools/FindUncommonShares/ || exit
    python3 -m venv ./venv/
    source ./venv/bin/activate
    pip3 install -r requirements.txt
    deactivate
    add-aliases finduncommonshares
    add-history finduncommonshares
    local version
    version=$(FindUncommonShares.py --help | head -n 1 | awk '{print $2}')
    add-test-command "FindUncommonShares.py --help"
    add-to-list "finduncommonshares,https://github.com/p0dalirius/FindUncommonShares,Script that can help identify shares that are not commonly found on a Windows system.,$version"
}

function install_ldaprelayscan() {
    # CODE-CHECK-WHITELIST=add-version
    colorecho "Installing LdapRelayScan"
    git -C /opt/tools/ clone --depth 1 https://github.com/zyn3rgy/LdapRelayScan
    cd /opt/tools/LdapRelayScan || exit
    python3 -m venv ./venv/
    source ./venv/bin/activate
    pip3 install -r requirements.txt
    # without following fix, tool raises "oscrypto.errors.LibraryNotFoundError: Error detecting the version of libcrypto"
    # see https://github.com/wbond/oscrypto/issues/78 and https://github.com/wbond/oscrypto/issues/75
    local temp_fix_limit="2024-03-20"
    if [[ "$(date +%Y%m%d)" -gt "$(date -d $temp_fix_limit +%Y%m%d)" ]]; then
      criticalecho "Temp fix expired. Exiting."
    else
      pip3 install --force oscrypto@git+https://github.com/wbond/oscrypto.git
    fi
    deactivate
    add-aliases ldaprelayscan
    add-history ldaprelayscan
    add-test-command "LdapRelayScan.py --help"
    add-to-list "ldaprelayscan,https://github.com/zyn3rgy/LdapRelayScan,Check Domain Controllers for LDAP server protections regarding the relay of NTLM authentication.,$version"
}

function install_goldencopy() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing GoldenCopy"
    git -C /opt/tools/ clone --depth 1 https://github.com/Dramelac/GoldenCopy
    cd /opt/tools/GoldenCopy || exit
    python3 -m venv ./venv/
    source ./venv/bin/activate
    pip3 install .
    deactivate
    ln -v -s /opt/tools/GoldenCopy/venv/bin/goldencopy /opt/tools/bin/goldencopy
    add-history goldencopy
    local version
    version=$(goldencopy --help | grep GoldenCopy | awk '{print $2}')
    add-test-command "goldencopy --help"
    add-to-list "goldencopy,https://github.com/Dramelac/GoldenCopy,Copy the properties and groups of a user from neo4j (bloodhound) to create an identical golden ticket,$version"
}

function install_crackhound() {
    # CODE-CHECK-WHITELIST=add-version
    colorecho "Installing CrackHound"
    git -C /opt/tools/ clone --depth 1 https://github.com/trustedsec/CrackHound
    cd /opt/tools/CrackHound || exit
    python3 -m venv ./venv/
    source ./venv/bin/activate
    pip3 install -r requirements.txt
    deactivate
    add-aliases crackhound
    add-history crackhound
    add-test-command "crackhound.py --help"
    add-to-list "crackhound,https://github.com/trustedsec/crackhound,A fast WPA/WPA2/WPA3 WiFi Handshake capture / password recovery and analysis tool,$version"
}

function install_kerbrute() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing Kerbrute"
    go install -v github.com/ropnop/kerbrute@latest
    asdf reshim golang
    add-history kerbrute
    local version
    version=$(kerbrute --help | grep Version | awk '{print $2}')
    add-test-command "kerbrute --help"
    add-to-list "kerbrute,https://github.com/ropnop/kerbrute,A tool to perform Kerberos pre-auth bruteforcing,$version"
}

function install_ldeep() {
    # CODE-CHECK-WHITELIST=add-aliases,add-version
    colorecho "Installing ldeep"
    fapt libkrb5-dev krb5-config
    pipx install ldeep
    add-history ldeep
    add-test-command "ldeep --help"
    add-to-list "ldeep,https://github.com/franc-pentest/ldeep,ldeep is a tool to discover hidden paths on Web servers.,$version"
}

function install_rusthound() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing RustHound"
    fapt gcc clang libclang-dev libgssapi-krb5-2 libkrb5-dev libsasl2-modules-gssapi-mit musl-tools gcc-mingw-w64-x86-64
    git -C /opt/tools/ clone --depth 1 https://github.com/OPENCYBER-FR/RustHound
    cd /opt/tools/RustHound || exit
    # Sourcing rustup shell setup, so that rust binaries are found when installing cme
    source "$HOME/.cargo/env"
    cargo build --release
    # Clean dependencies used to build the binary
    rm -rf target/release/{deps,build}
    ln -s /opt/tools/RustHound/target/release/rusthound /opt/tools/bin/rusthound
    add-history rusthound
    local version
    version=$(rusthound --version | grep rusthound | awk '{print $2}')
    add-test-command "rusthound --help"
    add-to-list "rusthound,https://github.com/OPENCYBER-FR/RustHound,BloodHound ingestor in Rust.,$version"
}

function install_rusthound-ce() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing RustHound for BloodHound-CE"
    fapt gcc clang libclang-dev libgssapi-krb5-2 libkrb5-dev libsasl2-modules-gssapi-mit musl-tools gcc-mingw-w64-x86-64
    git -C /opt/tools/ clone --depth 1 --branch v2 https://github.com/OPENCYBER-FR/RustHound RustHound-CE
    cd /opt/tools/RustHound-CE || exit
    # Sourcing rustup shell setup, so that rust binaries are found when installing cme
    source "$HOME/.cargo/env"
    cargo build --release
    # Clean dependencies used to build the binary
    rm -rf target/release/{deps,build}
    ln -v -s /opt/tools/RustHound-CE/target/release/rusthound /opt/tools/bin/rusthound-ce
    add-history rusthound-ce
    local version
    version=$(rusthound-ce --version | grep rusthound | awk '{print $2}')
    add-test-command "rusthound-ce --help"
    add-to-list "rusthound (v2),https://github.com/OPENCYBER-FR/RustHound,BloodHound-CE ingestor in Rust.,$version"
}

function install_certsync() {
    # CODE-CHECK-WHITELIST=add-aliases,add-version
    colorecho "Installing certsync"
    pipx install git+https://github.com/zblurx/certsync
    add-history certsync
    add-test-command "certsync --help"
    add-to-list "certsync,https://github.com/zblurx/certsync,certsync is a tool that helps you synchronize certificates between two directories.,$version"
}

function install_keepwn() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing KeePwn"
    pipx install git+https://github.com/Orange-Cyberdefense/KeePwn
    add-history keepwn
    local version
    version=$(KeePwn --help | head -n 1 | awk '{print $2}')
    add-test-command "KeePwn --help"
    add-to-list "KeePwn,https://github.com/Orange-Cyberdefense/KeePwn,KeePwn is a tool that extracts passwords from KeePass 1.x and 2.x databases.,$version"
}

function install_pre2k() {
    # CODE-CHECK-WHITELIST=add-aliases,add-version
    colorecho "Installing pre2k"
    pipx install git+https://github.com/garrettfoster13/pre2k
    add-history pre2k
    add-test-command "pre2k --help"
    add-to-list "pre2k,https://github.com/garrettfoster13/pre2k,pre2k is a tool to check if a Windows domain has any pre-2000 Windows 2000 logon names still in use.,$version"
}

function install_msprobe() {
    # CODE-CHECK-WHITELIST=add-aliases,add-version
    colorecho "Installing msprobe"
    pipx install git+https://github.com/puzzlepeaches/msprobe
    add-history msprobe
    add-test-command "msprobe --help"
    add-to-list "msprobe,https://github.com/puzzlepeaches/msprobe,msprobe is a tool to identify Microsoft Windows hosts and servers that are running certain services.,$version"
}

function install_masky() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing masky"
    pipx install git+https://github.com/Z4kSec/Masky
    add-history masky
    local version
    version=$(masky --help | grep v | head -n 1 | awk '{print $1}')
    add-test-command "masky --help"
    add-to-list "masky,https://github.com/Z4kSec/masky,masky is a tool to mask sensitive data / such as credit card numbers / in logs and other files.,$version"
}

function install_roastinthemiddle() {
    # CODE-CHECK-WHITELIST=add-aliases,add-version
    colorecho "Installing roastinthemiddle"
    pipx install git+https://github.com/Tw1sm/RITM
    add-history roastinthemiddle
    add-test-command "roastinthemiddle --help"
    add-to-list "roastinthemiddle,https://github.com/Tw1sm/RITM,RoastInTheMiddle is a tool to intercept and relay NTLM authentication requests.,$version"
}

function install_PassTheCert() {
    # CODE-CHECK-WHITELIST=add-version
    colorecho "Installing PassTheCert"
    git -C /opt/tools/ clone --depth 1 https://github.com/AlmondOffSec/PassTheCert
    cd /opt/tools/PassTheCert/Python/ || exit
    python3 -m venv ./venv
    source ./venv/bin/activate
    pip3 install impacket
    deactivate
    add-aliases PassTheCert
    add-history PassTheCert
    add-test-command "passthecert.py --help"
    add-to-list "PassTheCert,https://github.com/AlmondOffSec/PassTheCert,PassTheCert is a tool to extract Active Directory user password hashes from a domain controller's local certificate store.,$version"
}

function install_bqm() {
    # CODE-CHECK-WHITELIST=add-version
    colorecho "Installing BQM"
    rvm use 3.2.2@bqm --create
    gem install bqm --no-wrapper
    rvm use 3.2.2@default
    add-aliases bqm
    add-history bqm
    add-test-command "bqm --help"
    add-to-list "bqm,https://github.com/Acceis/bqm,Tool to deduplicate custom BloudHound queries from different datasets and merge them in one file.,$version"
}

function install_neo4j() {
    colorecho "Installing neo4j"
    wget -O /tmp/neo4j.gpg.armored https://debian.neo4j.com/neotechnology.gpg.key
    # doing wget, gpg, chmod, to avoid the warning of apt-key being deprecated
    gpg --dearmor --output /etc/apt/trusted.gpg.d/neo4j.gpg /tmp/neo4j.gpg.armored
    chmod 644 /etc/apt/trusted.gpg.d/neo4j.gpg
    # TODO: temporary fix => rollback to 4.4 stable until perf issue is fix on neo4j 5.x
    #echo 'deb https://debian.neo4j.com stable latest' | tee /etc/apt/sources.list.d/neo4j.list
    echo 'deb https://debian.neo4j.com stable 4.4' | tee /etc/apt/sources.list.d/neo4j.list
    apt-get update
    fapt gnupg libgtk2.0-bin libcanberra-gtk-module libx11-xcb1 libva-glx2 libgl1-mesa-glx libgl1-mesa-dri libgconf-2-4 libasound2 libxss1 neo4j
    # TODO: when temporary fix is not needed anymore add --> neo4j-admin dbms set-initial-password exegol4thewin
    # TODO: when temporary fix is not needed anymore remove following line
    neo4j-admin set-initial-password exegol4thewin
    mkdir -p /usr/share/neo4j/logs/
    touch /usr/share/neo4j/logs/neo4j.log
    add-aliases neo4j
    add-history neo4j
    local version
    version=$(neo4j version | awk '{print $2}')
    add-test-command "neo4j version"
    add-to-list "neo4j,https://github.com/neo4j/neo4j,Database.,$version"
}

function install_noPac() {
    # CODE-CHECK-WHITELIST=add-version
    colorecho "Installing noPac"
    git -C /opt/tools/ clone --depth 1 https://github.com/Ridter/noPac
    cd /opt/tools/noPac || exit
    python3 -m venv ./venv
    source ./venv/bin/activate
    pip3 install -r requirements.txt
    deactivate
    add-aliases noPac
    add-history noPac
    add-test-command "noPac.py --help"
    add-to-list "noPac,https://github.com/Ridter/noPac,Exploiting CVE-2021-42278 and CVE-2021-42287 to impersonate DA from standard domain user.,$version"
}

function install_roadtools() {
    # CODE-CHECK-WHITELIST=add-aliases,add-history,add-version
    colorecho "Installing roadtools"
    pipx install roadrecon
    add-test-command "roadrecon --help"
    add-test-command "roadrecon-gui --help"
    add-to-list "ROADtools,https://github.com/dirkjanm/ROADtools,ROADtools is a framework to interact with Azure AD. It consists of a library (roadlib) with common components / the ROADrecon Azure AD exploration tool and the ROADtools Token eXchange (roadtx) tool.,$version"
}

function install_teamsphisher() {
    colorecho "Installing TeamsPhisher"
    git -C /opt/tools clone --depth 1 https://github.com/Octoberfest7/TeamsPhisher
    cd /opt/tools/TeamsPhisher || exit
    python3 -m venv ./venv
    source ./venv/bin/activate
    pip3 install msal colorama requests
    deactivate
    add-aliases teamsphisher
    add-history teamsphisher
    local version
    version=$(teamsphisher.py --help | grep developed | awk '{print $1}')
    add-test-command "teamsphisher.py --help"
    add-to-list "TeamsPhisher,https://github.com/Octoberfest7/TeamsPhisher,TeamsPhisher is a Python3 program that facilitates the delivery of phishing messages and attachments to Microsoft Teams users whose organizations allow external communications.,$version"
}

function install_GPOddity() {
    # CODE-CHECK-WHITELIST=add-aliases,add-version
    colorecho "Installing GPOddity"
    pipx install git+https://github.com/synacktiv/GPOddity
    add-history GPOddity
    add-test-command "gpoddity --help"
    add-to-list "GPOddity,https://github.com/synacktiv/GPOddity,Aiming at automating GPO attack vectors through NTLM relaying (and more),$version"
}

function install_netexec() {
    colorecho "Installing netexec"
    git -C /opt/tools/ clone --depth 1 https://github.com/Pennyw0rth/NetExec
    pipx install /opt/tools/NetExec/
    mkdir -p ~/.nxc
    [[ -f ~/.nxc/nxc.conf ]] && mv ~/.nxc/nxc.conf ~/.nxc/nxc.conf.bak
    cp -v /root/sources/assets/netexec/nxc.conf ~/.nxc/nxc.conf
    cp -v /root/sources/assets/grc/conf.cme /usr/share/grc/conf.cme
    add-aliases netexec
    add-history netexec
    local version
    version=$(netexec --version| grep nxc | awk '{print $1}')
    add-test-command "netexec --help"
    add-to-list "netexec,https://github.com/Pennyw0rth/NetExec,Network scanner (Crackmapexec updated).,$version"
}

function install_extractbitlockerkeys() {
    colorecho "Installing ExtractBitlockerKeys"
    git -C /opt/tools/ clone --depth 1 https://github.com/p0dalirius/ExtractBitlockerKeys
    cd /opt/tools/ExtractBitlockerKeys || exit
    python3 -m venv ./venv
    source ./venv/bin/activate
    pip3 install -r requirements.txt
    deactivate
    add-aliases extractbitlockerkeys
    add-history extractbitlockerkeys
    local version
    version=$(ExtractBitlockerKeys.py --help | head -n 1 | awk '{print $2}')
    add-test-command "ExtractBitlockerKeys.py --help"
    add-to-list "ExtractBitlockerKeys,https://github.com/p0dalirius/ExtractBitlockerKeys,A system administration or post-exploitation script to automatically extract the bitlocker recovery keys from a domain.,$version"
}

function install_LDAPWordlistHarvester() {
    colorecho "Installing LDAPWordlistHarvester"
    git -C /opt/tools/ clone --depth 1 https://github.com/p0dalirius/LDAPWordlistHarvester
    cd /opt/tools/LDAPWordlistHarvester || exit
    python3 -m venv ./venv
    source ./venv/bin/activate
    pip3 install -r requirements.txt
    deactivate
    add-aliases LDAPWordlistHarvester
    add-history LDAPWordlistHarvester
    local version
    version=$(LDAPWordlistHarvester.py --help | head -n 1 | awk '{print $2}')
    add-test-command "pywerview --help"
    add-test-command "LDAPWordlistHarvester.py --help"
    add-to-list "LDAPWordlistHarvester,https://github.com/p0dalirius/LDAPWordlistHarvester,Generate a wordlist from the information present in LDAP in order to crack passwords of domain accounts,$version"
}

function install_pywerview() {
    # CODE-CHECK-WHITELIST=add-aliases,add-version
    colorecho "Installing pywerview"
    pipx install git+https://github.com/the-useless-one/pywerview
    add-history pywerview
    add-test-command "pywerview --help"
    add-to-list "pywerview,https://github.com/the-useless-one/pywerview,A (partial) Python rewriting of PowerSploit's PowerView.,$version"
}

function install_freeipscanner() {
    # CODE-CHECK-WHITELIST=add-aliases,add-version
    colorecho "Installing freeipscanner"
    fapt arping
    wget -O /opt/tools/bin/freeipscanner.sh https://raw.githubusercontent.com/scrt/freeipscanner/master/freeipscanner.sh
    chmod +x /opt/tools/bin/freeipscanner.sh
    add-history freeipscanner
    add-test-command "freeipscanner.sh --help"
    add-to-list "freeipscanner,https://github.com/scrt/freeipscanner,A simple bash script to enumerate stale ADIDNS entries,$version"
}

function install_scrtdnsdump() {
    # CODE-CHECK-WHITELIST=add-aliases,add-version
    colorecho "Installing scrtdnsdump"
    pipx install git+https://github.com/scrt/scrtdnsdump
    add-history scrtdnsdump
    add-test-command "scrtdnsdump --help"
    add-to-list "scrtdnsdump,https://github.com/scrt/scrtdnsdump,Enumeration and exporting of all DNS records in the zone for recon purposes of internal networks,$version"
}

function install_ntlm_theft() {
    colorecho "Installing ntlm_theft"
    git -C /opt/tools/ clone --depth 1 https://github.com/Greenwolf/ntlm_theft
    cd /opt/tools/ntlm_theft || exit
    python3 -m venv ./venv
    source ./venv/bin/activate
    pip3 install xlsxwriter
    deactivate
    add-aliases ntlm_theft
    add-history ntlm_theft
    local version
    version=$(ntlm_theft.py --version | awk '{print $2}')
    add-test-command "ntlm_theft.py --help"
    add-to-list "ntlm_theft,https://github.com/Greenwolf/ntlm_theft,A tool for generating multiple types of NTLMv2 hash theft files,$version"
}

function install_abuseACL() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing abuseACL"
    pipx install git+https://github.com/AetherBlack/abuseACL
    add-history abuseACL
    local version
    version=$(abuseACL --help | grep by | awk '{print $4}' | tr -d '()')
    add-test-command "abuseACL --help"
    add-to-list "abuseACL,https://github.com/AetherBlack/abuseACL,A python script to automatically list vulnerable Windows ACEs/ACLs.,$version"
}

# Package dedicated to internal Active Directory tools
function package_ad() {
    set_env
    local start_time
    local end_time
    start_time=$(date +%s)
    install_ad_apt_tools
    install_pretender
    install_responder               # LLMNR, NBT-NS and MDNS poisoner
    install_ldapdomaindump
    install_crackmapexec            # Network scanner
    install_sprayhound              # Password spraying tool
    install_smartbrute              # Password spraying tool
    install_bloodhound-py           # ingestor for legacy BloodHound
    install_bloodhound-ce-py           # ingestor for legacy BloodHound
    install_bloodhound
    install_cypheroth               # Bloodhound dependency
    # install_mitm6_sources         # Install mitm6 from sources
    install_mitm6_pip               # DNS server misconfiguration exploiter
    install_aclpwn                  # ACL exploiter
    install_impacket                # Network protocols scripts
    install_pykek                   # AD vulnerability exploiter
    install_lsassy                  # Credentials extracter
    install_privexchange            # Exchange exploiter
    install_ruler                   # Exchange exploiter
    install_darkarmour              # Windows AV evasion
    install_amber                   # AV evasion
    install_powershell              # Windows Powershell for Linux
    install_krbrelayx               # Kerberos unconstrained delegation abuse toolkit
    install_evilwinrm               # WinRM shell
    install_pypykatz                # Mimikatz implementation in pure Python
    install_krbjack                 # KrbJack
    install_enyx                    # Hosts discovery
    install_enum4linux-ng           # Hosts enumeration
    install_zerologon               # Exploit for zerologon cve-2020-1472
    install_libmspack               # Library for some loosely related Microsoft compression format
    install_windapsearch-go         # Active Directory Domain enumeration through LDAP queries
    install_oaburl                  # Send request to the MS Exchange Autodiscover service
    install_lnkup
    install_polenum
    install_smbmap                  # Allows users to enumerate samba share drives across an entire domain
    install_pth-tools               # Pass the hash attack
    install_smtp-user-enum          # SMTP user enumeration via VRFY, EXPN and RCPT
    install_gpp-decrypt             # Decrypt a given GPP encrypted string
    install_ntlmv1-multi            # NTLMv1 multi tools: modifies NTLMv1/NTLMv1-ESS/MSCHAPv2
    install_hashonymize             # Anonymize NTDS, ASREProast, Kerberoast hashes for remote cracking
    install_gosecretsdump           # secretsdump in Go for heavy files
    install_adidnsdump              # enumerate DNS records in Domain or Forest DNS zones
    install_pygpoabuse
    install_bloodhound-import
    install_bloodhound-quickwin     # Python script to find quickwins from BH data in a neo4j db
    install_ldapsearch-ad           # Python script to find quickwins from basic ldap enum
    install_petitpotam              # Python script to coerce auth through MS-EFSR abuse
    install_dfscoerce               # Python script to coerce auth through NetrDfsRemoveStdRoot and NetrDfsAddStdRoot abuse
    install_coercer                 # Python script to coerce auth through multiple methods
    install_pkinittools             # Python scripts to use kerberos PKINIT to obtain TGT
    install_pywhisker               # Python script to manipulate msDS-KeyCredentialLink
    install_manspider               # Snaffler-like in Python
    install_targetedKerberoast
    install_pcredz
    install_pywsus
    install_donpapi
    install_webclientservicescanner
    install_certipy
    install_shadowcoerce
    install_gmsadumper
    install_pylaps
    install_finduncommonshares
    install_ldaprelayscan
    install_goldencopy
    install_crackhound
    install_kerbrute                # Tool to enumerate and bruteforce AD accounts through kerberos pre-authentication
    install_ldeep
    install_rusthound
    install_rusthound-ce
    install_certsync
    install_keepwn
    install_pre2k
    install_msprobe
    install_masky
    install_roastinthemiddle
    install_PassTheCert
    install_bqm                    # Deduplicate custom BloudHound queries from different datasets and merge them in one customqueries.json file.
    install_neo4j                  # Bloodhound dependency
    install_noPac
    install_roadtools              # Rogue Office 365 and Azure (active) Directory tools
    install_teamsphisher           # TeamsPhisher is a Python3 program that facilitates the delivery of phishing messages and attachments to Microsoft Teams users whose organizations allow external communications.
    install_GPOddity
    install_netexec                # Crackmapexec repo
    install_extractbitlockerkeys   # Extract Bitlocker recovery keys from all the computers of the domain
    install_LDAPWordlistHarvester
    install_pywerview
    install_freeipscanner
    # install_scrtdnsdump          # This tool is a fork of adidnsdump (https://github.com/dirkjanm/adidnsdump). We are currently waiting to see if a PR will be made.
    install_bloodhound-ce          # AD (Community Edition) security tool for reconnaissance and attacking AD environments
    install_ntlm_theft
    install_abuseACL
    end_time=$(date +%s)
    local elapsed_time=$((end_time - start_time))
    colorecho "Package ad completed in $elapsed_time seconds."
}
