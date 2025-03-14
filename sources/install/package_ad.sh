#!/bin/bash
# Author: The Exegol Project

source common.sh

function install_ad_apt_tools() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing AD apt tools"
    fapt samdump2 smbclient onesixtyone nbtscan ldap-utils krb5-user

    add-history samdump2
    add-history smbclient
    add-history onesixtyone
    add-history nbtscan
    add-history ldapsearch
    add-history kerberos

    add-test-command "samdump2 -h|& grep 'enable debugging'"        # Dumps Windows 2k/NT/XP/Vista password hashes
    add-test-command "smbclient --help"                             # Small dynamic library that allows iOS apps to access SMB/CIFS file servers
    add-test-command "onesixtyone 127.0.0.1 public"                 # SNMP scanning
    add-test-command "nbtscan 127.0.0.1"                            # NetBIOS scanning tool
    add-test-command "ldapsearch --help|& grep 'Search options'"    # Perform queries on a LDAP server
    add-test-command "klist -V"

    add-to-list "samdump2,https://github.com/azan121468/SAMdump2,A tool to dump Windows NT/2k/XP/Vista password hashes from SAM files"
    add-to-list "smbclient,https://github.com/samba-team/samba,SMBclient is a command-line utility that allows you to access Windows shared resources"
    add-to-list "onesixtyone,https://github.com/trailofbits/onesixtyone,onesixtyone is an SNMP scanner which utilizes a sweep technique to achieve very high performance."
    add-to-list "nbtscan,https://github.com/charlesroelli/nbtscan,NBTscan is a program for scanning IP networks for NetBIOS name information."
    add-to-list "ldapsearch,https://wiki.debian.org/LDAP/LDAPUtils,Search for and display entries (ldap)"
}

function install_asrepcatcher() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing ASRepCatcher"
    pipx install --system-site-packages git+https://github.com/Yaxxine7/ASRepCatcher
    add-history asrepcatcher
    add-test-command "ASRepCatcher --help"
    add-to-list "asrepcatcher,https://github.com/Yaxxine7/ASRepCatcher,Make your VLAN ASREProastable."
}

function install_pretender() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing Pretender"
    go install -v github.com/RedTeamPentesting/pretender@latest
    asdf reshim golang
    add-history pretender
    add-test-command "pretender --help |& grep pretender"
    add-to-list "pretender,https://github.com/RedTeamPentesting/pretender,an mitm tool for helping with relay attacks."
}

function install_responder() {
    colorecho "Installing Responder"
    git -C /opt/tools/ clone --depth 1 https://github.com/lgandx/Responder
    cd /opt/tools/Responder || exit
    fapt gcc-mingw-w64-x86-64
    python3 -m venv --system-site-packages ./venv
    source ./venv/bin/activate
    pip3 install -r requirements.txt
    # following requirements needed by MultiRelay.py
    pip3 install pycryptodomex six
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
    add-test-command "Responder.py --version"
    add-test-command "RunFinger.py --help"
    add-test-command "MultiRelay.py --help"
    add-to-list "responder,https://github.com/lgandx/Responder,a LLMNR / NBT-NS and MDNS poisoner."
}

function install_sprayhound() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing sprayhound"
    pipx install --system-site-packages git+https://github.com/Hackndo/sprayhound
    add-history sprayhound
    add-test-command "sprayhound --help"
    add-to-list "sprayhound,https://github.com/Hackndo/Sprayhound,Active Directory password audit tool."
}

function install_smartbrute() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing smartbrute"
    pipx install --system-site-packages git+https://github.com/ShutdownRepo/smartbrute
    add-history smartbrute
    add-test-command "smartbrute --help"
    add-to-list "smartbrute,https://github.com/ShutdownRepo/SmartBrute,The smart password spraying and bruteforcing tool for Active Directory Domain Services."
}

function install_ldapdomaindump() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing ldapdomaindump"
    # Remove --system-site-packages because the ldapdomaindump package conflicts with the base package
    pipx install git+https://github.com/dirkjanm/ldapdomaindump
    add-history ldapdomaindump
    add-test-command "ldapdomaindump --help"
    add-to-list "ldapdomaindump,https://github.com/dirkjanm/ldapdomaindump,A tool for dumping domain data from an LDAP service"
}

function install_bloodhound-py() {
    colorecho "Installing and Python ingestor for BloodHound"
    pipx install --system-site-packages git+https://github.com/fox-it/BloodHound.py
    add-aliases bloodhound-py
    add-history bloodhound-py
    add-test-command "bloodhound.py --help"
    add-to-list "bloodhound.py,https://github.com/fox-it/BloodHound.py,BloodHound ingestor in Python."
}


function install_bloodhound-ce-py() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing and Python ingestor for BloodHound-CE"
    git -C /opt/tools/ clone --branch bloodhound-ce --depth 1 https://github.com/dirkjanm/BloodHound.py BloodHound-CE.py
    cd /opt/tools/BloodHound-CE.py || exit
    python3 -m venv --system-site-packages ./venv
    source ./venv/bin/activate
    pip3 install .
    deactivate
    ln -v -s /opt/tools/BloodHound-CE.py/venv/bin/bloodhound-ce-python /opt/tools/bin/bloodhound-ce.py
    add-history bloodhound-ce-py
    add-test-command "bloodhound-ce.py --help"
    add-to-list "bloodhound-ce.py,https://github.com/fox-it/BloodHound.py,BloodHound-CE ingestor in Python."
}

function install_bloodhound() {
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
    add-to-list "bloodhound,https://github.com/BloodHoundAD/BloodHound,Active Directory security tool for reconnaissance and attacking AD environments."
}

function install_bloodhound-ce() {
    # CODE-CHECK-WHITELIST=add-aliases,add-history
    colorecho "Installing BloodHound-CE"

    # Ingestors: bloodhound-ce requires the ingestors to be in a specific directory and checks that when starting, they need to be downloaded here
    local bloodhoundce_path="/opt/tools/BloodHound-CE/"
    local sharphound_path="${bloodhoundce_path}/collectors/sharphound/"
    local azurehound_path="${bloodhoundce_path}/collectors/azurehound/"
    mkdir -p "${bloodhoundce_path}"
    mkdir -p "${sharphound_path}"
    mkdir -p "${azurehound_path}"

    local curl_tempfile
    curl_tempfile=$(mktemp)
    [[ -f "${curl_tempfile}" ]] || exit

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
    local latestRelease
    # Had to output into a tempfile as the Exegol's wrapper for curl breaks stdout
    curl --location --silent "https://api.github.com/repos/SpecterOps/BloodHound/releases" -o "${curl_tempfile}"
    latestRelease=$(jq --raw-output 'first(.[] | select(.tag_name | contains("-rc") | not) | .tag_name)' "${curl_tempfile}")
    git -C "${bloodhoundce_path}" clone --depth 1 --branch "${latestRelease}" "https://github.com/SpecterOps/BloodHound.git" src
    cd "${bloodhoundce_path}/src/" || exit
    catch_and_retry VERSION=v999.999.999 CHECKOUT_HASH="" python3 ./packages/python/beagle/main.py build --verbose --ci

    ## SharpHound
    local sharphound_url
    local sharphound_name
    local sharphound_name_lowercase
    curl --location --silent "https://api.github.com/repos/BloodHoundAD/SharpHound/releases/latest" -o "${curl_tempfile}"
    sharphound_url=$(jq --raw-output '.assets[].browser_download_url | select(contains("debug") | not)' "${curl_tempfile}")
    sharphound_name=$(jq --raw-output '.assets[].name | select(contains("debug") | not)' "${curl_tempfile}")
    # lowercase fix: https://github.com/ThePorgs/Exegol-images/pull/405
    sharphound_name_lowercase=$(jq --raw-output '.assets[].name | ascii_downcase | select(contains("debug") | not)' "${curl_tempfile}")
    wget --directory-prefix "${sharphound_path}" "${sharphound_url}"
    [[ -f "${sharphound_path}/${sharphound_name}" ]] || exit
    mv "${sharphound_path}/${sharphound_name}" "${sharphound_path}/${sharphound_name_lowercase}"
    # Unlike Azurehound, upstream does not provide a sha256 file to check the integrity
    sha256sum "${sharphound_path}/${sharphound_name_lowercase}" > "${sharphound_path}/${sharphound_name_lowercase}.sha256"

    ## AzureHound
    local azurehound_url_amd64
    local azurehound_url_amd64_sha256
    local azurehound_url_arm64
    local azurehound_url_arm64_sha256
    local azurehound_version
    curl --location --silent "https://api.github.com/repos/BloodHoundAD/AzureHound/releases/latest" -o "${curl_tempfile}"
    azurehound_version=$(jq --raw-output '.tag_name' "${curl_tempfile}")
    azurehound_url_amd64=$(jq --raw-output '.assets[].browser_download_url | select (endswith("azurehound-linux-amd64.zip"))' "${curl_tempfile}")
    azurehound_url_amd64_sha256=$(jq --raw-output '.assets[].browser_download_url | select (endswith("azurehound-linux-amd64.zip.sha256"))' "${curl_tempfile}")
    azurehound_url_arm64=$(jq --raw-output '.assets[].browser_download_url | select (endswith("azurehound-linux-arm64.zip"))' "${curl_tempfile}")
    azurehound_url_arm64_sha256=$(jq --raw-output '.assets[].browser_download_url | select (endswith("azurehound-linux-arm64.zip.sha256"))' "${curl_tempfile}")
    rm "${curl_tempfile}"
    wget --directory-prefix "${azurehound_path}" "${azurehound_url_amd64}"
    [[ -f "${azurehound_path}/azurehound-linux-amd64.zip" ]] || exit
    wget --directory-prefix "${azurehound_path}" "${azurehound_url_amd64_sha256}"
    [[ -f "${azurehound_path}/azurehound-linux-amd64.zip.sha256" ]] || exit
    wget --directory-prefix "${azurehound_path}" "${azurehound_url_arm64}"
    [[ -f "${azurehound_path}/azurehound-linux-arm64.zip" ]] || exit
    wget --directory-prefix "${azurehound_path}" "${azurehound_url_arm64_sha256}"
    [[ -f "${azurehound_path}/azurehound-linux-arm64.zip.sha256" ]] || exit
    (cd "${azurehound_path}"; sha256sum --check --warn ./*.sha256) || exit
    7z a -tzip -mx9 "${azurehound_path}/azurehound-${azurehound_version}.zip" "${azurehound_path}/azurehound-*"
    # Upstream does not provide a sha256 file for the archive to check the integrity
    sha256sum "${azurehound_path}/azurehound-${azurehound_version}.zip" > "${azurehound_path}/azurehound-${azurehound_version}.zip.sha256"

    # Files and directories
    # work directory required by bloodhound
    mkdir -p "${bloodhoundce_path}/work"
    ln -v -s "${bloodhoundce_path}/src/artifacts/bhapi" "${bloodhoundce_path}/bloodhound"
    cp -v /root/sources/assets/bloodhound-ce/bloodhound-ce /opt/tools/bin/
    cp -v /root/sources/assets/bloodhound-ce/bloodhound-ce-reset /opt/tools/bin/
    cp -v /root/sources/assets/bloodhound-ce/bloodhound-ce-stop /opt/tools/bin/
    chmod +x /opt/tools/bin/bloodhound-ce*

    # Configuration
    cp -v /root/sources/assets/bloodhound-ce/bloodhound.config.json "${bloodhoundce_path}"

    # the following test command probably needs to be changed. No idea how we can make sure bloodhound-ce works as intended.
    add-test-command "${bloodhoundce_path}/bloodhound -version"
    add-test-command "service postgresql start && sleep 5 && PGPASSWORD=exegol4thewin psql -U bloodhound -d bloodhound -h localhost -c '\l' && service postgresql stop"
    add-to-list "BloodHound-CE,https://github.com/SpecterOps/BloodHound,Active Directory security tool for reconnaissance and attacking AD environments (Community Edition)"
}

function install_cypheroth() {
    colorecho "Installing cypheroth"
    git -C /opt/tools/ clone --depth 1 https://github.com/seajaysec/cypheroth
    add-aliases cypheroth
    add-history cypheroth
    add-test-command "cypheroth.sh --help|& grep 'Example with Defaults:'"
    add-to-list "cyperoth,https://github.com/seajaysec/cypheroth,Automated extensible toolset that runs cypher queries against Bloodhound's Neo4j backend and saves output to spreadsheets."
}

function install_mitm6_pip() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing mitm6 with pip"
    pipx install --system-site-packages mitm6
    add-history mitm6
    add-test-command "mitm6 --help"
    add-to-list "mitm6,https://github.com/fox-it/mitm6,Tool to conduct a man-in-the-middle attack against IPv6 protocols."
}

function install_aclpwn() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing aclpwn with pip"
    pipx install --system-site-packages git+https://github.com/aas-n/aclpwn.py
    add-history aclpwn
    add-test-command "aclpwn -h"
    add-to-list "aclpwn,https://github.com/aas-n/aclpwn.py,Tool for testing the security of Active Directory access controls."
}

function install_impacket() {
    colorecho "Installing Impacket scripts"
    pipx install --system-site-packages git+https://github.com/ThePorgs/impacket
    pipx inject impacket chardet
    cp -v /root/sources/assets/grc/conf.ntlmrelayx /usr/share/grc/conf.ntlmrelayx
    cp -v /root/sources/assets/grc/conf.secretsdump /usr/share/grc/conf.secretsdump
    cp -v /root/sources/assets/grc/conf.getgpppassword /usr/share/grc/conf.getgpppassword
    cp -v /root/sources/assets/grc/conf.rbcd /usr/share/grc/conf.rbcd
    cp -v /root/sources/assets/grc/conf.describeTicket /usr/share/grc/conf.describeTicket
    add-aliases impacket
    add-history impacket
    add-test-command "ntlmrelayx.py --help"
    add-test-command "secretsdump.py --help"
    add-test-command "Get-GPPPassword.py --help"
    add-test-command "getST.py --help |& grep 'u2u'"
    add-test-command "ticketer.py --help |& grep impersonate"
    add-test-command "ticketer.py --help |& grep hours"
    add-test-command "ticketer.py --help |& grep extra-pac"
    add-test-command "dacledit.py --help"
    add-test-command "describeTicket.py --help"
    add-to-list "impacket,https://github.com/ThePorgs/impacket,Set of tools for working with network protocols (ThePorgs version)."
}

function install_pykek() {
    colorecho "Installing Python Kernel Exploit Kit (pykek) for MS14-068"
    git -C /opt/tools/ clone --depth 1 https://github.com/preempt/pykek
    add-aliases pykek
    add-history pykek
    add-test-command "ms14-068.py |& grep '<clearPassword>'"
    add-to-list "pykek,https://github.com/preempt/pykek,PyKEK (Python Kerberos Exploitation Kit) a python library to manipulate KRB5-related data."
}

function install_lsassy() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing lsassy"
    pipx install --system-site-packages lsassy
    add-history lsassy
    add-test-command "lsassy --version"
    add-to-list "lsassy,https://github.com/Hackndo/lsassy,Windows secrets and passwords extraction tool."
}

function install_privexchange() {
    colorecho "Installing privexchange"
    git -C /opt/tools/ clone --depth 1 https://github.com/dirkjanm/PrivExchange
    cd /opt/tools/PrivExchange || exit
    python3 -m venv --system-site-packages ./venv
    source ./venv/bin/activate
    pip3 install impacket
    deactivate
    add-aliases privexchange
    add-history privexchange
    add-test-command "privexchange.py --help"
    add-to-list "privexchange,https://github.com/dirkjanm/PrivExchange,a tool to perform attacks against Microsoft Exchange server using NTLM relay techniques"
}

function install_ruler() {
    colorecho "Downloading ruler and form templates"
    mkdir -p /opt/tools/ruler || exit
    cd /opt/tools/ruler || exit
    asdf set golang 1.23.0
    mkdir -p .go/bin
    GOBIN=/opt/tools/ruler/.go/bin go install -v github.com/sensepost/ruler@latest
    asdf reshim golang
    add-aliases ruler
    add-history ruler
    add-test-command "ruler --version"
    add-to-list "ruler,https://github.com/sensepost/ruler,Outlook Rules exploitation framework."
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
    add-test-command "upx --help"
    add-to-list "upx,https://github.com/upx/upx,UPX is an advanced executable packer"
}

function install_darkarmour() {
    colorecho "Installing darkarmour"
    fapt mingw-w64-tools mingw-w64-common g++-mingw-w64 gcc-mingw-w64 osslsigncode
    install_upx
    git -C /opt/tools/ clone --depth 1 https://github.com/bats3c/darkarmour
    add-aliases darkarmour
    add-history darkarmour
    add-test-command "darkarmour.py --help"
    add-to-list "darkarmour,https://github.com/bats3c/darkarmour,a tool to detect and evade common antivirus products"
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
    make -j
    make install && ldconfig
    # Installing amber
    go install -v github.com/EgeBalci/amber@latest
    asdf reshim golang
    add-history amber
    add-test-command "amber --help"
    add-to-list "amber,https://github.com/EgeBalci/amber,Forensic tool to recover browser history / cookies and credentials"
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
      add-test-command "powershell -Version"
      add-to-list "powershell,https://github.com/PowerShell/PowerShell,a command-line shell and scripting language designed for system administration and automation"
    fi
}

function install_krbrelayx() {
    colorecho "Installing krbrelayx"
    git -C /opt/tools/ clone --depth 1 https://github.com/dirkjanm/krbrelayx
    cd /opt/tools/krbrelayx || exit
    python3 -m venv --system-site-packages ./venv
    source ./venv/bin/activate
    pip3 install dnspython ldap3 impacket dsinternals
    deactivate
    cp -v /root/sources/assets/grc/conf.krbrelayx /usr/share/grc/conf.krbrelayx
    add-aliases krbrelayx
    add-history krbrelayx
    add-test-command "krbrelayx.py --help"
    add-test-command "addspn.py --help"
    add-test-command "addspn.py --help"
    add-test-command "printerbug.py --help"
    add-to-list "krbrelayx,https://github.com/dirkjanm/krbrelayx,a tool for performing Kerberos relay attacks"
}

function install_evilwinrm() {
    colorecho "Installing evil-winrm"
    rvm use 3.1.2@evil-winrm --create
    gem install evil-winrm
    rvm use 3.2.2@default
    add-aliases evil-winrm
    add-history evil-winrm
    add-test-command "evil-winrm --help"
    add-to-list "evilwinrm,https://github.com/Hackplayers/evil-winrm,Tool to connect to a remote Windows system with WinRM."
}

function install_pypykatz() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing pypykatz"
    # without following fix, tool raises "oscrypto.errors.LibraryNotFoundError: Error detecting the version of libcrypto"
    # see https://github.com/wbond/oscrypto/issues/78 and https://github.com/wbond/oscrypto/issues/75
    local temp_fix_limit="2025-04-01"
    if [[ "$(date +%Y%m%d)" -gt "$(date -d $temp_fix_limit +%Y%m%d)" ]]; then
      criticalecho "Temp fix expired. Exiting."
    else
       git -C /opt/tools/ clone --depth 1 https://github.com/skelsec/pypykatz
      cd /opt/tools/pypykatz || exit
      python3 -m venv --system-site-packages ./venv
      source ./venv/bin/activate
      pip3 install .
      pip3 install --force oscrypto@git+https://github.com/wbond/oscrypto.git
      ln -v -s /opt/tools/pypykatz/venv/bin/pypykatz /opt/tools/bin/pypykatz
      deactivate
    fi
    # pipx install --system-site-packages pypykatz
    add-history pypykatz
    add-test-command "pypykatz version"
    add-test-command "pypykatz crypto nt 'exegol4thewin'"
    add-to-list "pypykatz,https://github.com/skelsec/pypykatz,a Python library for mimikatz-like functionality"
}

function install_krbjack() {
    # CODE-CHECK-WHITELIST=add-aliases,add-history
    colorecho "Installing krbjack"
    pipx install --system-site-packages krbjack
    add-test-command "krbjack --help"
    add-to-list "krbjack,https://github.com/almandin/krbjack,A Kerberos AP-REQ hijacking tool with DNS unsecure updates abuse."
}

function install_enyx() {
    colorecho "Installing enyx"
    git -C /opt/tools/ clone --depth 1 https://github.com/trickster0/Enyx
    add-aliases enyx
    add-history enyx
    add-test-command "enyx.py"
    add-to-list "enyx,https://github.com/trickster0/enyx,Framework for building offensive security tools."
}

function install_enum4linux-ng() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing enum4linux-ng"
    pipx install --system-site-packages git+https://github.com/cddmp/enum4linux-ng
    add-history enum4linux-ng
    add-test-command "enum4linux-ng --help"
    add-to-list "enum4linux-ng,https://github.com/cddmp/enum4linux-ng,Tool for enumerating information from Windows and Samba systems."
}

function install_zerologon() {
    colorecho "Pulling CVE-2020-1472 exploit and scan scripts"
    mkdir /opt/tools/zerologon
    cd /opt/tools/zerologon || exit
    python3 -m venv --system-site-packages ./venv
    source ./venv/bin/activate
    pip3 install impacket
    deactivate
    git -C /opt/tools/zerologon clone --depth 1 https://github.com/SecuraBV/CVE-2020-1472 zerologon-scan
    git -C /opt/tools/zerologon clone --depth 1 https://github.com/dirkjanm/CVE-2020-1472 zerologon-exploit
    add-aliases zerologon
    add-history zerologon
    add-test-command "zerologon-scan.py |& grep Usage"
    add-to-list "zerologon,https://github.com/SecuraBV/CVE-2020-1472,Exploit for the Zerologon vulnerability (CVE-2020-1472)."
}

function install_libmspack() {
    colorecho "Installing libmspack"
    git -C /opt/tools/ clone --depth 1 https://github.com/kyz/libmspack.git
    cd /opt/tools/libmspack/libmspack || exit
    ./rebuild.sh
    ./configure
    make
    add-aliases libmspack
    add-history libmspack
    add-test-command "oabextract"
    add-to-list "libmspack,https://github.com/kyz/libmspack,C library for Microsoft compression formats."
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
    add-test-command "windapsearch --version"
    add-to-list "windapsearch-go,https://github.com/ropnop/go-windapsearch/,Active Directory enumeration tool."
}

function install_oaburl() {
    colorecho "Downloading oaburl.py"
    mkdir /opt/tools/OABUrl
    wget -O /opt/tools/OABUrl/oaburl.py "https://gist.githubusercontent.com/snovvcrash/4e76aaf2a8750922f546eed81aa51438/raw/96ec2f68a905eed4d519d9734e62edba96fd15ff/oaburl.py"
    cd /opt/tools/OABUrl/ || exit
    python3 -m venv --system-site-packages ./venv
    source ./venv/bin/activate
    pip3 install requests
    deactivate
    add-aliases oaburl
    add-history oaburl
    add-test-command "oaburl.py --help"
    add-to-list "oaburl,https://gist.githubusercontent.com/snovvcrash/4e76aaf2a8750922f546eed81aa51438/raw/96ec2f68a905eed4d519d9734e62edba96fd15ff/oaburl.py,Find Open redirects and other vulnerabilities."
}

function install_lnkup() {
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
    add-to-list "lnkup,https://github.com/Plazmaz/lnkUp,This tool will allow you to generate LNK payloads. Upon rendering or being run they will exfiltrate data."
}

function install_polenum() {
    colorecho "Installing polenum"
    git -C /opt/tools/ clone --depth 1 https://github.com/Wh1t3Fox/polenum
    cd /opt/tools/polenum || exit
    python3 -m venv --system-site-packages ./venv
    source ./venv/bin/activate
    pip3 install impacket
    deactivate
    add-aliases polenum
    add-history polenum
    add-test-command "polenum.py --help"
    add-to-list "polenum,https://github.com/Wh1t3Fox/polenum,Polenum is a Python script which uses the Impacket library to extract user information through the SMB protocol."
}

function install_smbmap() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing smbmap"
    git -C /opt/tools clone --depth 1 https://github.com/ShawnDEvans/smbmap
    cd /opt/tools/smbmap || exit
    pipx install --system-site-packages .
    add-history smbmap
    add-test-command "smbmap --help"
    add-to-list "smbmap,https://github.com/ShawnDEvans/smbmap,A tool to enumerate SMB shares and check for null sessions"
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
        add-test-command "pth-net --version"
        add-test-command "pth-rpcclient --version"
        add-test-command "pth-smbclient --version"
        add-test-command "pth-smbget --version"
        add-test-command "pth-winexe --help"
        add-test-command "pth-wmic --help"
        add-test-command "pth-wmis --help"
        add-to-list "pth-tools,https://github.com/byt3bl33d3r/pth-toolkit,A toolkit to perform pass-the-hash attacks"
    elif [[ $(uname -m) = 'aarch64' ]]
    then
        criticalecho-noexit "This installation function doesn't support architecture $(uname -m)" && return
    fi
}

function install_smtp-user-enum() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing smtp-user-enum"
    pipx install --system-site-packages smtp-user-enum
    add-history smtp-user-enum
    add-test-command "smtp-user-enum --help"
    add-to-list "smtp-user-enum,https://github.com/pentestmonkey/smtp-user-enum,A tool to enumerate email addresses via SMTP"
}

function install_gpp-decrypt() {
    colorecho "Installing gpp-decrypt"
    git -C /opt/tools/ clone --depth 1 https://github.com/t0thkr1s/gpp-decrypt
    cd /opt/tools/gpp-decrypt || exit
    python3 -m venv --system-site-packages ./venv
    source ./venv/bin/activate
    pip3 install pycryptodome colorama
    deactivate
    add-aliases gpp-decrypt
    add-history gpp-decrypt
    add-test-command "gpp-decrypt.py -f /opt/tools/gpp-decrypt/groups.xml"
    add-to-list "gpp-decrypt,https://github.com/t0thkr1s/gpp-decrypt,A tool to decrypt Group Policy Preferences passwords"
}

function install_ntlmv1-multi() {
    colorecho "Installing ntlmv1 multi tool"
    git -C /opt/tools clone --depth 1 https://github.com/evilmog/ntlmv1-multi
    cd /opt/tools/ntlmv1-multi || exit
    python3 -m venv --system-site-packages ./venv
    source ./venv/bin/activate
    pip3 install pycryptodome
    deactivate
    add-aliases ntlmv1-multi
    add-history ntlmv1-multi
    add-test-command "ntlmv1-multi.py --ntlmv1 a::a:a:a:a"
    add-to-list "ntlmv1-multi,https://github.com/evilmog/ntlmv1-multi,Exploit a vulnerability in Microsoft Windows to gain system-level access."
}

function install_hashonymize() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing hashonymizer"
    pipx install --system-site-packages git+https://github.com/ShutdownRepo/hashonymize
    add-history hashonymize
    add-test-command "hashonymize --help"
    add-to-list "hashonymize,https://github.com/ShutdownRepo/hashonymize,This small tool is aimed at anonymizing hashes files for offline but online cracking like Google Collab for instance (see https://github.com/ShutdownRepo/google-colab-hashcat)."
}

function install_gosecretsdump() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing gosecretsdump"
    go install -v github.com/C-Sto/gosecretsdump@latest
    asdf reshim golang
    add-history gosecretsdump
    add-test-command "gosecretsdump -version"
    add-to-list "gosecretsdump,https://github.com/c-sto/gosecretsdump,Implements NTLMSSP network authentication protocol in Go"
}

function install_adidnsdump() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing adidnsdump"
    pipx install --system-site-packages git+https://github.com/dirkjanm/adidnsdump
    add-history adidnsdump
    add-test-command "adidnsdump --help"
    add-to-list "adidnsdump,https://github.com/dirkjanm/adidnsdump,Active Directory Integrated DNS dump utility"
}

function install_pygpoabuse() {
    colorecho "Installing pyGPOabuse"
    git -C /opt/tools/ clone --depth 1 https://github.com/Hackndo/pyGPOAbuse
    cd /opt/tools/pyGPOAbuse || exit
    python3 -m venv --system-site-packages ./venv
    source ./venv/bin/activate
    pip3 install -r requirements.txt
    # without following fix, tool raises "oscrypto.errors.LibraryNotFoundError: Error detecting the version of libcrypto"
    # see https://github.com/wbond/oscrypto/issues/78 and https://github.com/wbond/oscrypto/issues/75
    local temp_fix_limit="2025-04-01"
    if [[ "$(date +%Y%m%d)" -gt "$(date -d $temp_fix_limit +%Y%m%d)" ]]; then
      criticalecho "Temp fix expired. Exiting."
    else
      pip3 install --force oscrypto@git+https://github.com/wbond/oscrypto.git
    fi
    deactivate
    add-aliases pygpoabuse
    add-history pygpoabuse
    add-test-command "pygpoabuse.py --help"
    add-to-list "pygpoabuse,https://github.com/Hackndo/pyGPOAbuse,A tool for abusing GPO permissions to escalate privileges"
}

function install_bloodhound-import() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing bloodhound-import"
    pipx install --system-site-packages bloodhound-import
    add-history bloodhound-import
    add-test-command "bloodhound-import --help"
    add-to-list "bloodhound-import,https://github.com/fox-it/BloodHound.py,Import data into BloodHound for analyzing active directory trust relationships"
}

function install_bloodhound-quickwin() {
    colorecho "Installing bloodhound-quickwin"
    git -C /opt/tools/ clone --depth 1 https://github.com/kaluche/bloodhound-quickwin
    cd /opt/tools/bloodhound-quickwin || exit
    python3 -m venv --system-site-packages ./venv
    source ./venv/bin/activate
    pip3 install -r requirements.txt
    deactivate
    add-aliases bloodhound-quickwin
    add-history bloodhound-quickwin
    add-test-command "bloodhound-quickwin --help"
    add-to-list "bloodhound-quickwin,https://github.com/kaluche/bloodhound-quickwin,A tool for BloodHounding on Windows machines without .NET or Powershell installed"
}

function install_ldapsearch-ad() {
    colorecho "Installing ldapsearch-ad"
    git -C /opt/tools/ clone --depth 1 https://github.com/yaap7/ldapsearch-ad
    cd /opt/tools/ldapsearch-ad || exit
    python3 -m venv --system-site-packages ./venv
    source ./venv/bin/activate
    pip3 install -r requirements.txt
    deactivate
    add-aliases ldapsearch-ad
    add-history ldapsearch-ad
    add-test-command "ldapsearch-ad.py --version"
    add-to-list "ldapsearch-ad,https://github.com/yaap7/ldapsearch-ad,LDAP search utility with AD support"
}

function install_petitpotam() {
    colorecho "Installing PetitPotam"
    git -C /opt/tools/ clone --depth 1 https://github.com/ly4k/PetitPotam
    cd /opt/tools/PetitPotam || exit
    python3 -m venv --system-site-packages ./venv
    source ./venv/bin/activate
    pip3 install impacket
    deactivate
    mv /opt/tools/PetitPotam /opt/tools/PetitPotam_alt
    git -C /opt/tools/ clone --depth 1 https://github.com/topotam/PetitPotam
    cd /opt/tools/PetitPotam || exit
    python3 -m venv --system-site-packages ./venv
    source ./venv/bin/activate
    pip3 install impacket
    deactivate
    add-aliases petitpotam
    add-history petitpotam
    add-test-command "petitpotam.py --help"
    add-to-list "petitpotam,https://github.com/topotam/PetitPotam,Windows machine account manipulation"
}

function install_dfscoerce() {
    colorecho "Installing DfsCoerce"
    git -C /opt/tools/ clone --depth 1 https://github.com/Wh04m1001/DFSCoerce
    cd /opt/tools/DFSCoerce || exit
    python3 -m venv --system-site-packages ./venv
    source ./venv/bin/activate
    pip3 install impacket
    deactivate
    add-aliases dfscoerce
    add-history dfscoerce
    add-test-command "dfscoerce.py --help"
    add-to-list "dfscoerce,https://github.com/Wh04m1001/dfscoerce,DFS-R target coercion tool"
}

function install_coercer() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing Coercer"
    pipx install --system-site-packages git+https://github.com/p0dalirius/Coercer
    add-history coercer
    add-test-command "coercer --help"
    add-to-list "coercer,https://github.com/p0dalirius/coercer,DFS-R target coercion tool"
}

function install_pkinittools() {
    colorecho "Installing PKINITtools"
    git -C /opt/tools/ clone --depth 1 https://github.com/dirkjanm/PKINITtools
    cd /opt/tools/PKINITtools || exit
    python3 -m venv --system-site-packages ./venv
    source ./venv/bin/activate
    pip3 install -r requirements.txt
    # without following fix, tool raises "oscrypto.errors.LibraryNotFoundError: Error detecting the version of libcrypto"
    # see https://github.com/wbond/oscrypto/issues/78 and https://github.com/wbond/oscrypto/issues/75
    local temp_fix_limit="2025-04-01"
    if [[ "$(date +%Y%m%d)" -gt "$(date -d $temp_fix_limit +%Y%m%d)" ]]; then
      criticalecho "Temp fix expired. Exiting."
    else
      pip3 install --force oscrypto@git+https://github.com/wbond/oscrypto.git
    fi
    deactivate
    add-aliases pkinittools
    add-history pkinittools
    add-test-command "gettgtpkinit.py --help"
    add-to-list "pkinittools,https://github.com/dirkjanm/PKINITtools,Pkinit support tools"
}

function install_pywhisker() {
    colorecho "Installing pyWhisker"
    # CODE-CHECK-WHITELIST=add-aliases
    pipx install --system-site-packages git+https://github.com/ShutdownRepo/pywhisker
    add-history pywhisker
    add-test-command "pywhisker --help"
    add-to-list "pywhisker,https://github.com/ShutdownRepo/pywhisker,PyWhisker is a Python equivalent of the original Whisker made by Elad Shamir and written in C#. This tool allows users to manipulate the msDS-KeyCredentialLink attribute of a target user/computer to obtain full control over that object. It's based on Impacket and on a Python equivalent of Michael Grafnetter's DSInternals called PyDSInternals made by podalirius."
}

function install_manspider() {
    colorecho "Installing Manspider"
    git -C /opt/tools clone --depth 1 https://github.com/blacklanternsecurity/MANSPIDER.git
    cd /opt/tools/MANSPIDER || exit
    python3 -m venv --system-site-packages ./venv
    source ./venv/bin/activate
    pip3 install .
    deactivate
    touch ./man_spider/lib/init.py
    sed -i "s#from .lib import#from lib import##" man_spider/manspider.py
    add-aliases manspider
    add-history manspider
    add-test-command "manspider.py --help"
    add-to-list "manspider,https://github.com/blacklanternsecurity/MANSPIDER,Manspider will crawl every share on every target system. If provided creds don't work it will fall back to 'guest' then to a null session."
}

function install_targetedKerberoast() {
    colorecho "Installing targetedKerberoast"
    git -C /opt/tools/ clone --depth 1 https://github.com/ShutdownRepo/targetedKerberoast
    cd /opt/tools/targetedKerberoast || exit
    python3 -m venv --system-site-packages ./venv
    source ./venv/bin/activate
    pip3 install -r requirements.txt
    deactivate
    add-aliases targetedkerberoast
    add-history targetedkerberoast
    add-test-command "targetedKerberoast.py --help"
    add-to-list "targetedKerberoast,https://github.com/ShutdownRepo/targetedKerberoast,Kerberoasting against specific accounts"
}

function install_pcredz() {
    colorecho "Installing PCredz"
    fapt libpcap-dev
    git -C /opt/tools/ clone --depth 1 https://github.com/lgandx/PCredz
    cd /opt/tools/PCredz || exit
    python3 -m venv --system-site-packages ./venv
    source ./venv/bin/activate
    pip3 install Cython python-libpcap
    deactivate
    add-aliases pcredz
    add-history pcredz
    add-test-command "PCredz --help"
    add-to-list "pcredz,https://github.com/lgandx/PCredz,PowerShell credential dumper"
}

function install_pywsus() {
    colorecho "Installing pywsus"
    fapt libxml2-dev libxslt-dev
    git -C /opt/tools/ clone --depth 1 https://github.com/GoSecure/pywsus
    cd /opt/tools/pywsus || exit
    python3 -m venv --system-site-packages ./venv
    # https://github.com/GoSecure/pywsus/pull/12
    echo -e "beautifulsoup4==4.9.1\nlxml==4.9.1\nsoupsieve==2.0.1" > requirements.txt
    source ./venv/bin/activate
    pip3 install -r requirements.txt
    deactivate
    add-aliases pywsus
    add-history pywsus
    add-test-command "pywsus.py --help"
    add-to-list "pywsus,https://github.com/GoSecure/pywsus,Python implementation of a WSUS client"
}

function install_donpapi() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing DonPAPI"
    fapt swig
    pipx install --system-site-packages git+https://github.com/login-securite/DonPAPI
    add-history donpapi
    add-test-command "DonPAPI --help"
    add-to-list "donpapi,https://github.com/login-securite/DonPAPI,Dumping revelant information on compromised targets without AV detection"
}

function install_webclientservicescanner() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing webclientservicescanner"
    pipx install --system-site-packages git+https://github.com/Hackndo/WebclientServiceScanner
    add-history webclientservicescanner
    add-test-command "webclientservicescanner --help"
    add-to-list "webclientservicescanner,https://github.com/Hackndo/webclientservicescanner,Scans for web service endpoints"
}

function install_certipy() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing Certipy"
    pipx install --system-site-packages git+https://github.com/ly4k/Certipy
    add-history certipy
    add-test-command "certipy --version"
    add-to-list "certipy,https://github.com/ly4k/Certipy,Python tool to create and sign certificates"
}

function install_shadowcoerce() {
    colorecho "Installing ShadowCoerce PoC"
    git -C /opt/tools/ clone --depth 1 https://github.com/ShutdownRepo/ShadowCoerce
    cd /opt/tools/ShadowCoerce || exit
    python3 -m venv --system-site-packages ./venv
    source ./venv/bin/activate
    pip3 install impacket
    deactivate
    add-aliases shadowcoerce
    add-history shadowcoerce
    add-test-command "shadowcoerce.py --help"
    add-to-list "shadowcoerce,https://github.com/ShutdownRepo/shadowcoerce,Utility for bypassing the Windows Defender antivirus by hiding a process within a legitimate process."
}

function install_gmsadumper() {
    colorecho "Installing gMSADumper"
    git -C /opt/tools/ clone --depth 1 https://github.com/micahvandeusen/gMSADumper
    cd /opt/tools/gMSADumper || exit
    python3 -m venv --system-site-packages ./venv
    source ./venv/bin/activate
    pip3 install -r requirements.txt
    deactivate
    add-aliases gmsadumper
    add-history gmsadumper
    add-test-command "gMSADumper.py --help"
    add-to-list "gmsadumper,https://github.com/micahvandeusen/gMSADumper,A tool for extracting credentials and other information from a Microsoft Active Directory domain."
}

function install_pylaps() {
    colorecho "Installing pyLAPS"
    git -C /opt/tools/ clone --depth 1 https://github.com/p0dalirius/pyLAPS
    cd /opt/tools/pyLAPS || exit
    python3 -m venv --system-site-packages ./venv
    source ./venv/bin/activate
    pip3 install impacket
    deactivate
    add-aliases pylaps
    add-history pylaps
    add-test-command "pyLAPS.py --help"
    add-to-list "pylaps,https://github.com/p0dalirius/pylaps,Utility for enumerating and querying LDAP servers."
}

function install_pyfinduncommonshares() {
    colorecho "Installing pyFindUncommonShares"
    git -C /opt/tools/ clone --depth 1 https://github.com/p0dalirius/pyFindUncommonShares
    cd /opt/tools/pyFindUncommonShares/ || exit
    python3 -m venv --system-site-packages ./venv
    source ./venv/bin/activate
    pip3 install -r requirements.txt
    deactivate
    add-aliases finduncommonshares
    add-history finduncommonshares
    add-test-command "FindUncommonShares.py --help"
    add-to-list "pyFindUncommonShares,https://github.com/p0dalirius/pyFindUncommonShares,Script that can help identify shares that are not commonly found on a Windows system."
}

function install_ldaprelayscan() {
    colorecho "Installing LdapRelayScan"
    git -C /opt/tools/ clone --depth 1 https://github.com/zyn3rgy/LdapRelayScan
    cd /opt/tools/LdapRelayScan || exit
    python3 -m venv --system-site-packages ./venv
    source ./venv/bin/activate
    pip3 install -r requirements.txt
    # without following fix, tool raises "oscrypto.errors.LibraryNotFoundError: Error detecting the version of libcrypto"
    # see https://github.com/wbond/oscrypto/issues/78 and https://github.com/wbond/oscrypto/issues/75
    local temp_fix_limit="2025-04-01"
    if [[ "$(date +%Y%m%d)" -gt "$(date -d $temp_fix_limit +%Y%m%d)" ]]; then
      criticalecho "Temp fix expired. Exiting."
    else
      pip3 install --force oscrypto@git+https://github.com/wbond/oscrypto.git
    fi
    deactivate
    add-aliases ldaprelayscan
    add-history ldaprelayscan
    add-test-command "LdapRelayScan.py --help"
    add-to-list "ldaprelayscan,https://github.com/zyn3rgy/LdapRelayScan,Check Domain Controllers for LDAP server protections regarding the relay of NTLM authentication."
}

function install_goldencopy() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing GoldenCopy"
    git -C /opt/tools/ clone --depth 1 https://github.com/Dramelac/GoldenCopy
    cd /opt/tools/GoldenCopy || exit
    python3 -m venv --system-site-packages ./venv
    source ./venv/bin/activate
    pip3 install .
    deactivate
    ln -v -s /opt/tools/GoldenCopy/venv/bin/goldencopy /opt/tools/bin/goldencopy
    add-history goldencopy
    add-test-command "goldencopy --help"
    add-to-list "goldencopy,https://github.com/Dramelac/GoldenCopy,Copy the properties and groups of a user from neo4j (bloodhound) to create an identical golden ticket"
}

function install_crackhound() {
    colorecho "Installing CrackHound"
    git -C /opt/tools/ clone --depth 1 https://github.com/trustedsec/CrackHound
    cd /opt/tools/CrackHound || exit
    python3 -m venv --system-site-packages ./venv
    source ./venv/bin/activate
    pip3 install -r requirements.txt
    deactivate
    add-aliases crackhound
    add-history crackhound
    add-test-command "crackhound.py --help"
    add-to-list "crackhound,https://github.com/trustedsec/crackhound,A fast WPA/WPA2/WPA3 WiFi Handshake capture / password recovery and analysis tool"
}

function install_kerbrute() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing Kerbrute"
    go install -v github.com/ropnop/kerbrute@latest
    asdf reshim golang
    add-history kerbrute
    add-test-command "kerbrute --help"
    add-to-list "kerbrute,https://github.com/ropnop/kerbrute,A tool to perform Kerberos pre-auth bruteforcing"
}

function install_ldeep() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing ldeep"
    fapt libkrb5-dev krb5-config
    pipx install --system-site-packages ldeep
    add-history ldeep
    add-test-command "ldeep --help"
    add-to-list "ldeep,https://github.com/franc-pentest/ldeep,ldeep is a tool to discover hidden paths on Web servers."
}

function install_rusthound() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing RustHound"
    fapt gcc clang libclang-dev libgssapi-krb5-2 libkrb5-dev libsasl2-modules-gssapi-mit musl-tools gcc-mingw-w64-x86-64
    git -C /opt/tools/ clone --depth 1 https://github.com/NH-RED-TEAM/RustHound
    cd /opt/tools/RustHound || exit
    # Sourcing rustup shell setup, so that rust binaries are found when installing cme
    source "$HOME/.cargo/env"
    cargo update -p time
    cargo build --release
    # Clean dependencies used to build the binary
    rm -rf target/release/{deps,build}
    ln -s /opt/tools/RustHound/target/release/rusthound /opt/tools/bin/rusthound
    add-history rusthound
    add-test-command "rusthound --help"
    add-to-list "rusthound,https://github.com/NH-RED-TEAM/RustHound,BloodHound ingestor in Rust."
}

function install_rusthound-ce() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing RustHound for BloodHound-CE"
    fapt gcc clang libclang-dev libgssapi-krb5-2 libkrb5-dev libsasl2-modules-gssapi-mit musl-tools gcc-mingw-w64-x86-64
    git -C /opt/tools/ clone --depth 1 https://github.com/g0h4n/RustHound-CE
    cd /opt/tools/RustHound-CE || exit
    # Sourcing rustup shell setup, so that rust binaries are found when installing cme
    source "$HOME/.cargo/env"
    cargo build --release
    # Clean dependencies used to build the binary
    rm -rf target/release/{deps,build}
    ln -v -s /opt/tools/RustHound-CE/target/release/rusthound-ce /opt/tools/bin/rusthound-ce
    add-history rusthound-ce
    add-test-command "rusthound-ce --help"
    add-to-list "rusthound-ce,https://github.com/g0h4n/RustHound-CE,BloodHound-CE ingestor in Rust."
}

function install_certsync() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing certsync"
    pipx install --system-site-packages git+https://github.com/zblurx/certsync
    add-history certsync
    add-test-command "certsync --help"
    add-to-list "certsync,https://github.com/zblurx/certsync,certsync is a tool that helps you synchronize certificates between two directories."
}

function install_keepwn() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing KeePwn"
    pipx install --system-site-packages git+https://github.com/Orange-Cyberdefense/KeePwn
    add-history keepwn
    add-test-command "KeePwn --help"
    add-to-list "KeePwn,https://github.com/Orange-Cyberdefense/KeePwn,KeePwn is a tool that extracts passwords from KeePass 1.x and 2.x databases."
}

function install_pre2k() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing pre2k"
    pipx install --system-site-packages git+https://github.com/garrettfoster13/pre2k
    add-history pre2k
    add-test-command "pre2k --help"
    add-to-list "pre2k,https://github.com/garrettfoster13/pre2k,pre2k is a tool to check if a Windows domain has any pre-2000 Windows 2000 logon names still in use."
}

function install_msprobe() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing msprobe"
    pipx install --system-site-packages git+https://github.com/puzzlepeaches/msprobe
    add-history msprobe
    add-test-command "msprobe --help"
    add-to-list "msprobe,https://github.com/puzzlepeaches/msprobe,msprobe is a tool to identify Microsoft Windows hosts and servers that are running certain services."
}

function install_masky() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing masky"
    pipx install --system-site-packages git+https://github.com/Z4kSec/Masky
    add-history masky
    add-test-command "masky --help"
    add-to-list "masky,https://github.com/Z4kSec/Masky,Masky is a python library providing an alternative way to remotely dump domain users' credentials thanks to an ADCS. A command line tool has been built on top of this library in order to easily gather PFX or NT hashes and TGT on a larger scope"
}

function install_roastinthemiddle() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing roastinthemiddle"
    pipx install --system-site-packages git+https://github.com/Tw1sm/RITM
    add-history roastinthemiddle
    add-test-command "roastinthemiddle --help"
    add-to-list "roastinthemiddle,https://github.com/Tw1sm/RITM,RoastInTheMiddle is a tool to intercept and relay NTLM authentication requests."
}

function install_PassTheCert() {
    colorecho "Installing PassTheCert"
    git -C /opt/tools/ clone --depth 1 https://github.com/AlmondOffSec/PassTheCert
    cd /opt/tools/PassTheCert/Python/ || exit
    python3 -m venv --system-site-packages ./venv
    source ./venv/bin/activate
    pip3 install impacket
    deactivate
    add-aliases PassTheCert
    add-history PassTheCert
    add-test-command "passthecert.py --help"
    add-to-list "PassTheCert,https://github.com/AlmondOffSec/PassTheCert,PassTheCert is a tool to extract Active Directory user password hashes from a domain controller's local certificate store."
}

function install_bqm() {
    colorecho "Installing BQM"
    rvm use 3.2.2@bqm --create
    gem install bqm --no-wrapper
    rvm use 3.2.2@default
    add-aliases bqm
    add-history bqm
    add-test-command "bqm --help"
    add-to-list "bqm,https://github.com/Acceis/bqm,Tool to deduplicate custom BloudHound queries from different datasets and merge them in one file."
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
    add-test-command "neo4j version"
    add-to-list "neo4j,https://github.com/neo4j/neo4j,Database."
}

function install_noPac() {
    colorecho "Installing noPac"
    git -C /opt/tools/ clone --depth 1 https://github.com/Ridter/noPac
    cd /opt/tools/noPac || exit
    python3 -m venv --system-site-packages ./venv
    source ./venv/bin/activate
    pip3 install -r requirements.txt
    deactivate
    add-aliases noPac
    add-history noPac
    add-test-command "noPac.py --help"
    add-to-list "noPac,https://github.com/Ridter/noPac,Exploiting CVE-2021-42278 and CVE-2021-42287 to impersonate DA from standard domain user."
}

function install_roadrecon() {
    # CODE-CHECK-WHITELIST=add-aliases,add-history
    colorecho "Installing roadrecon"
    pipx install --system-site-packages roadrecon
    add-test-command "roadrecon --help"
    add-test-command "roadrecon-gui --help"
    add-to-list "ROADrecon,https://github.com/dirkjanm/ROADtools#roadrecon,Azure AD recon for red and blue."
}

function install_roadtx() {
    # CODE-CHECK-WHITELIST=add-aliases,add-history
    colorecho "Installing roadtx"
    pipx install --system-site-packages roadtx
    add-test-command "roadtx --help"
    add-to-list "ROADtx,https://github.com/dirkjanm/ROADtools#roadtools-token-exchange-roadtx,ROADtools Token eXchange."
}

function install_teamsphisher() {
    colorecho "Installing TeamsPhisher"
    git -C /opt/tools clone --depth 1 https://github.com/Octoberfest7/TeamsPhisher
    cd /opt/tools/TeamsPhisher || exit
    python3 -m venv --system-site-packages ./venv
    source ./venv/bin/activate
    pip3 install msal colorama requests
    deactivate
    add-aliases teamsphisher
    add-history teamsphisher
    add-test-command "teamsphisher.py --help"
    add-to-list "TeamsPhisher,https://github.com/Octoberfest7/TeamsPhisher,TeamsPhisher is a Python3 program that facilitates the delivery of phishing messages and attachments to Microsoft Teams users whose organizations allow external communications."
}

function install_GPOddity() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing GPOddity"
    pipx install --system-site-packages git+https://github.com/synacktiv/GPOddity
    add-history GPOddity
    add-test-command "gpoddity --help"
    add-to-list "GPOddity,https://github.com/synacktiv/GPOddity,Aiming at automating GPO attack vectors through NTLM relaying (and more)"
}

function install_netexec() {
    colorecho "Installing netexec"
    git -C /opt/tools/ clone --depth 1 https://github.com/Pennyw0rth/NetExec
    pipx install --system-site-packages /opt/tools/NetExec/
    mkdir -p ~/.nxc
    [[ -f ~/.nxc/nxc.conf ]] && mv ~/.nxc/nxc.conf ~/.nxc/nxc.conf.bak
    cp -v /root/sources/assets/netexec/nxc.conf ~/.nxc/nxc.conf
    add-aliases netexec
    add-history netexec
    add-test-command "netexec --help"
    add-to-list "netexec,https://github.com/Pennyw0rth/NetExec,Network scanner (Crackmapexec updated)."
}

function install_extractbitlockerkeys() {
    colorecho "Installing ExtractBitlockerKeys"
    git -C /opt/tools/ clone --depth 1 https://github.com/p0dalirius/ExtractBitlockerKeys
    cd /opt/tools/ExtractBitlockerKeys || exit
    python3 -m venv --system-site-packages ./venv
    source ./venv/bin/activate
    pip3 install -r requirements.txt
    deactivate
    add-aliases extractbitlockerkeys
    add-history extractbitlockerkeys
    add-test-command "ExtractBitlockerKeys.py|& grep 'usage: ExtractBitlockerKeys.py'"
    add-to-list "ExtractBitlockerKeys,https://github.com/p0dalirius/ExtractBitlockerKeys,A system administration or post-exploitation script to automatically extract the bitlocker recovery keys from a domain."
}

function install_LDAPWordlistHarvester() {
    colorecho "Installing LDAPWordlistHarvester"
    git -C /opt/tools/ clone --depth 1 https://github.com/p0dalirius/pyLDAPWordlistHarvester
    cd /opt/tools/pyLDAPWordlistHarvester || exit
    python3 -m venv --system-site-packages ./venv
    source ./venv/bin/activate
    pip3 install -r requirements.txt
    deactivate
    add-aliases LDAPWordlistHarvester
    add-history LDAPWordlistHarvester
    add-test-command "LDAPWordlistHarvester.py --help"
    add-to-list "LDAPWordlistHarvester,https://github.com/p0dalirius/pyLDAPWordlistHarvester,Generate a wordlist from the information present in LDAP in order to crack passwords of domain accounts"
}

function install_pywerview() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing pywerview"
    pipx install --system-site-packages git+https://github.com/the-useless-one/pywerview
    add-history pywerview
    add-test-command "pywerview --help"
    add-to-list "pywerview,https://github.com/the-useless-one/pywerview,A (partial) Python rewriting of PowerSploit's PowerView."
}

function install_freeipscanner() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing freeipscanner"
    fapt arping
    wget -O /opt/tools/bin/freeipscanner.sh https://raw.githubusercontent.com/scrt/freeipscanner/master/freeipscanner.sh
    chmod +x /opt/tools/bin/freeipscanner.sh
    add-history freeipscanner
    add-test-command "freeipscanner.sh --help"
    add-to-list "freeipscanner,https://github.com/scrt/freeipscanner,A simple bash script to enumerate stale ADIDNS entries"
}

function install_scrtdnsdump() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing scrtdnsdump"
    pipx install --system-site-packages git+https://github.com/scrt/scrtdnsdump
    add-history scrtdnsdump
    add-test-command "scrtdnsdump --help"
    add-to-list "scrtdnsdump,https://github.com/scrt/scrtdnsdump,Enumeration and exporting of all DNS records in the zone for recon purposes of internal networks"
}

function install_ntlm_theft() {
    colorecho "Installing ntlm_theft"
    git -C /opt/tools/ clone --depth 1 https://github.com/Greenwolf/ntlm_theft
    cd /opt/tools/ntlm_theft || exit
    python3 -m venv --system-site-packages ./venv
    source ./venv/bin/activate
    pip3 install xlsxwriter
    deactivate
    add-aliases ntlm_theft
    add-history ntlm_theft
    add-test-command "ntlm_theft.py --help"
    add-to-list "ntlm_theft,https://github.com/Greenwolf/ntlm_theft,A tool for generating multiple types of NTLMv2 hash theft files"
}

function install_abuseACL() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing abuseACL"
    pipx install --system-site-packages git+https://github.com/AetherBlack/abuseACL
    add-history abuseACL
    add-test-command "abuseACL --help"
    add-to-list "abuseACL,https://github.com/AetherBlack/abuseACL,A python script to automatically list vulnerable Windows ACEs/ACLs."
}

function install_bloodyAD() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing bloodyAD"
    pipx install --system-site-packages git+https://github.com/CravateRouge/bloodyAD
    add-history bloodyAD
    add-test-command "bloodyAD --help"
    add-to-list "bloodyAD,https://github.com/CravateRouge/bloodyAD,bloodyAD is an Active Directory privilege escalation swiss army knife."
}

function install_autobloody() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing autobloody"
    pipx install --system-site-packages git+https://github.com/CravateRouge/autobloody
    add-history autobloody
    add-test-command "autobloody --help"
    add-to-list "autobloody,https://github.com/CravateRouge/autobloody,Automatically exploit Active Directory privilege escalation paths shown by BloodHound."
}

function install_dploot() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing dploot"
    pipx install --system-site-packages git+https://github.com/zblurx/dploot
    add-history dploot
    add-test-command "dploot --help"
    add-to-list "dploot,https://github.com/zblurx/dploot,dploot is Python rewrite of SharpDPAPI written un C#."
}

# function install_PXEThief() {
#     # CODE-CHECK-WHITELIST=
#     colorecho "Installing PXEThief"
#     git -C /opt/tools/ clone --depth 1 https://github.com/MWR-CyberSec/PXEThief
#     cd /opt/tools/PXEThief || exit
#     python3 -m venv ./venv
#     source ./venv/bin/activate
# TODO: pywin32 not found
#     pip3 install -r requirements.txt
#     deactivate
#     add-aliases PXEThief
#     add-history PXEThief
#     add-test-command "PXEThief --help"
#     add-to-list "PXEThief,https://github.com/MWR-CyberSec/PXEThief,PXEThief is a toolset designed to exploit vulnerabilities in Microsoft Endpoint Configuration Manager's OS Deployment enabling credential theft from network and task sequence accounts."
# }

function install_sccmhunter() {
    colorecho "Installing sccmhunter"
    git -C /opt/tools/ clone --depth 1 https://github.com/garrettfoster13/sccmhunter
    cd /opt/tools/sccmhunter || exit
    python3 -m venv --system-site-packages ./venv
    source ./venv/bin/activate
    pip3 install -r requirements.txt
    deactivate
    add-aliases sccmhunter
    add-history sccmhunter
    add-test-command "sccmhunter.py --help"
    add-to-list "sccmhunter,https://github.com/garrettfoster13/sccmhunter,SCCMHunter is a post-ex tool built to streamline identifying profiling and attacking SCCM related assets in an Active Directory domain."
}

function install_sccmwtf() {
    # CODE-CHECK-WHITELIST=add-test-command
    colorecho "Installing sccmwtf"
    git -C /opt/tools/ clone --depth 1 https://github.com/xpn/sccmwtf
    cd /opt/tools/sccmwtf || exit
    python3 -m venv --system-site-packages ./venv
    source ./venv/bin/activate
    pip3 install -r requirements.txt
    deactivate
    add-aliases sccmwtf
    add-history sccmwtf
    add-to-list "sccmwtf,https://github.com/xpn/sccmwtf,This code is designed for exploring SCCM in a lab."
}

function install_smbclientng() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing smbclient-ng"
    pipx install git+https://github.com/p0dalirius/smbclient-ng
    add-history smbclient-ng
    add-test-command "smbclientng --help"
    add-to-list "smbclient-ng,https://github.com/p0dalirius/smbclient-ng,smbclient-ng is a fast and user friendly way to interact with SMB shares."
}

function install_conpass() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing conpass"
    pipx install --system-site-packages git+https://github.com/login-securite/conpass
    add-history conpass
    add-test-command "conpass --help"
    add-to-list "conpass,https://github.com/login-securite/conpass,Python tool for continuous password spraying taking into account the password policy."
}

function install_adminer() {
    colorecho "Installing adminer"
    pipx install git+https://github.com/Mazars-Tech/AD_Miner
    add-aliases adminer
    add-history adminer
    add-test-command "adminer --help"
    add-to-list "AD-miner,https://github.com/Mazars-Tech/AD_Miner,Active Directory audit tool that leverages cypher queries."
}

# Package dedicated to internal Active Directory tools
function package_ad() {
    set_env
    local start_time
    local end_time
    start_time=$(date +%s)
    install_ad_apt_tools
    install_asrepcatcher            # Active Directory ASREP roasting tool that catches ASREP for users in the same VLAN whether they require pre-authentication or not
    install_pretender
    install_responder               # LLMNR, NBT-NS and MDNS poisoner
    install_ldapdomaindump
    install_sprayhound              # Password spraying tool
    install_smartbrute              # Password spraying tool
    install_bloodhound-py           # ingestor for legacy BloodHound
    install_bloodhound-ce-py        # ingestor for legacy BloodHound
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
    install_pyfinduncommonshares
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
    install_roadrecon              # Rogue Office 365 and Azure (active) Directory tools
    install_roadtx                 # ROADtools Token eXchange
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
    install_bloodyAD               # Active Directory privilege escalation swiss army knife.
    install_autobloody             # Automatically exploit Active Directory privilege escalation paths.
    install_dploot                 # Python rewrite of SharpDPAPI written un C#.
    # install_PXEThief             # TODO: pywin32 not found - PXEThief is a toolset designed to exploit vulnerabilities in Microsoft Endpoint Configuration Manager's OS Deployment, enabling credential theft from network and task sequence accounts.
    install_sccmhunter             # SCCMHunter is a post-ex tool built to streamline identifying, profiling, and attacking SCCM related assets in an Active Directory domain.
    install_sccmwtf                # This code is designed for exploring SCCM in a lab.
    install_smbclientng
    install_conpass                # Python tool for continuous password spraying taking into account the password policy.
    install_adminer
    post_install
    end_time=$(date +%s)
    local elapsed_time=$((end_time - start_time))
    colorecho "Package ad completed in $elapsed_time seconds."
}
