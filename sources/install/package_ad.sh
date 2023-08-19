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

    add-to-list "samdump2,https://github.com/azan121468/SAMdump2,A tool to dump Windows NT/2k/XP/Vista password hashes from SAM files"
    add-to-list "smbclient,https://github.com/samba-team/samba,SMBclient is a command-line utility that allows you to access Windows shared resources"
    add-to-list "onesixtyone,https://github.com/trailofbits/onesixtyone,onesixtyone is an SNMP scanner which utilizes a sweep technique to achieve very high performance."
    add-to-list "nbtscan,https://github.com/charlesroelli/nbtscan,NBTscan is a program for scanning IP networks for NetBIOS name information."
    add-to-list "ldapsearch,https://wiki.debian.org/LDAP/LDAPUtils,Search for and display entries (ldap)"
}

function install_responder() {
    colorecho "Installing Responder"
    git -C /opt/tools/ clone --depth 1 https://github.com/lgandx/Responder
    cd /opt/tools/Responder
    python3 -m venv ./venv
    ./venv/bin/python3 -m pip install -r requirements.txt
    ./venv/bin/python3 -m pip install pycryptodome six pycryptodomex
    add-aliases responder
    add-history responder
    add-test-command "responder --version"
    add-test-command "runfinger --help"
    add-test-command "multirelay --help"
    add-to-list "responder,https://github.com/lgandx/Responder,a LLMNR / NBT-NS and MDNS poisoner."
}

function configure_responder() {
    colorecho "Configure responder"
    fapt python3-netifaces
    sed -i 's/ Random/ 1122334455667788/g' /opt/tools/Responder/Responder.conf
    sed -i 's/files\/AccessDenied.html/\/opt\/tools\/Responder\/files\/AccessDenied.html/g' /opt/tools/Responder/Responder.conf
    sed -i 's/files\/BindShell.exe/\/opt\/tools\/Responder\/files\/BindShell.exe/g' /opt/tools/Responder/Responder.conf
    sed -i 's/certs\/responder.crt/\/opt\/tools\/Responder\/certs\/responder.crt/g' /opt/tools/Responder/Responder.conf
    sed -i 's/certs\/responder.key/\/opt\/tools\/Responder\/certs\/responder.key/g' /opt/tools/Responder/Responder.conf
    x86_64-w64-mingw32-gcc /opt/tools/Responder/tools/MultiRelay/bin/Runas.c -o /opt/tools/Responder/tools/MultiRelay/bin/Runas.exe -municode -lwtsapi32 -luserenv
    x86_64-w64-mingw32-gcc /opt/tools/Responder/tools/MultiRelay/bin/Syssvc.c -o /opt/tools/Responder/tools/MultiRelay/bin/Syssvc.exe -municode
    cd /opt/tools/Responder || false
    /opt/tools/Responder/certs/gen-self-signed-cert.sh
}

function install_sprayhound() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing sprayhound"
    python3 -m pipx install git+https://github.com/Hackndo/sprayhound
    add-history sprayhound
    add-test-command "sprayhound --help"
    add-to-list "sprayhound,https://github.com/Hackndo/Sprayhound,Active Directory password audit tool."
}

function install_smartbrute() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing smartbrute"
    python3 -m pipx install git+https://github.com/ShutdownRepo/smartbrute
    add-history smartbrute
    add-test-command "smartbrute --help"
    add-to-list "smartbrute,https://github.com/ShutdownRepo/SmartBrute,The smart password spraying and bruteforcing tool for Active Directory Domain Services."
}

function install_ldapdomaindump() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing ldapdomaindump"
    python3 -m pipx install git+https://github.com/dirkjanm/ldapdomaindump
    add-history ldapdomaindump
    add-test-command "ldapdomaindump --help"
    add-to-list "ldapdomaindump,https://github.com/dirkjanm/ldapdomaindump,A tool for dumping domain data from an LDAP service"
}

function install_crackmapexec() {
    colorecho "Installing CrackMapExec"
    # Source bc cme needs cargo PATH (rustc) -> aardwolf dep
    # TODO: Optimize so that the PATH is always up to date
    source /root/.zshrc || true
    git -C /opt/tools/ clone --depth 1 https://github.com/mpgn/CrackMapExec.git
    python3 -m pipx install /opt/tools/CrackMapExec/
    add-aliases crackmapexec
    add-history crackmapexec
    add-test-command "crackmapexec --help"
    add-to-list "crackmapexec,https://github.com/mpgn/CrackMapExec,Network scanner."
}

function configure_crackmapexec() {
    colorecho "Configure crackmapexec"
    mkdir -p ~/.cme
    [ -f ~/.cme/cme.conf ] && mv ~/.cme/cme.conf ~/.cme/cme.conf.bak
    cp -v /root/sources/assets/crackmapexec/cme.conf ~/.cme/cme.conf
    # below is for having the ability to check the source code when working with modules and so on
    cp -v /root/sources/assets/grc/conf.cme /usr/share/grc/conf.cme
}

function install_bloodhound-py() {
    colorecho "Installing and Python ingestor for BloodHound"
    python3 -m pipx install git+https://github.com/fox-it/BloodHound.py
    add-aliases bloodhound-py
    add-history bloodhound-py
    add-test-command "bloodhound.py --help"
    add-to-list "bloodhound.py,https://github.com/fox-it/BloodHound.py,BloodHound ingestor in Python."
}

function install_bloodhound() {
    colorecho "Installing BloodHound from sources"
    git -C /opt/tools/ clone --depth 1 https://github.com/BloodHoundAD/BloodHound/
    mv /opt/tools/BloodHound /opt/tools/BloodHound4
    zsh -c "source ~/.zshrc && cd /opt/tools/BloodHound4 && nvm install 16.13.0 && nvm use 16.13.0 && npm install -g electron-packager && npm install && npm run build:linux"
    add-aliases bloodhound
    add-history bloodhound
    add-test-command "ldd /opt/tools/BloodHound4/BloodHound"
    add-to-list "bloodhound,https://github.com/BloodHoundAD/BloodHound,Active Directory security tool for reconnaissance and attacking AD environments."
}

function configure_bloodhound() {
    colorecho "Configure bloodhound"
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
}

function install_cypheroth() {
    colorecho "Installing cypheroth"
    git -C /opt/tools/ clone --depth 1 https://github.com/seajaysec/cypheroth
    add-aliases cypheroth
    add-history cypheroth
    add-test-command "cypheroth --help|& grep 'Example with Defaults:'"
    add-to-list "cyperoth,https://github.com/seajaysec/cypheroth,Automated extensible toolset that runs cypher queries against Bloodhound's Neo4j backend and saves output to spreadsheets."
}

function install_mitm6_pip() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing mitm6 with pip"
    python3 -m pipx install mitm6
    add-history mitm6
    add-test-command "mitm6 --help"
    add-to-list "mitm6,https://github.com/fox-it/mitm6,Tool to conduct a man-in-the-middle attack against IPv6 protocols."
}

function install_aclpwn() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing aclpwn with pip"
    python3 -m pipx install git+https://github.com/aas-n/aclpwn.py
    add-history aclpwn
    add-test-command "aclpwn -h"
    add-to-list "aclpwn,https://github.com/aas-n/aclpwn.py,Tool for testing the security of Active Directory access controls."
}

function install_impacket() {
    colorecho "Installing Impacket scripts"
    python3 -m pipx install git+https://github.com/ThePorgs/impacket
    python3 -m pipx inject impacket chardet
    add-aliases impacket
    add-history impacket
    add-test-command "ntlmrelayx.py --help"
    add-test-command "secretsdump.py --help"
    add-test-command "Get-GPPPassword.py --help"
    add-test-command "getST.py --help | grep 'u2u'"
    add-test-command "ticketer.py --help | grep impersonate"
    add-test-command "ticketer.py --help | grep hours"
    add-test-command "ticketer.py --help | grep extra-pac"
    add-test-command "dacledit.py --help"
    add-test-command "describeTicket.py --help"
    add-to-list "impacket,https://github.com/ThePorgs/impacket,Set of tools for working with network protocols (ThePorgs version)."
}

function configure_impacket() {
    colorecho "Configure impacket"
    cp -v /root/sources/assets/grc/conf.ntlmrelayx /usr/share/grc/conf.ntlmrelayx
    cp -v /root/sources/assets/grc/conf.secretsdump /usr/share/grc/conf.secretsdump
    cp -v /root/sources/assets/grc/conf.getgpppassword /usr/share/grc/conf.getgpppassword
    cp -v /root/sources/assets/grc/conf.rbcd /usr/share/grc/conf.rbcd
    cp -v /root/sources/assets/grc/conf.describeTicket /usr/share/grc/conf.describeTicket
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
    python3 -m pipx install lsassy
    add-history lsassy
    add-test-command "lsassy --version"
    add-to-list "lsassy,https://github.com/Hackndo/lsassy,Windows secrets and passwords extraction tool."
}

function install_privexchange() {
    colorecho "Installing privexchange"
    git -C /opt/tools/ clone --depth 1 https://github.com/dirkjanm/PrivExchange
    cd /opt/tools/PrivExchange
    python3 -m venv ./venv
    ./venv/bin/python3 -m pip install impacket
    add-aliases privexchange
    add-history privexchange
    add-test-command "privexchange.py --help"
    add-to-list "privexchange,https://github.com/dirkjanm/PrivExchange,a tool to perform attacks against Microsoft Exchange server using NTLM relay techniques"
}

function install_ruler() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Downloading ruler and form templates"
    go install github.com/sensepost/ruler@latest
    add-history ruler
    add-test-command "ruler --version"
    add-to-list "ruler,https://github.com/sensepost/ruler,Outlook Rules exploitation framework."
}

function install_darkarmour() {
    colorecho "Installing darkarmour"
    fapt mingw-w64-tools mingw-w64-common g++-mingw-w64 gcc-mingw-w64 upx-ucl osslsigncode
    git -C /opt/tools/ clone --depth 1 https://github.com/bats3c/darkarmour
    add-aliases darkarmour
    add-history darkarmour
    add-test-command "darkarmour --help"
    add-to-list "darkarmour,https://github.com/bats3c/darkarmour,a tool to detect and evade common antivirus products"
}

function install_amber() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing amber"
    # Installing keystone requirement
    git -C /opt/tools/ clone --depth 1 https://github.com/EgeBalci/keystone
    cd /opt/tools/keystone
    mkdir build && cd build
    ../make-lib.sh
    cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF -DLLVM_TARGETS_TO_BUILD="AArch64;X86" -G "Unix Makefiles" ..
    make -j8
    make install && ldconfig
    # Installing amber
    go install -v github.com/EgeBalci/amber@latest
    add-history amber
    add-test-command "amber --help"
    add-to-list "amber,https://github.com/EgeBalci/amber,Forensic tool to recover browser history / cookies and credentials"
}

function install_powershell() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing powershell"
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
}

function install_krbrelayx() {
    colorecho "Installing krbrelayx"
    git -C /opt/tools/ clone --depth 1 https://github.com/dirkjanm/krbrelayx
    cd /opt/tools/krbrelayx
    python3 -m venv ./venv
    ./venv/bin/python3 -m pip install dnspython ldap3 impacket dsinternals
    add-aliases krbrelayx
    add-history krbrelayx
    add-test-command "krbrelayx.py --help"
    add-test-command "addspn.py --help"
    add-test-command "addspn.py --help"
    add-test-command "printerbug.py --help"
    add-to-list "krbrelayx,https://github.com/dirkjanm/krbrelayx,a tool for performing Kerberos relay attacks"
}

function configure_krbrelayx() {
    colorecho "Configure krbrelayx"
    cp -v /root/sources/assets/grc/conf.krbrelayx /usr/share/grc/conf.krbrelayx
}

function install_evilwinrm() {
    colorecho "Installing evil-winrm"
    rvm use 3.0.0@evil-winrm --create
    gem install evil-winrm
    rvm use 3.0.0@default
    add-aliases evil-winrm
    add-history evil-winrm
    add-test-command "evil-winrm --help"
    add-to-list "evilwinrm,https://github.com/Hackplayers/evil-winrm,Tool to connect to a remote Windows system with WinRM."
}

function install_pypykatz() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing pypykatz"
    python3 -m pipx install pypykatz
    add-history pypykatz
    add-test-command "pypykatz version"
    add-to-list "pypykatz,https://github.com/skelsec/pypykatz,a Python library for mimikatz-like functionality"
}

function install_enyx() {
    colorecho "Installing enyx"
    git -C /opt/tools/ clone --depth 1 https://github.com/trickster0/Enyx
    add-aliases enyx
    add-history enyx
    add-test-command "enyx"
    add-to-list "enyx,https://github.com/trickster0/enyx,Framework for building offensive security tools."
}

function install_enum4linux-ng() {
    colorecho "Installing enum4linux-ng"
    python3 -m pipx install git+https://github.com/cddmp/enum4linux-ng
    add-history enum4linux-ng
    add-test-command "enum4linux-ng --help"
    add-to-list "enum4linux-ng,https://github.com/cddmp/enum4linux-ng,Tool for enumerating information from Windows and Samba systems."
}

function install_zerologon() {
    colorecho "Pulling CVE-2020-1472 exploit and scan scripts"
    mkdir /opt/tools/zerologon
    cd /opt/tools/zerologon
    python3 -m venv ./venv
    ./venv/bin/python3 -m pip install impacket
    git -C /opt/tools/zerologon clone --depth 1 https://github.com/SecuraBV/CVE-2020-1472 zerologon-scan
    git -C /opt/tools/zerologon clone --depth 1 https://github.com/dirkjanm/CVE-2020-1472 zerologon-exploit
    add-aliases zerologon
    add-history zerologon
    add-test-command "zerologon-scan| grep Usage"
    add-to-list "zerologon,https://github.com/SecuraBV/CVE-2020-1472,Exploit for the Zerologon vulnerability (CVE-2020-1472)."
}

function install_libmspack() {
    colorecho "Installing libmspack"
    git -C /opt/tools/ clone --depth 1 https://github.com/kyz/libmspack.git
    cd /opt/tools/libmspack/libmspack
    ./rebuild.sh
    ./configure
    make
    add-aliases libmspack
    add-history libmspack
    add-test-command "oabextract"
    add-to-list "libmspack,https://github.com/kyz/libmspack,C library for Microsoft compression formats."
}

function install_windapsearch-go() {
    colorecho "Installing Go windapsearch"
    # Install mage dependency
    git -C /opt/tools/ clone --depth 1 https://github.com/magefile/mage
    cd /opt/tools/mage
    go run bootstrap.go
    # Install windapsearch tool
    git -C /opt/tools/ clone --depth 1 https://github.com/ropnop/go-windapsearch
    cd /opt/tools/go-windapsearch
    /root/go/bin/mage build
    add-aliases windapsearch
    add-history windapsearch
    add-test-command "windapsearch --version"
    add-to-list "windapsearch-go,https://github.com/ropnop/go-windapsearch/,Active Directory enumeration tool."
}

function install_oaburl() {
    colorecho "Downloading oaburl.py"
    mkdir /opt/tools/OABUrl
    wget -O /opt/tools/OABUrl/oaburl.py "https://gist.githubusercontent.com/snovvcrash/4e76aaf2a8750922f546eed81aa51438/raw/96ec2f68a905eed4d519d9734e62edba96fd15ff/oaburl.py"
    cd /opt/tools/OABUrl/
    python3 -m venv ./venv
    ./venv/bin/python3 -m pip install requests
    add-aliases oaburl
    add-history oaburl
    add-test-command "oaburl.py --help"
    add-to-list "oaburl,https://gist.githubusercontent.com/snovvcrash/4e76aaf2a8750922f546eed81aa51438/raw/96ec2f68a905eed4d519d9734e62edba96fd15ff/oaburl.py,Find Open redirects and other vulnerabilities."
}

function install_lnkup() {
    colorecho "Installing LNKUp"
    git -C /opt/tools/ clone --depth 1 https://github.com/Plazmaz/LNKUp
    cd /opt/tools/LNKUp
    virtualenv --python=/usr/bin/python2 ./venv
    ./venv/bin/python2 -m pip install -r requirements.txt
    add-aliases lnkup
    add-history lnkup
    add-test-command "lnk-generate.py --help"
    add-to-list "lnkup,https://github.com/Plazmaz/lnkUp,This tool will allow you to generate LNK payloads. Upon rendering or being run they will exfiltrate data."
}

function install_polenum() {
    colorecho "Installing polenum"
    git -C /opt/tools/ clone --depth 1 https://github.com/Wh1t3Fox/polenum
    cd /opt/tools/polenum
    python3 -m venv ./venv/
    ./venv/bin/python3 -m pip install impacket
    add-aliases polenum
    add-history polenum
    add-test-command "polenum.py --help"
    add-to-list "polenum,https://github.com/Wh1t3Fox/polenum,Polenum is a Python script which uses the Impacket library to extract user information through the SMB protocol."
}

function install_smbmap() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing smbmap"
    python3 -m pipx install git+https://github.com/ShawnDEvans/smbmap
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
    colorecho "Installing smtp-user-enum"
    python3 -m pipx install smtp-user-enum
    add-history smtp-user-enum
    add-test-command "smtp-user-enum --help"
    add-to-list "smtp-user-enum,https://github.com/pentestmonkey/smtp-user-enum,A tool to enumerate email addresses via SMTP"
}

function install_gpp-decrypt() {
    colorecho "Installing gpp-decrypt"
    git -C /opt/tools/ clone --depth 1 https://github.com/t0thkr1s/gpp-decrypt
    cd /opt/tools/gpp-decrypt
    python3 -m venv ./venv/
    ./venv/bin/python3 -m pip install pycrypto colorama
    add-aliases gpp-decrypt
    add-history gpp-decrypt
    add-test-command "gpp-decrypt.py -f /opt/tools/gpp-decrypt/groups.xml"
    add-to-list "gpp-decrypt,https://github.com/t0thkr1s/gpp-decrypt,A tool to decrypt Group Policy Preferences passwords"
}

function install_ntlmv1-multi() {
    colorecho "Installing ntlmv1 multi tool"
    git -C /opt/tools clone --depth 1 https://github.com/evilmog/ntlmv1-multi
    add-aliases ntlmv1-multi
    add-history ntlmv1-multi
    add-test-command "ntlmv1-multi --ntlmv1 a::a:a:a:a"
    add-to-list "ntlmv1-multi,https://github.com/evilmog/ntlmv1-multi,Exploit a vulnerability in Microsoft Windows to gain system-level access."
}

function install_hashonymize() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing hashonymizer"
    python3 -m pipx install git+https://github.com/ShutdownRepo/hashonymize
    add-history hashonymize
    add-test-command "hashonymize --help"
    add-to-list "hashonymize,https://github.com/ShutdownRepo/hashonymize,This small tool is aimed at anonymizing hashes files for offline but online cracking like Google Collab for instance (see https://github.com/ShutdownRepo/google-colab-hashcat)."
}

function install_gosecretsdump() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing gosecretsdump"
    go install -v github.com/C-Sto/gosecretsdump@latest
    add-history gosecretsdump
    add-test-command "gosecretsdump -version"
    add-to-list "gosecretsdump,https://github.com/c-sto/gosecretsdump,Implements NTLMSSP network authentication protocol in Go"
}

function install_adidnsdump() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing adidnsdump"
    python3 -m pipx install git+https://github.com/dirkjanm/adidnsdump
    add-history adidnsdump
    add-test-command "adidnsdump --help"
    add-to-list "adidnsdump,https://github.com/dirkjanm/adidnsdump,Active Directory Integrated DNS dump utility"
}

function install_pygpoabuse() {
    colorecho "Installing pyGPOabuse"
    git -C /opt/tools/ clone --depth 1 https://github.com/Hackndo/pyGPOAbuse
    cd /opt/tools/pyGPOAbuse
    python3 -m venv ./venv/
    ./venv/bin/python3 -m pip install -r requirements.txt
    add-aliases pygpoabuse
    add-history pygpoabuse
    add-test-command "pygpoabuse --help"
    add-to-list "pygpoabuse,https://github.com/Hackndo/pyGPOAbuse,A tool for abusing GPO permissions to escalate privileges"
}

function install_bloodhound-import() {
    colorecho "Installing bloodhound-import"
    python3 -m pipx install bloodhound-import
    add-history bloodhound-import
    add-test-command "bloodhound-import --help"
    add-to-list "bloodhound-import,https://github.com/fox-it/BloodHound.py,Import data into BloodHound for analyzing active directory trust relationships"
}

function install_bloodhound-quickwin() {
    colorecho "Installing bloodhound-quickwin"
    git -C /opt/tools/ clone --depth 1 https://github.com/kaluche/bloodhound-quickwin
    cd /opt/tools/bloodhound-quickwin
    python3 -m venv ./venv/
    ./venv/bin/python3 -m pip install py2neo pandas prettytable
    add-aliases bloodhound-quickwin
    add-history bloodhound-quickwin
    add-test-command "bloodhound-quickwin --help"
    add-to-list "bloodhound-quickwin,https://github.com/kaluche/bloodhound-quickwin,A tool for BloodHounding on Windows machines without .NET or Powershell installed"
}

function install_ldapsearch-ad() {
    colorecho "Installing ldapsearch-ad"
    git -C /opt/tools/ clone --depth 1 https://github.com/yaap7/ldapsearch-ad
    cd /opt/tools/ldapsearch-ad
    python3 -m venv ./venv/
    ./venv/bin/python3 -m pip install -r requirements.txt
    add-aliases ldapsearch-ad
    add-history ldapsearch-ad
    add-test-command "ldapsearch-ad --version"
    add-to-list "ldapsearch-ad,https://github.com/yaap7/ldapsearch-ad,LDAP search utility with AD support"
}

function install_petitpotam() {
    colorecho "Installing PetitPotam"
    git -C /opt/tools/ clone --depth 1 https://github.com/ly4k/PetitPotam
    cd /opt/tools/PetitPotam
    python3 -m venv ./venv
    ./venv/bin/python3 -m pip install impacket
    mv /opt/tools/PetitPotam /opt/tools/PetitPotam_alt
    git -C /opt/tools/ clone --depth 1 https://github.com/topotam/PetitPotam
    cd /opt/tools/PetitPotam
    python3 -m venv ./venv
    ./venv/bin/python3 -m pip install impacket
    add-aliases petitpotam
    add-history petitpotam
    add-test-command "petitpotam.py --help"
    add-to-list "petitpotam,https://github.com/topotam/PetitPotam,Windows machine account manipulation"
}

function install_dfscoerce() {
    colorecho "Installing DfsCoerce"
    git -C /opt/tools/ clone --depth 1 https://github.com/Wh04m1001/DFSCoerce
    cd /opt/tools/DFSCoerce
    python3 -m venv ./venv
    ./venv/bin/python3 -m pip install impacket
    add-aliases dfscoerce
    add-history dfscoerce
    add-test-command "dfscoerce.py --help"
    add-to-list "dfscoerce,https://github.com/Wh04m1001/dfscoerce,DFS-R target coercion tool"
}

function install_coercer() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing Coercer"
    python3 -m pipx install git+https://github.com/p0dalirius/Coercer
    add-history coercer
    add-test-command "coercer --help"
    add-to-list "coercer,https://github.com/p0dalirius/coercer,DFS-R target coercion tool"
}

function install_pkinittools() {
    colorecho "Installing PKINITtools"
    git -C /opt/tools/ clone --depth 1 https://github.com/dirkjanm/PKINITtools
    cd /opt/tools/PKINITtools
    python3 -m venv ./venv
    ./venv/bin/python3 -m pip install -r requirements.txt
    add-aliases pkinittools
    add-history pkinittools
    add-test-command "gettgtpkinit.py --help"
    add-to-list "pkinittools,https://github.com/dirkjanm/PKINITtools,Pkinit support tools"
}

function install_pywhisker() {
    colorecho "Installing pyWhisker"
    git -C /opt/tools/ clone --depth 1 https://github.com/ShutdownRepo/pywhisker
    cd /opt/tools/pywhisker
    python3 -m venv ./venv/
    ./venv/bin/python3 -m pip install -r requirements.txt
    add-aliases pywhisker
    add-history pywhisker
    add-test-command "pywhisker.py --help"
    add-to-list "pywhisker,https://github.com/ShutdownRepo/pywhisker,PyWhisker is a Python equivalent of the original Whisker made by Elad Shamir and written in C#. This tool allows users to manipulate the msDS-KeyCredentialLink attribute of a target user/computer to obtain full control over that object. It's based on Impacket and on a Python equivalent of Michael Grafnetter's DSInternals called PyDSInternals made by podalirius."
}

function install_manspider() {
    colorecho "Installing Manspider"
    git -C /opt/tools clone --depth 1 https://github.com/blacklanternsecurity/MANSPIDER.git
    cd /opt/tools/MANSPIDER
    python3 -m venv ./venv
    ./venv/bin/python3 -m pip install .
    touch ./man_spider/lib/init.py
    sed -i "s#from .lib import#from lib import##" man_spider/manspider.py
    add-aliases manspider
    add-history manspider
    add-test-command "manspider --help"
    add-to-list "manspider,https://github.com/blacklanternsecurity/MANSPIDER,Manspider will crawl every share on every target system. If provided creds don't work it will fall back to 'guest' then to a null session."
}

function install_targetedKerberoast() {
    colorecho "Installing targetedKerberoast"
    git -C /opt/tools/ clone --depth 1 https://github.com/ShutdownRepo/targetedKerberoast
    cd /opt/tools/targetedKerberoast
    python3 -m venv ./venv/
    ./venv/bin/python3 -m pip install -r requirements.txt
    add-aliases targetedkerberoast
    add-history targetedkerberoast
    add-test-command "targetedKerberoast.py --help"
    add-to-list "targetedKerberoast,https://github.com/ShutdownRepo/targetedKerberoast,Kerberoasting against specific accounts"
}

function install_pcredz() {
    colorecho "Installing PCredz"
    fapt libpcap-dev
    git -C /opt/tools/ clone --depth 1 https://github.com/lgandx/PCredz
    cd /opt/tools/PCredz
    python3 -m venv ./venv
    ./venv/bin/python3 -m pip install Cython
    ./venv/bin/python3 -m pip install python-libpcap
    add-aliases pcredz
    add-history pcredz
    add-test-command "PCredz --help"
    add-to-list "pcredz,https://github.com/lgandx/PCredz,PowerShell credential dumper"
}

function install_pywsus() {
    colorecho "Installing pywsus"
    git -C /opt/tools/ clone --depth 1 https://github.com/GoSecure/pywsus
    cd /opt/tools/pywsus
    python3 -m venv ./venv/
    ./venv/bin/python3 -m pip install -r ./requirements.txt
    add-aliases pywsus
    add-history pywsus
    add-test-command "pywsus.py --help"
    add-to-list "pywsus,https://github.com/GoSecure/pywsus,Python implementation of a WSUS client"
}

function install_donpapi() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing DonPAPI"
    fapt swig
    python3 -m pipx install git+https://github.com/login-securite/DonPAPI
    add-history donpapi
    add-test-command "DonPAPI --help"
    add-to-list "donpapi,https://github.com/login-securite/DonPAPI,Dumping revelant information on compromised targets without AV detection"
}

function install_webclientservicescanner() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing webclientservicescanner"
    python3 -m pipx install git+https://github.com/Hackndo/WebclientServiceScanner
    add-history webclientservicescanner
    add-test-command "webclientservicescanner --help"
    add-to-list "webclientservicescanner,https://github.com/Hackndo/webclientservicescanner,Scans for web service endpoints"
}

function install_certipy() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing Certipy"
    python3 -m pipx install git+https://github.com/ly4k/Certipy
    add-history certipy
    add-test-command "certipy --version"
    add-to-list "certipy,https://github.com/ly4k/Certipy,Python tool to create and sign certificates"
}

function install_shadowcoerce() {
    colorecho "Installing ShadowCoerce PoC"
    git -C /opt/tools/ clone --depth 1 https://github.com/ShutdownRepo/ShadowCoerce
    cd /opt/tools/ShadowCoerce
    python3 -m venv ./venv
    ./venv/bin/python3 -m pip install impacket
    add-aliases shadowcoerce
    add-history shadowcoerce
    add-test-command "shadowcoerce.py --help"
    add-to-list "shadowcoerce,https://github.com/ShutdownRepo/shadowcoerce,Utility for bypassing the Windows Defender antivirus by hiding a process within a legitimate process."
}

function install_gmsadumper() {
    colorecho "Installing gMSADumper"
    git -C /opt/tools/ clone --depth 1 https://github.com/micahvandeusen/gMSADumper
    cd /opt/tools/gMSADumper
    python3 -m venv ./venv
    ./venv/bin/python3 -m pip install -r requirements.txt
    add-aliases gmsadumper
    add-history gmsadumper
    add-test-command "gMSADumper.py --help"
    add-to-list "gmsadumper,https://github.com/micahvandeusen/gMSADumper,A tool for extracting credentials and other information from a Microsoft Active Directory domain."
}

function install_pylaps() {
    colorecho "Installing pyLAPS"
    git -C /opt/tools/ clone --depth 1 https://github.com/p0dalirius/pyLAPS
    cd /opt/tools/pyLAPS
    python3 -m venv ./venv
    ./venv/bin/python3 -m pip install impacket
    add-aliases pylaps
    add-history pylaps
    add-test-command "pyLAPS.py --help"
    add-to-list "pylaps,https://github.com/p0dalirius/pylaps,Utility for enumerating and querying LDAP servers."
}

function install_finduncommonshares() {
    colorecho "Installing FindUncommonShares"
    git -C /opt/tools/ clone --depth 1 https://github.com/p0dalirius/FindUncommonShares
    cd /opt/tools/FindUncommonShares/
    python3 -m venv ./venv/
    ./venv/bin/python3 -m pip install -r requirements.txt
    add-aliases finduncommonshares
    add-history finduncommonshares
    add-test-command "FindUncommonShares.py --help"
    add-to-list "finduncommonshares,https://github.com/p0dalirius/FindUncommonShares,Script that can help identify shares that are not commonly found on a Windows system."
}

function install_ldaprelayscan() {
    colorecho "Installing LdapRelayScan"
    git -C /opt/tools/ clone --depth 1 https://github.com/zyn3rgy/LdapRelayScan
    cd /opt/tools/LdapRelayScan
    python3 -m venv ./venv/
    ./venv/bin/python3 -m pip install -r requirements.txt
    add-aliases ldaprelayscan
    add-history ldaprelayscan
    add-test-command "LdapRelayScan.py --help"
    add-to-list "ldaprelayscan,https://github.com/zyn3rgy/LdapRelayScan,Check Domain Controllers for LDAP server protections regarding the relay of NTLM authentication."
}

function install_goldencopy() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing GoldenCopy"
    python3 -m pipx install goldencopy
    add-history goldencopy
    add-test-command "goldencopy --help"
    add-to-list "goldencopy,https://github.com/0x09AL/golden_copy.git,A tool to copy data from Golden Ticket and Silver Ticket"
}

function install_crackhound() {
    colorecho "Installing CrackHound"
    git -C /opt/tools/ clone --depth 1 https://github.com/trustedsec/CrackHound
    cd /opt/tools/CrackHound
    prs="6"
    for pr in $prs; do git fetch origin pull/$pr/head:pull/$pr && git merge --strategy-option theirs --no-edit pull/$pr; done
    python3 -m venv ./venv/
    ./venv/bin/python3 -m pip install -r requirements.txt
    add-aliases crackhound
    add-history crackhound
    add-test-command "crackhound.py --help"
    add-to-list "crackhound,https://github.com/trustedsec/crackhound.git,A fast WPA/WPA2/WPA3 WiFi Handshake capture / password recovery and analysis tool"
}

function install_kerbrute() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing Kerbrute"
    go install -v github.com/ropnop/kerbrute@latest
    add-history kerbrute
    add-test-command "kerbrute --help"
    add-to-list "kerbrute,https://github.com/ropnop/kerbrute,A tool to perform Kerberos pre-auth bruteforcing"
}

function install_ldeep() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing ldeep"
    python3 -m pipx install ldeep
    add-history ldeep
    add-test-command "ldeep --help"
    add-to-list "ldeep,https://github.com/franc-pentest/ldeep,ldeep is a tool to discover hidden paths on Web servers."
}

function install_rusthound() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing RustHound"
    fapt gcc clang libclang-dev libgssapi-krb5-2 libkrb5-dev libsasl2-modules-gssapi-mit musl-tools gcc-mingw-w64-x86-64
    git -C /opt/tools/ clone --depth 1 https://github.com/OPENCYBER-FR/RustHound
    cd /opt/tools/RustHound
    # Sourcing rustup shell setup, so that rust binaries are found when installing cme
    source "$HOME/.cargo/env"
    cargo build --release
    # Clean dependencies used to build the binary
    rm -rf target/release/{deps,build}
    ln -s /opt/tools/RustHound/target/release/rusthound /opt/tools/bin/rusthound
    add-history rusthound
    add-test-command "rusthound --help"
    add-to-list "rusthound,https://github.com/OPENCYBER-FR/RustHound,BloodHound ingestor in Rust."
}

function install_certsync() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing certsync"
    python3 -m pipx install git+https://github.com/zblurx/certsync
    add-history certsync
    add-test-command "certsync --help"
    add-to-list "certsync,https://github.com/zblurx/certsync,certsync is a tool that helps you synchronize certificates between two directories."
}

function install_keepwn() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing KeePwn"
    python3 -m pipx install git+https://github.com/Orange-Cyberdefense/KeePwn
    add-history keepwn
    add-test-command "KeePwn --help"
    add-to-list "KeePwn,https://github.com/Orange-Cyberdefense/KeePwn,KeePwn is a tool that extracts passwords from KeePass 1.x and 2.x databases."
}

function install_pre2k() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing pre2k"
    python3 -m pipx install git+https://github.com/garrettfoster13/pre2k
    add-history pre2k
    add-test-command "pre2k --help"
    add-to-list "pre2k,https://github.com/garrettfoster13/pre2k,pre2k is a tool to check if a Windows domain has any pre-2000 Windows 2000 logon names still in use."
}

function install_msprobe() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing msprobe"
    python3 -m pipx install git+https://github.com/puzzlepeaches/msprobe
    add-history msprobe
    add-test-command "msprobe --help"
    add-to-list "msprobe,https://github.com/puzzlepeaches/msprobe,msprobe is a tool to identify Microsoft Windows hosts and servers that are running certain services."
}

function install_masky() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing masky"
    python3 -m pipx install git+https://github.com/Z4kSec/Masky
    add-history masky
    add-test-command "masky --help"
    add-to-list "masky,https://github.com/Z4kSec/masky,masky is a tool to mask sensitive data / such as credit card numbers / in logs and other files."
}

function install_roastinthemiddle() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing roastinthemiddle"
    python3 -m pipx install git+https://github.com/Tw1sm/RITM
    add-history roastinthemiddle
    add-test-command "roastinthemiddle --help"
    add-to-list "roastinthemiddle,https://github.com/Tw1sm/RITM,RoastInTheMiddle is a tool to intercept and relay NTLM authentication requests."
}

function install_PassTheCert() {
    colorecho "Installing PassTheCert"
    git -C /opt/tools/ clone --depth 1 https://github.com/AlmondOffSec/PassTheCert
    cd /opt/tools/PassTheCert/Python/
    python3 -m venv ./venv
    ./venv/bin/python3 -m pip install impacket
    add-aliases PassTheCert
    add-history PassTheCert
    add-test-command "passthecert.py --help"
    add-to-list "PassTheCert,https://github.com/AlmondOffSec/PassTheCert,PassTheCert is a tool to extract Active Directory user password hashes from a domain controller's local certificate store."
}

function install_bqm() {
    colorecho "Installing BQM"
    rvm use 3.0.0@bqm --create
    gem install bqm --no-wrapper
    rvm use 3.0.0@default
    add-aliases bqm
    add-history bqm
    add-test-command "bqm --help"
    add-to-list "bqm,https://github.com/Acceis/bqm,Tool to deduplicate custom BloudHound queries from different datasets and merge them in one file."
}

function install_neo4j() {
    colorecho "Installing neo4j"
    wget -O - https://debian.neo4j.com/neotechnology.gpg.key | apt-key add -
    # TODO: temporary fix => rollback to 4.4 stable until perf issue is fix on neo4j 5.x
    #echo 'deb https://debian.neo4j.com stable latest' | tee /etc/apt/sources.list.d/neo4j.list
    echo 'deb https://debian.neo4j.com stable 4.4' | tee /etc/apt/sources.list.d/neo4j.list
    apt update
    apt install -y --no-install-recommends gnupg libgtk2.0-bin libcanberra-gtk-module libx11-xcb1 libva-glx2 libgl1-mesa-glx libgl1-mesa-dri libgconf-2-4 libasound2 libxss1
    fapt neo4j
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
    cd /opt/tools/noPac
    python3 -m venv ./venv
    ./venv/bin/python3 -m pip install -r requirements.txt
    add-aliases noPac
    add-history noPac
    add-test-command "noPac --help"
    add-to-list "noPac,https://github.com/Ridter/noPac,Exploiting CVE-2021-42278 and CVE-2021-42287 to impersonate DA from standard domain user."
}
# Package dedicated to internal Active Directory tools
function package_ad() {
    install_ad_apt_tools
    set_go_env
    set_ruby_env
    install_responder               # LLMNR, NBT-NS and MDNS poisoner
    install_ldapdomaindump
    install_crackmapexec            # Network scanner
    install_sprayhound              # Password spraying tool
    install_smartbrute              # Password spraying tool
    install_bloodhound-py           # AD cartographer
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
}

function package_ad_configure() {
    configure_responder
    configure_crackmapexec
    configure_bloodhound
    configure_impacket
    configure_krbrelayx
}
