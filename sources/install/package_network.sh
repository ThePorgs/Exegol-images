#!/bin/bash
# Author: The Exegol Project

source common.sh

function install_network_apt_tools() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing network apt tools"
    export DEBIAN_FRONTEND=noninteractive
    fapt wireshark tshark hping3 masscan netdiscover tcpdump iptables traceroute dns2tcp freerdp2-x11 \
    rdesktop xtightvncviewer hydra mariadb-client redis-tools

    add-history wireshark
    add-history tshark
    add-history hping3
    add-history masscan
    add-history netdiscover
    add-history tcpdump
    add-history iptables
    add-history traceroute
    add-history rdesktop
    add-history hydra
    add-history xfreerdp

    add-test-command "wireshark --help"                             # Wireshark packet sniffer
    add-test-command "tshark --version"                             # Tshark packet sniffer
    add-test-command "hping3 --version"                             # Discovery tool
    add-test-command "masscan --version|& grep 'Masscan version'"   # Port scanner
    add-test-command "netdiscover -h |& grep 'Usage: netdiscover'"  # Active/passive address reconnaissance tool
    add-test-command "tcpdump --version"                            # Capture TCP traffic
    add-test-command "iptables --version"                           # iptables for the win
    add-test-command "traceroute --help"                            # ping ping
    add-test-command "dns2tcpc|& grep 'Usage : dns2tcpc'"           # TCP tunnel over DNS
    add-test-command "which xfreerdp"
    add-test-command "rdesktop|& grep 'Usage: rdesktop'"
    add-test-command "which xtightvncviewer"
    add-test-command "hydra -h |& grep 'more command line options'" # Login scanner
    add-test-command "mariadb --version"                            # Mariadb client
    add-test-command "redis-cli --version"                          # Redis protocol

    add-to-list "wireshark,https://github.com/wireshark/wireshark,Wireshark is a network protocol analyzer that lets you see what’s happening on your network at a microscopic level."
    add-to-list "tshark,https://github.com/wireshark/wireshark,TShark is a terminal version of Wireshark."
    add-to-list "hping3,https://github.com/antirez/hping,A network tool able to send custom TCP/IP packets"
    add-to-list "masscan,https://github.com/robertdavidgraham/masscan,Masscan is an Internet-scale port scanner"
    add-to-list "netdiscover,https://github.com/netdiscover-scanner/netdiscover,netdiscover is an active/passive address reconnaissance tool"
    add-to-list "tcpdump,https://github.com/the-tcpdump-group/tcpdump,a powerful command-line packet analyzer for Unix-like systems"
    add-to-list "iptables,https://linux.die.net/man/8/iptables,Userspace command line tool for configuring kernel firewall"
    add-to-list "traceroute,https://github.com/iputils/iputils,Traceroute is a command which can show you the path a packet of information takes from your computer to one you specify."
    add-to-list "dns2tcp,https://github.com/alex-sector/dns2tcp,dns2tcp is a tool for relaying TCP connections over DNS."
    add-to-list "freerdp2-x11,https://github.com/FreeRDP/FreeRDP,FreeRDP is a free implementation of the Remote Desktop Protocol (RDP) released under the Apache license."
    add-to-list "rdesktop,https://github.com/rdesktop/rdesktop,rdesktop is a client for Remote Desktop Protocol (RDP) used in a number of Microsoft products including Windows NT Terminal Server / Windows 2000 Server / Windows XP and Windows 2003 Server."
    add-to-list "xtightvncviewer,https://www.commandlinux.com/man-page/man1/xtightvncviewer.1.html,xtightvncviewer is an open source VNC client software."
    add-to-list "hydra,https://github.com/vanhauser-thc/thc-hydra,Hydra is a parallelized login cracker which supports numerous protocols to attack."
    add-to-list "mariadb-client,https://github.com/MariaDB/server,MariaDB is a community-developed fork of the MySQL relational database management system. The mariadb-client package includes command-line utilities for interacting with a MariaDB server."
    add-to-list "redis-tools,https://github.com/antirez/redis-tools,redis-tools is a collection of Redis client utilities including redis-cli and redis-benchmark."
}

function install_proxychains() {
    colorecho "Installing proxychains"
    git -C /opt/tools/ clone --depth 1 https://github.com/rofl0r/proxychains-ng
    cd /opt/tools/proxychains-ng || exit
    ./configure --prefix=/usr --sysconfdir=/etc
    make
    make install
    # Add proxyresolv to PATH (needed with 'proxy_dns_old' config)
    ln -s /opt/tools/proxychains-ng/src/proxyresolv /usr/bin/proxyresolv
    make install-config
    cp -v /root/sources/assets/proxychains/proxychains.conf /etc/proxychains.conf
    add-aliases proxychains
    add-history proxychains
    add-test-command "proxychains4 echo test"
    add-test-command "proxyresolv"
    add-to-list "proxychains,https://github.com/rofl0r/proxychains,Proxy chains - redirect connections through proxy servers."
}

function install_remmina() {
    colorecho "Installing remmina"
    # CODE-CHECK-WHITELIST=add-aliases,add-history
    fapt remmina remmina-plugin-rdp remmina-plugin-secret
    # remmina-plugin-spice need build ?
    # https://gitlab.com/Remmina/Remmina/-/wikis/Compilation/Compile-on-Debian-10-Buster

    # Create default remmina config
    mkdir -p /root/.config/remmina
    # Use the same keymap for RDP than the local client
    echo "[remmina_pref]
rdp_use_client_keymap=1" > /root/.config/remmina/remmina.pref

    add-test-command "remmina --help"
    add-to-list "remmina,https://github.com/FreeRDP/Remmina,Remote desktop client."
}

function install_nmap() {
    colorecho "Installing nmap"
    # echo 'deb http://deb.debian.org/debian bullseye-backports main' > /etc/apt/sources.list.d/backports.list
    # nmap in main repo is a latest version
    # apt-get update
    fapt nmap
    add-aliases nmap
    add-history nmap
    add-test-command "nmap --version"
    add-to-list "nmap,https://nmap.org,The Network Mapper - a powerful network discovery and security auditing tool"
}

function install_nmap-parse-output() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing nmap-parse-output"
    fapt xsltproc
    git -C /opt/tools/ clone --depth 1 https://github.com/ernw/nmap-parse-output
    ln -s /opt/tools/nmap-parse-output/nmap-parse-output /opt/tools/bin/nmap-parse-output
    add-history nmap-parse-output
    # nmap-parse-output always exits with 1 if no argument is passed
    add-test-command "nmap-parse-output |& grep -E '^\[v.+\]'"
    add-to-list "nmap-parse-ouptut,https://github.com/ernw/nmap-parse-output,Converts/manipulates/extracts data from a Nmap scan output."
}

function install_autorecon() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing autorecon"
    git -C /opt/tools/ clone --depth 1 https://gitlab.com/kalilinux/packages/oscanner.git
    ln -sv /opt/tools/oscanner/debian/helper-script/oscanner /usr/bin/oscanner
    git -C /opt/tools clone --depth 1 https://gitlab.com/kalilinux/packages/tnscmd10g.git
    ln -sv /opt/tools/tnscmd10g/tnscmd10g /usr/bin/tnscmd10g
    fapt dnsrecon wkhtmltopdf
    pipx install --system-site-packages git+https://github.com/Tib3rius/AutoRecon
    add-history autorecon
    # test below cannot work because test runner cannot have a valid display
    # add-test-command "autorecon --version"
    add-test-command "which autorecon"
    add-to-list "autorecon,https://github.com/Tib3rius/AutoRecon,Multi-threaded network reconnaissance tool which performs automated enumeration of services."
}

function install_dnschef() {
    colorecho "Installing DNSChef"
    git -C /opt/tools/ clone --depth 1 https://github.com/iphelix/dnschef
    cd /opt/tools/dnschef || exit
    python3 -m venv --system-site-packages ./venv
    source ./venv/bin/activate
    pip3 install -r requirements.txt
    deactivate
    add-aliases dnschef
    add-history dnschef
    add-test-command "dnschef.py --help"
    add-to-list "dnschef,https://github.com/iphelix/dnschef,Tool for DNS MITM attacks"
}

function install_divideandscan() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing DivideAndScan"
    pipx install --system-site-packages git+https://github.com/snovvcrash/DivideAndScan
    add-history divideandscan
    add-test-command "divideandscan --help"
    add-to-list "divideandscan,https://github.com/snovvcrash/divideandscan,Advanced subdomain scanner"
}

function install_chisel() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing chisel"
    go install -v github.com/jpillora/chisel@latest
    asdf reshim golang
    # TODO: add windows pre-compiled binaries in /opt/ressources/windows ?
    add-history chisel
    add-test-command "chisel --help"
    add-to-list "chisel,https://github.com/jpillora/chisel,Go based TCP tunnel with authentication and encryption support"
}

function install_sshuttle() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing sshtuttle"
    pipx install --system-site-packages git+https://github.com/sshuttle/sshuttle.git
    add-history sshuttle
    add-test-command "sshuttle --version"
    add-to-list "sshuttle,https://github.com/sshuttle/sshuttle,Transparent proxy server that tunnels traffic through an SSH server"
}

function install_eaphammer() {
    colorecho "Installing eaphammer"
    git -C /opt/tools clone --depth 1 https://github.com/s0lst1c3/eaphammer.git
    cd /opt/tools/eaphammer || exit
    fapt apache2 dnsmasq libssl-dev libnfnetlink-dev libnl-3-dev libnl-genl-3-dev libcurl4-openssl-dev zlib1g-dev libpcap-dev
    python3 -m venv --system-site-packages ./venv
    source ./venv/bin/activate
    pip3 install -r pip.req
    deactivate
    add-aliases eaphammer
    add-history eaphammer
    add-test-command "eaphammer -h"
    add-to-list "eaphammer,https://github.com/s0lst1c3/eaphammer,EAPHammer is a toolkit for performing targeted evil twin attacks against WPA2-Enterprise networks."
}

function install_fierce() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing fierce"
    pipx install --system-site-packages git+https://github.com/mschwager/fierce
    add-history fierce
    add-test-command "fierce --help"
    add-to-list "fierce,https://github.com/mschwager/fierce,A DNS reconnaissance tool for locating non-contiguous IP space"
}

function install_dnsx() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing dnsx"
    go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
    asdf reshim golang
    add-history dnsx
    add-test-command "dnsx --help"
    add-to-list "dnsx,https://github.com/projectdiscovery/dnsx,A tool for DNS reconnaissance that can help identify subdomains and other related domains."
}

function install_shuffledns() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing shuffledns"
    go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest
    asdf reshim golang
    add-history shuffledns
    add-test-command "shuffledns --help"
    add-to-list "shuffledns,https://github.com/projectdiscovery/shuffledns,A fast and customizable DNS resolver that can be used for subdomain enumeration and other tasks."
}

function install_tailscale() {
    colorecho "Installing tailscale"
    wget -O /tmp/tailscale.gpg.armored https://pkgs.tailscale.com/stable/ubuntu/focal.gpg
    # doing wget, gpg, chmod, to avoid the warning of apt-key being deprecated
    gpg --dearmor --output /etc/apt/trusted.gpg.d/tailscale.gpg /tmp/tailscale.gpg.armored
    chmod 644 /etc/apt/trusted.gpg.d/tailscale.gpg
    wget -O /etc/apt/sources.list.d/tailscale.list https://pkgs.tailscale.com/stable/ubuntu/focal.list
    apt-get update
    fapt tailscale
    add-aliases tailscale
    add-history tailscale
    add-test-command "tailscale --help"
    add-to-list "tailscale,https://github.com/tailscale/tailscale,A secure and easy-to-use VPN alternative that is designed for teams and businesses."
}

function install_ligolo-ng() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing ligolo-ng"
    git -C /opt/tools clone --depth 1 https://github.com/nicocha30/ligolo-ng.git
    cd /opt/tools/ligolo-ng || exit
    go build -o agent cmd/agent/main.go
    go build -o proxy cmd/proxy/main.go
    ln -s /opt/tools/ligolo-ng/proxy /opt/tools/bin/ligolo-ng
    add-history ligolo-ng
    add-test-command "ligolo-ng --help"
    add-to-list "ligolo-ng,https://github.com/nicocha30/ligolo-ng,An advanced yet simple tunneling tool that uses a TUN interface."
}

function install_rustscan() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing RustScan"
    git -C /opt/tools/ clone --depth 1 https://github.com/RustScan/RustScan.git
    cd /opt/tools/RustScan || exit
    # Sourcing rustup shell setup, so that rust binaries are found when installing cme
    source "$HOME/.cargo/env"
    cargo build --release
    # Clean dependencies used to build the binary
    rm -rf target/release/{deps,build,.fingerprint}
    ln -s /opt/tools/RustScan/target/release/rustscan /opt/tools/bin/rustscan
    add-history rustscan
    add-test-command "rustscan --help"
    add-to-list "rustscan,https://github.com/RustScan/RustScan,The Modern Port Scanner"
}

function install_legba() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing legba"
    fapt libsmbclient-dev libsmbclient
    git -C /opt/tools/ clone --depth 1 https://github.com/evilsocket/legba
    cd /opt/tools/legba || exit
    cargo build --release
    # Clean dependencies used to build the binary
    rm -rf target/release/{deps,build,.fingerprint}
    ln -s /opt/tools/legba/target/release/legba /opt/tools/bin/legba
    add-history legba
    add-test-command "legba --help"
    add-to-list "legba,https://github.com/evilsocket/legba,a multiprotocol credentials bruteforcer / password sprayer and enumerator built with Rust"
}

function install_ssh-audit() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing ssh-audit"
    pipx install --system-site-packages git+https://github.com/jtesta/ssh-audit
    add-history ssh-audit
    add-test-command "ssh-audit --help"
    add-to-list "ssh-audit,https://github.com/jtesta/ssh-audit,ssh-audit is a tool to test SSH server configuration for best practices."
}

# Package dedicated to network pentest tools
function package_network() {
    set_env
    local start_time
    local end_time
    start_time=$(date +%s)
    install_network_apt_tools
    install_proxychains             # Network tool
    install_nmap                    # Port scanner
    install_nmap-parse-output       # Parse nmap XML files
    install_autorecon               # External recon tool
    install_dnschef                 # Python DNS server
    install_divideandscan           # Python project to automate port scanning routine
    install_chisel                  # Fast TCP/UDP tunnel over HTTP
    install_sshuttle                # Transparent proxy over SSH
    install_eaphammer               # EAPHammer is a toolkit for performing targeted evil twin attacks against WPA2-Enterprise networks.
    install_fierce
    # install_odat                  # Oracle Database Attacking Tool, FIXME
    install_dnsx                    # Fast and multi-purpose DNS toolkit
    install_shuffledns              # Wrapper around massdns to enumerate valid subdomains
    install_tailscale               # Zero config VPN for building secure networks
    install_ligolo-ng               # Tunneling tool that uses a TUN interface
    install_rustscan
    install_legba                   # Login Scanner
    install_ssh-audit               # SSH server audit
    end_time=$(date +%s)
    local elapsed_time=$((end_time - start_time))
    colorecho "Package network completed in $elapsed_time seconds."
}
