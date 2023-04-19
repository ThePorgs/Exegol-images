#!/bin/bash
# Author: The Exegol Project

source common.sh

# Package dedicated to network pentest tools
function package_network() {
    set_go_env
    install_network_apt_tools
    install_proxychains             # Network tool
    # install_wireshark_sources     # Install Wireshark from sources
    install_nmap                    # Port scanner
    install_autorecon               # External recon tool
    install_dnschef                 # Python DNS server
    install_divideandscan           # Python project to automate port scanning routine
    install_chisel                  # Fast TCP/UDP tunnel over HTTP
    install_sshuttle                # Transparent proxy over SSH
    # install_eaphammer             # FIXME
    install_fierce
    # install_odat                  # Oracle Database Attacking Tool, FIXME
    install_dnsx                    # Fast and multi-purpose DNS toolkit
    install_shuffledns              # Wrapper around massdns to enumerate valid subdomains
    install_tailscale               # Zero config VPN for building secure networks
    # install_ligolo-ng              # Tunneling tool that uses a TUN interface, FIXME: https://github.com/nicocha30/ligolo-ng/issues/32
}

function install_network_apt_tools() {
    export DEBIAN_FRONTEND=noninteractive
    fapt wireshark tshark hping3 masscan netdiscover tcpdump iptables traceroute dns2tcp freerdp2-x11 \
    rdesktop xtightvncviewer ssh-audit hydra mariadb-client redis-tools

    add-history masscan
    add-history netdiscover
    add-history xfreerdp

    add-test-command "wireshark --help" # Wireshark packet sniffer
    add-test-command "tshark --version" # Tshark packet sniffer
    add-test-command "hping3 --version" # Discovery tool
    add-test-command "masscan --help|& grep 'Masscan version'" # Port scanner
    add-test-command "netdiscover -h |& grep 'Usage: netdiscover'" # Active/passive address reconnaissance tool
    add-test-command "tcpdump --version" # Capture TCP traffic
    add-test-command "iptables --version" # iptables for the win
    add-test-command "traceroute --help" # ping ping
    add-test-command "dns2tcpc|& grep 'Usage : dns2tcpc'" # TCP tunnel over DNS
    add-test-command "which xfreerdp"
    add-test-command "rdesktop|& grep 'Usage: rdesktop'"
    add-test-command "which xtightvncviewer"
    add-test-command "ssh-audit --help |& grep 'verbose output'" # SSH server audit
    add-test-command "hydra -h |& grep 'more command line options'" # Login scanner
    add-test-command "mariadb --version" # Mariadb client
    add-test-command "redis-cli --version" # Redis protocol

    add-to-list "wireshark,https://github.com/wireshark/wireshark,Wireshark is a network protocol analyzer that lets you see what’s happening on your network at a microscopic level."
    add-to-list "tshark,https://github.com/wireshark/wireshark,TShark is a terminal version of Wireshark."
    add-to-list "hping3,https://github.com/antirez/hping,A network tool able to send custom TCP/IP packets"
    add-to-list "masscan,https://github.com/robertdavidgraham/masscan,Masscan is an Internet-scale port scanner"
    add-to-list "netdiscover,https://github.com/netdiscover-scanner/netdiscover is an active/passive address reconnaissance tool"
    add-to-list "tcpdump,https://github.com/the-tcpdump-group/tcpdump,a powerful command-line packet analyzer for Unix-like systems"
    add-to-list "iptables,https://linux.die.net/man/8/iptables,Userspace command line tool for configuring kernel firewall"
    add-to-list "traceroute,https://github.com/iputils/iputils,Traceroute is a command which can show you the path a packet of information takes from your computer to one you specify."
    add-to-list "dns2tcp,https://github.com/alex-sector/dns2tcp,dns2tcp is a tool for relaying TCP connections over DNS."
    add-to-list "freerdp2-x11,https://github.com/FreeRDP/FreeRDP,FreeRDP is a free implementation of the Remote Desktop Protocol (RDP), released under the Apache license."
    add-to-list "rdesktop,https://github.com/rdesktop/rdesktop,rdesktop is a client for Remote Desktop Protocol (RDP), used in a number of Microsoft products including Windows NT Terminal Server, Windows 2000 Server, Windows XP and Windows 2003 Server."
    add-to-list "xtightvncviewer,https://www.commandlinux.com/man-page/man1/xtightvncviewer.1.html,xtightvncviewer is an open source VNC client software."
    add-to-list "ssh-audit,https://github.com/arthepsy/ssh-audit,ssh-audit is a tool to test SSH server configuration for best practices."
    add-to-list "hydra,https://github.com/vanhauser-thc/thc-hydra,Hydra is a parallelized login cracker which supports numerous protocols to attack."
    add-to-list "mariadb-client,https://github.com/MariaDB/server,MariaDB is a community-developed fork of the MySQL relational database management system. The mariadb-client package includes command-line utilities for interacting with a MariaDB server."
    add-to-list "redis-tools,https://github.com/antirez/redis-tools,redis-tools is a collection of Redis client utilities, including redis-cli and redis-benchmark."
}

function install_proxychains() {
    colorecho "Installing proxychains"
    git -C /opt/tools/ clone --depth=1 https://github.com/rofl0r/proxychains-ng
    cd /opt/tools/proxychains-ng
    ./configure --prefix=/usr --sysconfdir=/etc
    make
    make install
    # Add proxyresolv to PATH (needed with 'proxy_dns_old' config)
    ln -s /opt/tools/proxychains-ng/src/proxyresolv /usr/bin/proxyresolv
    make install-config
    cp -v /root/sources/assets/proxychains/proxychains.conf /etc/proxychains.conf
    add-aliases proxychains
    add-test-command "proxychains4 echo test"
    add-test-command "proxyresolv"
    add-to-list "proxychains,https://github.com/rofl0r/proxychains,Proxy chains - redirect connections through proxy servers."
}

function install_nmap() {
    colorecho "Installing nmap"
    echo 'deb http://deb.debian.org/debian bullseye-backports main' > /etc/apt/sources.list.d/backports.list
    apt-get update
    fapt nmap/bullseye-backports
    add-aliases nmap
    add-history nmap
    add-test-command "nmap --version"
    add-to-list "nmap,https://nmap.org,The Network Mapper - a powerful network discovery and security auditing tool"
}

function install_autorecon() {
    colorecho "Installing autorecon"
    fapt wkhtmltopdf
    python3 -m pipx install git+https://github.com/Tib3rius/AutoRecon
    add-history autorecon
    # test below cannot work because test runner cannot have a valid display
    # add-test-command "autorecon --version"
    add-test-command "which autorecon"
    add-to-list "autorecon,https://github.com/Tib3rius/AutoRecon,Multi-threaded network reconnaissance tool which performs automated enumeration of services."
}

function install_dnschef() {
    colorecho "Installing DNSChef"
    git -C /opt/tools/ clone --depth=1 https://github.com/iphelix/dnschef
    cd /opt/tools/dnschef
    python3 -m venv ./venv
    ./venv/bin/python3 -m pip install -r requirements.txt
    add-aliases dnschef
    add-test-command "dnschef --help"
    add-to-list "dnschef,https://github.com/iphelix/dnschef,Tool for DNS MITM attacks"
}

function install_divideandscan() {
    colorecho "Installing DivideAndScan"
    python3 -m pipx install git+https://github.com/snovvcrash/DivideAndScan
    add-history divideandscan
    add-test-command "divideandscan --help"
    add-to-list "divideandscan,https://github.com/snovvcrash/divideandscan,Advanced subdomain scanner"
}

function install_chisel() {
    colorecho "Installing chisel"
    go install -v github.com/jpillora/chisel@latest
    # TODO: add windows pre-compiled binaries in /opt/ressources/windows ?
    add-test-command "chisel --help"
    add-to-list "chisel,https://github.com/jpillora/chisel,Go based TCP tunnel, with authentication and encryption support"
}

function install_sshuttle() {
    colorecho "Installing sshtuttle"
    python3 -m pipx install git+https://github.com/sshuttle/sshuttle.git
    add-test-command "sshuttle --version"
    add-to-list "sshuttle,https://github.com/sshuttle/sshuttle,Transparent proxy server that tunnels traffic through an SSH server"
}

function install_fierce() {
    colorecho "Installing fierce"
    python3 -m pipx install git+https://github.com/mschwager/fierce
    add-history fierce
    add-test-command "fierce --help"
    add-to-list "fierce,https://github.com/mschwager/fierce,A DNS reconnaissance tool for locating non-contiguous IP space"
}

function install_dnsx() {
    colorecho "Installing dnsx"
    go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
    add-history dnsx
    add-test-command "dnsx --help"
    add-to-list "dnsx,https://github.com/projectdiscovery/dnsx,A tool for DNS reconnaissance that can help identify subdomains and other related domains."
}

function install_shuffledns() {
    colorecho "Installing shuffledns"
    go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest
    add-history shuffledns
    add-test-command "shuffledns --help"
    add-to-list "shuffledns,https://github.com/projectdiscovery/shuffledns,A fast and customizable DNS resolver that can be used for subdomain enumeration and other tasks."
}

function install_tailscale() {
    curl -fsSL https://pkgs.tailscale.com/stable/ubuntu/focal.gpg | sudo apt-key add -
    curl -fsSL https://pkgs.tailscale.com/stable/ubuntu/focal.list | sudo tee /etc/apt/sources.list.d/tailscale.list
    apt-get update
    fapt tailscale
    add-aliases tailscale
    add-history tailscale
    add-test-command "tailscale --help"
    add-to-list "tailscale,https://github.com/tailscale/tailscale,A secure and easy-to-use VPN alternative that is designed for teams and businesses."
}
