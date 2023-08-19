#!/bin/bash
# Author: The Exegol Project

source common.sh

function install_wifi_apt_tools() {
    colorecho "Installing wifi apt tools"
    fapt aircrack-ng reaver bully cowpatty
  
    add-aliases aircrack-ng

    add-history aircrack-ng
    add-history reaver
    add-history bully
    add-history cowpatty
  
    add-test-command "aircrack-ng --help"                                                # WiFi security auditing tools suite
    add-test-command "reaver --help; reaver --help |& grep 'Tactical Network Solutions'" # Brute force attack against Wifi Protected Setup
    add-test-command "bully --version"                                                   # WPS brute force attack
    add-test-command "cowpatty -V"                                                       # WPA2-PSK Cracking
  
    add-to-list "aircrack-ng,https://www.aircrack-ng.org,A suite of tools for wireless penetration testing"
    add-to-list "reaver,https://github.com/t6x/reaver-wps-fork-t6x,reaver is a tool for brute-forcing WPS (Wireless Protected Setup) PINs."
    add-to-list "bully,https://github.com/aanarchyy/bully,bully is a tool for brute-forcing WPS (Wireless Protected Setup) PINs."
    add-to-list "cowpatty,https://github.com/joswr1ght/cowpatty,cowpatty is a tool for offline dictionary attacks against WPA-PSK (Pre-Shared Key) networks."
}

function install_pyrit() {
    colorecho "Installing pyrit"
    git -C /opt/tools clone --depth 1 https://github.com/JPaulMora/Pyrit
    cd /opt/tools/Pyrit
    fapt libpq-dev
    virtualenv -p /usr/bin/python2 ./venv
    ./venv/bin/python2 -m pip install psycopg2-binary scapy
    # https://github.com/JPaulMora/Pyrit/issues/591
    cp -v /root/sources/assets/patches/undefined-symbol-aesni-key.patch undefined-symbol-aesni-key.patch
    git apply --verbose undefined-symbol-aesni-key.patch
    source ./venv/bin/activate
    python2 setup.py clean
    python2 setup.py build
    python2 setup.py install
    deactivate
    add-aliases pyrit
    add-history pyrit
    add-test-command "pyrit help"
    add-to-list "pyrit,https://github.com/JPaulMora/Pyrit,Python-based WPA/WPA2-PSK attack tool."
}

function install_wifite2() {
    colorecho "Installing wifite2"
    git -C /opt/tools/ clone --depth 1 https://github.com/derv82/wifite2.git
    cd /opt/tools/wifite2
    python3 -m venv ./venv
    ./venv/bin/python3 setup.py install
    add-aliases wifite
    add-history wifite
    add-test-command "wifite --help"
    add-to-list "wifite2,https://github.com/derv82/wifite2,Script for auditing wireless networks."
}

function install_bettercap() {
    colorecho "Installing Bettercap"
    fapt libpcap-dev libusb-1.0-0-dev libnetfilter-queue-dev
    go install -v github.com/bettercap/bettercap@latest
    /root/go/bin/bettercap -eval "caplets.update; ui.update; q"
    sed -i 's/set api.rest.username user/set api.rest.username bettercap/g' /usr/local/share/bettercap/caplets/http-ui.cap
    sed -i 's/set api.rest.password pass/set api.rest.password exegol4thewin/g' /usr/local/share/bettercap/caplets/http-ui.cap
    sed -i 's/set api.rest.username user/set api.rest.username bettercap/g' /usr/local/share/bettercap/caplets/https-ui.cap
    sed -i 's/set api.rest.password pass/set api.rest.password exegol4thewin/g' /usr/local/share/bettercap/caplets/https-ui.cap
    add-aliases bettercap
    add-history bettercap
    add-test-command "bettercap --version"
    add-to-list "bettercap,https://github.com/bettercap/bettercap,The Swiss Army knife for 802.11 / BLE / and Ethernet networks reconnaissance and MITM attacks."
}

function install_hcxtools() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing hcxtools"
    fapt libcurl4 libcurl4-openssl-dev libssl-dev openssl pkg-config
    # git -C /opt/tools/ clone --depth 1 https://github.com/ZerBea/hcxtools  # Depth 1 must be removed because of the git checkout
    git -C /opt/tools/ clone https://github.com/ZerBea/hcxtools
    cd /opt/tools/hcxtools
    # Checking out to specific commit is a temporary fix to the project no compiling anymore.
    # FIXME whenever possible to stay up to date with project (https://github.com/ZerBea/hcxtools/issues/233) => Need to upgrade to the Debian 12 release
    git checkout 5937d2ad9d021f3b5e2edd55d79439b8485d3222
    make install PREFIX=/opt/tools
    ln -s /opt/tools/bin/hcxpcapngtool /opt/tools/bin/hcxpcaptool
    add-history hcxtools
    add-test-command "hcxpcapngtool --version"
    add-test-command "hcxhashtool --version"
    add-to-list "hcxtools,https://github.com/ZerBea/hcxtools,Tools for capturing and analyzing packets from WLAN devices."
}

function install_hcxdumptool() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing hcxdumptool"
    fapt libcurl4-openssl-dev libssl-dev
    # git -C /opt/tools/ clone --depth 1 https://github.com/ZerBea/hcxdumptool  # Depth 1 must be removed because of the git checkout
    git -C /opt/tools/ clone https://github.com/ZerBea/hcxdumptool
    cd /opt/tools/hcxdumptool
    # Checking out to specific commit is a temporary fix to the project no compiling anymore.
    # FIXME whenever possible to stay up to date with project (https://github.com/ZerBea/hcxdumptool/issues/232) => upgrade to debian 12
    git checkout 56d078de4d6f5cef07b378707ab478fde03168c0
    make install PREFIX=/opt/tools
    add-history hcxdumptool
    add-test-command "hcxdumptool --version"
    add-to-list "hcxdumptool,https://github.com/ZerBea/hcxdumptool,Small tool to capture packets from wlan devices."
}

# Package dedicated to wifi pentest tools
function package_wifi() {
    set_go_env
    set_ruby_env
    install_wifi_apt_tools
    install_pyrit                   # Databases of pre-computed WPA/WPA2-PSK authentication phase
    install_wifite2                 # Retrieving password of a wireless access point (router)
    # install_hostapd-wpe           # Modified hostapd to facilitate AP impersonation attacks, FIXME broken install, need official release of hostapd-2.6.tar.gz
    install_bettercap               # MiTM tool
    install_hcxtools                # Tools for PMKID and other wifi attacks
    install_hcxdumptool             # Small tool to capture packets from wlan devices
}
