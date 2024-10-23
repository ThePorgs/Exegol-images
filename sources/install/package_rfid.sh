#!/bin/bash
# Author: The Exegol Project

source common.sh

function install_rfid_apt_tools() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing rfid apt tools"
    fapt libusb-dev autoconf nfct pcsc-tools pcscd libpcsclite-dev libpcsclite1 libnfc-dev libnfc-bin mfcuk
    
    add-history libnfc
    add-history mfcuk

    add-test-command "dpkg -l libusb-dev | grep 'libusb-dev'"
    add-test-command "autoconf --version"
    add-test-command "nfct --help |& grep 'nfct command'"
    add-test-command "pcsc_scan -V"
    add-test-command "nfc-scan-device -h"                   # NFC library
    add-test-command "mfcuk -i whatever"                    # Tool for Darkside attack on Mifare Classic

    add-to-list "libusb-dev,https://github.com/libusb/libusb,Library for USB device access"
    add-to-list "autoconf,https://www.gnu.org/software/autoconf/autoconf.html,Tool for producing shell scripts to configure source code packages"
    add-to-list "nfct,https://github.com/grundid/nfctools,Tool for Near Field Communication (NFC) devices"
    add-to-list "pcsc,https://pcsclite.apdu.fr/,Middleware for smart card readers"
    add-to-list "libnfc,https://github.com/grundid/nfctools,Library for Near Field Communication (NFC) devices"
    add-to-list "mfcuk,https://github.com/nfc-tools/mfcuk,Implementation of an attack on Mifare Classic and Plus RFID cards"
}

function install_mfoc() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing mfoc"
    git -C /opt/tools/ clone --depth 1 https://github.com/nfc-tools/mfoc
    cd /opt/tools/mfoc || exit
    autoreconf -vis
    ./configure
    make
    make install
    add-history mfoc
    add-test-command "mfoc -h"
    add-to-list "mfoc,https://github.com/nfc-tools/mfoc,Implementation of 'offline nested' attack by Nethemba"
}

function install_libnfc-crypto1-crack() {
    colorecho "Installing libnfc-crypto1-crack"
    git -C /opt/tools/ clone --depth 1 https://github.com/aczid/crypto1_bs
    cd /opt/tools/crypto1_bs || exit
    wget https://github.com/droidnewbie2/acr122uNFC/raw/master/crapto1-v3.3.tar.xz
    wget https://github.com/droidnewbie2/acr122uNFC/raw/master/craptev1-v1.1.tar.xz
    xz -d craptev1-v1.1.tar.xz crapto1-v3.3.tar.xz
    tar xvf craptev1-v1.1.tar
    tar xvf crapto1-v3.3.tar --one-top-level
    make CFLAGS=-"-std=gnu99 -O3 -march=native -Wl,--allow-multiple-definition"
    cp libnfc_crypto1_crack /opt/tools/bin
    add-aliases libnfc-crypto1-crack
    add-history libnfc-crypto1-crack
    add-test-command "libnfc_crypto1_crack --help |& grep 'libnfc.buses'"
    add-to-list "libnfc-crypto1-crack,https://github.com/droidnewbie2/acr122uNFC,Implementation of cryptographic attack on Mifare Classic RFID cards"
}

function install_mfdread() {
    colorecho "Installing mfdread"
    git -C /opt/tools/ clone --depth 1 https://github.com/zhovner/mfdread
    cd /opt/tools/mfdread || exit
    python3 -m venv --system-site-packages ./venv
    source ./venv/bin/activate
    pip3 install bitstring
    deactivate
    add-aliases mfdread
    add-history mfdread
    add-test-command "mfdread.py /opt/tools/mfdread/dump.mfd"
    add-to-list "mfdread,https://github.com/zhovner/mfdread,Tool for reading/writing Mifare RFID tags"
}

function install_proxmark3() {
    colorecho "Installing proxmark3 client"
    colorecho "Compiling proxmark client for generic usage with PLATFORM=PM3OTHER (read https://github.com/RfidResearchGroup/proxmark3/blob/master/doc/md/Use_of_Proxmark/4_Advanced-compilation-parameters.md#platform)"
    colorecho "It can be compiled again for RDV4.0 with 'make clean && make all && make install' from /opt/tools/proxmark3/"
    fapt --no-install-recommends git ca-certificates build-essential pkg-config libreadline-dev gcc-arm-none-eabi libnewlib-dev qtbase5-dev libbz2-dev libbluetooth-dev liblz4-dev
    git -C /opt/tools/ clone --depth 1 https://github.com/RfidResearchGroup/proxmark3.git
    cd /opt/tools/proxmark3 || exit
    make clean
    make all PLATFORM=PM3OTHER
    make install PLATFORM=PM3OTHER
    add-aliases proxmark3
    add-history proxmark3
    add-test-command "proxmark3 --version"
    add-to-list "proxmark3,https://github.com/RfidResearchGroup/proxmark3,Open source RFID research toolkit."
}

# Package dedicated to RFID/NCF pentest tools
function package_rfid() {
    set_env
    local start_time
    local end_time
    start_time=$(date +%s)
    install_rfid_apt_tools
    install_mfoc                    # Tool for nested attack on Mifare Classic
    install_libnfc-crypto1-crack    # tool for hardnested attack on Mifare Classic
    install_mfdread                 # Tool to pretty print Mifare 1k/4k dumps
    install_proxmark3               # Proxmark3 scripts
    end_time=$(date +%s)
    local elapsed_time=$((end_time - start_time))
    colorecho "Package rfid completed in $elapsed_time seconds."
}
