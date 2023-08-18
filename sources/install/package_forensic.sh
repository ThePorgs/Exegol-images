#!/bin/bash
# Author: The Exegol Project

source common.sh

function install_forensic_apt_tools() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing forensic apt tools"
    fapt pst-utils binwalk foremost testdisk fdisk sleuthkit
    
    add-history binwalk
    add-history foremost
    add-history testdisk
    add-history fdisk
    
    add-test-command "pst2ldif -V"      # Reads a PST and prints the tree structure to the console
    add-test-command "binwalk --help"   # Tool to find embedded files
    add-test-command "foremost -V"      # Alternative to binwalk
    add-test-command "testdisk --help"  # Recover lost partitions
    add-test-command "fdisk --help"     # Creating and manipulating disk partition table
    add-test-command "blkcalc -V"       # Collection of command line tools that allow you to investigate disk images

    add-to-list "pst-utils,https://manpages.debian.org/jessie/pst-utils/readpst.1,pst-utils is a set of tools for working with Outlook PST files."
    add-to-list "binwalk,https://github.com/ReFirmLabs/binwalk,Binwalk is a tool for analyzing / reverse engineering / and extracting firmware images."
    add-to-list "foremost,https://doc.ubuntu-fr.org/foremost,Foremost is a forensic tool for recovering files based on their headers / footers / and internal data structures."
    add-to-list "testdisk,https://github.com/cgsecurity/testdisk,Partition recovery and file undelete utility"
    add-to-list "fdisk,https://github.com/karelzak/util-linux,Collection of basic system utilities / including fdisk partitioning tool"
    add-to-list "sleuthkit,https://github.com/sleuthkit/sleuthkit,Forensic toolkit to analyze volume and file system data"
}

function install_volatility2() {
    colorecho "Installing volatility"
    fapt pcregrep libpcre++-dev yara libjpeg-dev zlib1g-dev
    git -C /opt/tools/ clone --depth 1 https://github.com/volatilityfoundation/volatility
    cd /opt/tools/volatility
    virtualenv -p /usr/bin/python2 ./venv
    ./venv/bin/python2 -m pip install pycrypto distorm3 pillow openpyxl
    ./venv/bin/python2 -m pip install ujson --no-use-pep517
    source ./venv/bin/activate
    python2 setup.py install
    deactivate
    # https://github.com/volatilityfoundation/volatility/issues/535#issuecomment-407571161
    ln -s /usr/local/lib/python2.7/dist-packages/usr/lib/libyara.so /usr/lib/libyara.so
    add-aliases volatility2
    # TODO: Improve volatility2 history
    add-history volatility2
    add-test-command "volatility2 --help"
    add-to-list "volatility2,https://github.com/volatilityfoundation/volatility,Volatile memory extraction utility framework"
}

function install_volatility3() {
    colorecho "Installing volatility3"
    python3 -m pipx install git+https://github.com/volatilityfoundation/volatility3
    add-aliases volatility3
    add-history volatility3
    add-test-command "volatility3 --help"
    add-to-list "volatility3,https://github.com/volatilityfoundation/volatility3,Advanced memory forensics framework"
}

function install_trid() {
    colorecho "Installing trid"
    mkdir /opt/tools/trid/
    cd /opt/tools/trid
    wget https://mark0.net/download/tridupdate.zip
    wget https://mark0.net/download/triddefs.zip
    wget https://mark0.net/download/trid_linux_64.zip
    unzip trid_linux_64.zip
    unzip triddefs.zip
    unzip tridupdate.zip
    rm tridupdate.zip triddefs.zip trid_linux_64.zip
    chmod +x trid
    python3 tridupdate.py
    add-aliases trid
    add-history trid
    add-test-command "trid '-?'; trid | grep 'This help'"
    add-to-list "trid,https://mark0.net/soft-trid-e.html,File identifier"
}

function install_peepdf() {
    colorecho "Installing peepdf"
    git -C /opt/tools clone --depth 1 https://github.com/jesparza/peepdf
    add-aliases peepdf
    add-history peepdf
    add-test-command "peepdf --help"
    add-to-list "peepdf,https://github.com/jesparza/peepdf,peepdf is a Python tool to explore PDF files in order to find out if the file can be harmful or not."
} 

function install_jadx() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing jadx"
    git -C /opt/tools/ clone --depth 1 https://github.com/skylot/jadx.git
    cd /opt/tools/jadx
    ./gradlew dist
    ln -v -s /opt/tools/jadx/build/jadx/bin/jadx /opt/tools/bin/jadx
    ln -v -s /opt/tools/jadx/build/jadx/bin/jadx-gui /opt/tools/bin/jadx-gui
    add-history jadx
    add-test-command "jadx --help"
    add-to-list "jadx,https://github.com/skylot/jadx,Java decompiler"
}

# Package dedicated to forensic tools
function package_forensic() {
    set_ruby_env
    install_forensic_apt_tools
    install_volatility2             # Memory analysis tool
    install_volatility3             # Memory analysis tool v2
    install_trid                    # filetype detection tool
    install_peepdf                  # PDF analysis
    install_jadx                    # Dex to Java decompiler
}
