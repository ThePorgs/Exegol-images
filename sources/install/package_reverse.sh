#!/bin/bash
# Author: The Exegol Project

source common.sh

# Package dedicated to reverse engineering tools
function package_reverse() {
    install_reverse_apt_tools
    install_pwntools                # CTF framework and exploit development library
    install_pwndbg                  # Advanced Gnu Debugger
    install_angr                    # Binary analysis
    install_checksec-py             # Check security on binaries
    install_radare2                 # Awesome debugger
    install_ghidra
    install_ida
    install_jd-gui                  # Java decompiler
}

function install_reverse_apt_tools() {
    fapt nasm wabt strace
    
    if [[ $(uname -m) = 'x86_64' ]]
    then
        fapt ltrace
        add-test-command "ltrace --version"
        add-to-list "ltrace,https://github.com/dkogan/ltrace,ltrace is a debugging program for Linux and Unix that intercepts and records dynamic library calls that are called by an executed process."
    else
        criticalecho-noexit "This installation function doesn't support architecture $(uname -m)" && return
    fi

    add-test-command "nasm --version" # Netwide Assembler
    add-test-command "strace --version"

    add-to-list "nasm,https://github.com/netwide-assembler/nasm,NASM is an 80x86 assembler designed for portability and modularity."
    add-to-list "wabt,https://github.com/WebAssembly/wabt,The WebAssembly Binary Toolkit (WABT) is a suite of tools for WebAssembly (Wasm), including assembler and disassembler, a syntax checker, and a binary format validator."
    add-to-list "strace,https://github.com/strace/strace,strace is a debugging utility for Linux that allows you to monitor and diagnose system calls made by a process."

}

function install_pwntools() {
    colorecho "Installing pwntools"
    python -m pip install pwntools
    python -m pip install pathlib2
    python3 -m pip install pwntools
    add-test-command "python -c 'import pwn'"
    add-test-command "python3 -c 'import pwn'"
    add-to-list "pwntools,https://github.com/Gallopsled/pwntools,a CTF framework and exploit development library"
}

function install_pwndbg() {
    colorecho "Installing pwndbg"
    git -C /opt/tools/ clone --depth=1 https://github.com/pwndbg/pwndbg
    cd /opt/tools/pwndbg
    ./setup.sh
    echo 'set disassembly-flavor intel' >> ~/.gdbinit
    add-aliases gdb
    add-test-command "gdb --help"
    add-to-list "pwndbg,https://github.com/pwndbg/pwndbg,a GDB plugin that makes debugging with GDB suck less"
}

function install_angr() {
    colorecho "Installing angr"
    fapt libffi-dev
    python3 -m pip install angr
    add-test-command "python3 -c 'import angr'"
    add-to-list "angr,https://github.com/angr/angr,a platform-agnostic binary analysis framework"
}

function install_checksec-py() {
    colorecho "Installing checksec.py"
    python3 -m pipx install checksec.py
    add-test-command "checksec --help"
    add-to-list "checksec-py,https://github.com/Wenzel/checksec.py,Python wrapper script for checksec.sh from paX."
}

function install_radare2(){
    colorecho "Installing radare2"
    git -C /opt/tools/ clone https://github.com/radareorg/radare2
    /opt/tools/radare2/sys/install.sh
    add-test-command "radare2 -h"
    add-to-list "radare2,https://github.com/radareorg/radare2,A complete framework for reverse-engineering and analyzing binaries"
}

function install_ghidra() {
    colorecho "Installing Ghidra"
    wget -P /tmp/ "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_10.1.2_build/ghidra_10.1.2_PUBLIC_20220125.zip"
    unzip /tmp/ghidra_10.1.2_PUBLIC_20220125.zip -d /opt/tools
    rm /tmp/ghidra_10.1.2_PUBLIC_20220125.zip
    add-aliases ghidra
    # TODO add-test-command GUI app
    add-to-list "ghidra,https://github.com/NationalSecurityAgency/ghidra,Software reverse engineering suite of tools."
}

function install_ida() {
    colorecho "Installing IDA"
    if [[ $(uname -m) = 'x86_64' ]]
    then
        wget -P /tmp/ "https://out7.hex-rays.com/files/idafree77_linux.run"
        chmod +x /tmp/idafree77_linux.run
        /tmp/idafree77_linux.run --mode unattended --prefix /opt/tools/idafree-7.7
        rm /tmp/idafree77_linux.run
    else
        criticalecho-noexit "This installation function doesn't support architecture $(uname -m), IDA Free only supports x86/x64" && return
    fi
    add-aliases ida
    # TODO add-test-command GUI app
    add-to-list "ida,https://www.hex-rays.com/products/ida/,Interactive disassembler for software analysis."
}

function install_jd-gui(){
    colorecho "Installing jd-gui"
    mkdir -p /opt/tools/jd-gui && cd /opt/tools/jd-gui || exit
    wget https://github.com/java-decompiler/jd-gui/releases/download/v1.6.6/jd-gui-1.6.6.jar
    add-aliases jd-gui
    # TODO add-test-command GUI app
    add-to-list "jd-gui,https://github.com/java-decompiler/jd-gui,A standalone Java Decompiler GUI"
}