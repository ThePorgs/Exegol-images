#!/bin/bash
# Author: The Exegol Project

source common.sh

function install_reverse_apt_tools() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing reverse apt tools"
    fapt nasm wabt strace

    add-history nasm
    add-history strace
    
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
    add-to-list "wabt,https://github.com/WebAssembly/wabt,The WebAssembly Binary Toolkit (WABT) is a suite of tools for WebAssembly (Wasm) including assembler and disassembler / a syntax checker / and a binary format validator."
    add-to-list "strace,https://github.com/strace/strace,strace is a debugging utility for Linux that allows you to monitor and diagnose system calls made by a process."
}

function install_pwntools() {
    # CODE-CHECK-WHITELIST=add-aliases,add-history
    colorecho "Installing pwntools"
    python -m pip install pwntools
    # Downgrade pyelftools version because : https://github.com/Gallopsled/pwntools/issues/2260
    python -m pip install pathlib2 pyelftools==0.29
    pip3 install pwntools
    pip3 install pyelftools==0.29
    add-test-command "python -c 'import pwn'"
    add-test-command "python3 -c 'import pwn'"
    add-to-list "pwntools,https://github.com/Gallopsled/pwntools,a CTF framework and exploit development library"
}

function install_pwndbg() {
    colorecho "Installing pwndbg"
    git -C /opt/tools/ clone --depth 1 https://github.com/pwndbg/pwndbg
    cd /opt/tools/pwndbg || exit
    ./setup.sh
    echo 'set disassembly-flavor intel' >> ~/.gdbinit
    add-aliases gdb
    add-history gdb
    add-test-command "gdb --help"
    add-to-list "pwndbg,https://github.com/pwndbg/pwndbg,a GDB plugin that makes debugging with GDB suck less"
}

function install_angr() {
    # CODE-CHECK-WHITELIST=add-aliases,add-history
    colorecho "Installing angr"
    fapt libffi-dev
    pip3 install angr
    add-test-command "python3 -c 'import angr'"
    add-to-list "angr,https://github.com/angr/angr,a platform-agnostic binary analysis framework"
}

function install_checksec-py() {
    colorecho "Installing checksec.py"
    git -C /opt/tools/ clone --depth 1 https://github.com/Wenzel/checksec.py.git
    cd /opt/tools/checksec.py || exit
    python3 -m venv --system-site-packages ./venv
    source ./venv/bin/activate
    pip install .
    deactivate
    add-aliases checksec
    add-history checksec
    add-test-command "checksec.py --help"
    add-to-list "checksec-py,https://github.com/Wenzel/checksec.py,Python wrapper script for checksec.sh from paX."
}

function install_radare2() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing radare2"
    git -C /opt/tools/ clone --depth 1 https://github.com/radareorg/radare2
    /opt/tools/radare2/sys/install.sh
    add-history radare2
    add-test-command "radare2 -h"
    add-to-list "radare2,https://github.com/radareorg/radare2,A complete framework for reverse-engineering and analyzing binaries"
}

function install_ghidra() {
    # CODE-CHECK-WHITELIST=add-test-command
    colorecho "Installing Ghidra"
    wget -P /tmp/ "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_10.1.2_build/ghidra_10.1.2_PUBLIC_20220125.zip"
    unzip /tmp/ghidra_10.1.2_PUBLIC_20220125.zip -d /opt/tools
    rm /tmp/ghidra_10.1.2_PUBLIC_20220125.zip
    add-aliases ghidra
    add-history ghidra
    # TODO add-test-command GUI app
    add-to-list "ghidra,https://github.com/NationalSecurityAgency/ghidra,Software reverse engineering suite of tools."
}

function install_ida() {
    # CODE-CHECK-WHITELIST=add-test-command
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
    add-history ida
    # TODO add-test-command GUI app
    add-to-list "ida,https://www.hex-rays.com/products/ida/,Interactive disassembler for software analysis."
}

function install_jd-gui() {
    # CODE-CHECK-WHITELIST=add-test-command
    colorecho "Installing jd-gui"
    mkdir -p /opt/tools/jd-gui && cd /opt/tools/jd-gui || exit
    wget https://github.com/java-decompiler/jd-gui/releases/download/v1.6.6/jd-gui-1.6.6.jar
    add-aliases jd-gui
    add-history jd-gui
    # TODO add-test-command GUI app
    add-to-list "jd-gui,https://github.com/java-decompiler/jd-gui,A standalone Java Decompiler GUI"
}

function install_pwninit() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing pwninit"
    fapt liblzma-dev
    # Sourcing rustup shell setup, so that rust binaries are found when installing cme
    source "$HOME/.cargo/env"
    cargo install pwninit
    add-history pwninit
    add-test-command "pwninit --help"
    add-to-list "pwninit,https://github.com/io12/pwninit,A tool for automating starting binary exploit challenges"
}

# Package dedicated to reverse engineering tools
function package_reverse() {
    set_env
    local start_time
    local end_time
    start_time=$(date +%s)
    install_reverse_apt_tools
    install_pwntools                # CTF framework and exploit development library
    install_pwndbg                  # Advanced Gnu Debugger
    install_angr                    # Binary analysis
    install_checksec-py             # Check security on binaries
    install_radare2                 # Awesome debugger
    install_ghidra
    install_ida
    install_jd-gui                  # Java decompiler
    install_pwninit                 # Tool for automating starting binary exploit
    end_time=$(date +%s)
    local elapsed_time=$((end_time - start_time))
    colorecho "Package reverse completed in $elapsed_time seconds."
}
