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
    git -C /opt/tools/ clone --depth 1 https://github.com/Gallopsled/pwntools
    cd /opt/tools/pwntools || exit
    sed -i 's/capstone[>=][^"]*/capstone==6.0.0a2/' pyproject.toml
    pip install .
    add-test-command "python -c 'import pwn'"
    add-test-command "python3 -c 'import pwn'"
    add-to-list "pwntools,https://github.com/Gallopsled/pwntools,a CTF framework and exploit development library"
}

function install_gdb_plugins() {
    colorecho "Installing GDB plugins"
    mkdir -p /opt/tools/gdb

    # Pwndbg
    colorecho "Installing pwndbg GDB plugin"
    git -C /opt/tools/gdb clone --depth 1 https://github.com/pwndbg/pwndbg
    cd /opt/tools/gdb/pwndbg || exit
    ./setup.sh
    add-to-list "pwndbg,https://github.com/pwndbg/pwndbg,a GDB plugin that makes debugging with GDB suck less"

    # PEDA
    colorecho "Installing PEDA GDB plugin"
    git -C /opt/tools/gdb clone --depth 1 https://github.com/longld/peda.git
    add-to-list "peda,https://github.com/longld/peda,Python Exploit Development Assistance for GDB."

    # GEF
    colorecho "Installing GEF GDB plugin"
    mkdir -p /opt/tools/gdb/gef
    wget "https://raw.githubusercontent.com/hugsy/gef/refs/heads/main/gef.py" -O /opt/tools/gdb/gef/gef.py
    add-to-list "gef,https://github.com/hugsy/gef,A modern experience for GDB with advanced debugging capabilities for exploit devs & reverse engineers on Linux."

    # GDB
    cp -v /root/sources/assets/shells/gdbinit ~/.gdbinit
    add-aliases gdb
    add-history gdb
    add-test-command "gdb --help"
    add-test-command "gdb-peda --help"
    add-test-command "gdb-gef --help"
}

function install_angr() {
    # CODE-CHECK-WHITELIST=add-aliases,add-history
    colorecho "Installing angr"
    fapt libffi-dev
    mkdir -p /opt/tools/angr || exit
    cd /opt/tools/angr || exit
    python3 -m venv --system-site-packages ./venv
    source ./venv/bin/activate
    pip install angr
    deactivate
    add-aliases angr
    add-test-command "angr -c 'import angr'"
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
    local ghidra_url
    ghidra_url=$(curl --location --silent "https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/latest" | grep 'browser_download_url' | grep -o 'https://[^"]*')
    curl --location -o /tmp/ghidra.zip "$ghidra_url"
    unzip -q /tmp/ghidra.zip -d /opt/tools # -q because too much useless verbose
    mv -v /opt/tools/ghidra_* /opt/tools/ghidra # ghidra always has a version number in the unzipped folder, lets make it consistent
    rm /tmp/ghidra.zip
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
        wget "https://out7.hex-rays.com/files/idafree84_linux.run" -O /tmp/idafree_linux.run
        chmod +x /tmp/idafree_linux.run # This is the setup wizard
        /tmp/idafree_linux.run --mode unattended --prefix /opt/tools/idafree
        rm /tmp/idafree_linux.run
    else
        criticalecho-noexit "This installation function doesn't support architecture $(uname -m), IDA Free only supports x86/x64" && return
    fi
    add-aliases ida
    add-history ida
    # TODO add-test-command GUI app
    add-to-list "ida,https://www.hex-rays.com/products/ida/,Interactive disassembler for software analysis."
}

function install_binaryninja() {
    # CODE-CHECK-WHITELIST=add-test-command,add-aliases,add-history
    colorecho "Installing Binary Ninja"
    if [[ $(uname -m) = 'x86_64' ]]
    then
        wget "https://cdn.binary.ninja/installers/binaryninja_free_linux.zip" -O /tmp/binaryninja_free_linux.zip
        unzip /tmp/binaryninja_free_linux.zip -d /opt/tools
        ln -s "/opt/tools/binaryninja/binaryninja" "/opt/tools/bin/binaryninja"
    else
        criticalecho-noexit "This installation function doesn't support architecture $(uname -m), Binary Ninja only supports x86/x64" && return
    fi
    # TODO add-test-command GUI app
    # TODO replace dashes by commas once `add-to-list` supports commas in tool description
    add-to-list "binaryninja,https://binary.ninja,An interactive decompiler - disassembler - debugger and binary analysis platform built by reverse engineers for reverse engineers."
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
    fapt liblzma-dev patchelf elfutils
    # Sourcing rustup shell setup, so that rust binaries are found when installing cme
    source "$HOME/.cargo/env"
    cargo install pwninit
    add-history pwninit
    add-test-command "pwninit --help"
    add-to-list "pwninit,https://github.com/io12/pwninit,A tool for automating starting binary exploit challenges"
}

function install_pycdc() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing pycdc"
    git -C /tmp clone --depth 1 https://github.com/zrax/pycdc.git
    mkdir -v /tmp/pycdc/build
    cd /tmp/pycdc/build || exit
    cmake ..
    make -j
    mv pycdc pycdas /opt/tools/bin
    add-history pycdc
    add-test-command "pycdc --help"
    add-test-command "pycdas --help"
    add-to-list "pycdc,https://github.com/zrax/pycdc,Python bytecode disassembler and decompiler."
}

# Package dedicated to reverse engineering tools
function package_reverse() {
    set_env
    local start_time
    local end_time
    start_time=$(date +%s)
    install_reverse_apt_tools
    install_pwntools                # CTF framework and exploit development library
    install_gdb_plugins             # GDB plugins (pwndbg, PEDA, GEF)
    install_angr                    # Binary analysis
    install_checksec-py             # Check security on binaries
    install_radare2                 # Awesome debugger
    install_ghidra
    install_ida
    install_binaryninja
    install_jd-gui                  # Java decompiler
    install_pwninit                 # Tool for automating starting binary exploit
    install_pycdc                   # Python bytecode disassembler and decompiler
    post_install
    end_time=$(date +%s)
    local elapsed_time=$((end_time - start_time))
    colorecho "Package reverse completed in $elapsed_time seconds."
}
