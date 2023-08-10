#!/bin/bash
# Author: The Exegol Project

source common.sh

function install_misc_apt_tools() {
    fapt rlwrap imagemagick ascii rsync

    add-history rlwrap
    add-history imagemagick
    add-history ascii
    add-history rsync

    add-test-command "rlwrap --version"                            # Reverse shell utility
    add-test-command "convert -version"                            # Copy, modify, and distribute image
    add-test-command "ascii -v"                                    # The ascii table in the shell
    add-test-command "rsync -h"                                    # File synchronization tool for efficiently copying and updating data between local or remote locations.

    add-to-list "rlwrap,https://github.com/hanslub42/rlwrap,rlwrap is a small utility that wraps input and output streams of executables / making it possible to edit and re-run input history"
    add-to-list "imagemagick,https://github.com/ImageMagick/ImageMagick,ImageMagick is a free and open-source image manipulation tool used to create / edit / compose / or convert bitmap images."
    add-to-list "ascii,https://github.com/moul/ascii,ASCII command-line tool to replace images with color-coded ASCII art."
    add-to-list "rsync,https://packages.debian.org/sid/rsync,File synchronization tool for efficiently copying and updating data between local or remote locations"
}

function install_goshs() {
    colorecho "Installing goshs"
    go install -v github.com/patrickhener/goshs@latest
    add-history goshs
    add-test-command "goshs -v"
    add-to-list "goshs,https://github.com/patrickhener/goshs,Goshs is a replacement for Python's SimpleHTTPServer. It allows uploading and downloading via HTTP/S with either self-signed certificate or user provided certificate and you can use HTTP basic auth."
}

function install_shellerator() {
    colorecho "Installing shellerator"
    python3 -m pipx install git+https://github.com/ShutdownRepo/shellerator
    add-history shellerator
    add-test-command "shellerator --help"
    add-to-list "shellerator,https://github.com/ShutdownRepo/Shellerator,a simple command-line tool for generating shellcode"
}

function install_uberfile() {
    colorecho "Installing uberfile"
    python3 -m pipx install git+https://github.com/ShutdownRepo/uberfile
    add-history uberfile
    add-test-command "uberfile --help"
    add-to-list "uberfile,https://github.com/ShutdownRepo/Uberfile,Uberfile is a simple command-line tool aimed to help pentesters quickly generate file downloader one-liners in multiple contexts (wget / curl / powershell / certutil...). This project code is based on my other similar project for one-liner reverseshell generation Shellerator."
}

function install_arsenal() {
    colorecho "Installing arsenal"
    python3 -m pipx install git+https://github.com/Orange-Cyberdefense/arsenal
    add-aliases arsenal
    add-history arsenal
    add-test-command "arsenal --version"
    add-to-list "arsenal,https://github.com/Orange-Cyberdefense/arsenal,Powerful weapons for penetration testing."
}

function install_whatportis() {
    colorecho "Installing whatportis"
    python3 -m pipx install whatportis
    # TODO : FIX : "port": port[1] if port[1] else "---",list index out of range - cli.py
    # echo y | whatportis --update
    add-history whatportis
    add-test-command "whatportis --version"
    add-to-list "whatportis,https://github.com/ncrocfer/whatportis,Command-line tool to lookup port information"
}

function install_searchsploit() {
    colorecho "Installing searchsploit"
    if [ ! -d /opt/tools/exploitdb ]
    then
        git -C /opt/tools/ clone --depth 1 https://gitlab.com/exploit-database/exploitdb
        add-history searchsploit
        add-test-command "searchsploit --help; searchsploit --help |& grep 'You can use any number of search terms'"
        add-to-list "searchsploit,https://gitlab.com/exploit-database/exploitdb,A command line search tool for Exploit-DB"
    else
        colorecho "Searchsploit is already installed"
    fi
}

function configure_searchsploit() {
    colorecho "Configuring Searchsploit"
    ln -sf /opt/tools/exploitdb/searchsploit /opt/tools/bin/searchsploit
    cp -n /opt/tools/exploitdb/.searchsploit_rc ~/
    sed -i 's/\(.*[pP]aper.*\)/#\1/' ~/.searchsploit_rc
    sed -i 's/opt\/exploitdb/opt\/tools\/exploitdb/' ~/.searchsploit_rc
}

function install_trilium() {
    colorecho "Installing Trilium (building from sources)"
    # TODO : apt install in a second step
    fapt libpng16-16 libpng-dev pkg-config autoconf libtool build-essential nasm libx11-dev libxkbfile-dev
    git -C /opt/tools/ clone -b stable --depth 1 https://github.com/zadam/trilium.git
    cd /opt/tools/trilium
    add-aliases trilium
    add-history trilium
    add-test-command "trilium-start;sleep 20;trilium-stop"
    add-to-list "trilium,https://github.com/zadam/trilium,Personal knowledge management system."
}

function configure_trilium() {
    colorecho "Configuring trilium"
    zsh -c "source ~/.zshrc && cd /opt/tools/trilium && nvm install 16 && nvm use 16 && npm install && npm rebuild"
    mkdir -p /root/.local/share/trilium-data
    cp -v /root/sources/assets/trilium/* /root/.local/share/trilium-data
}

function install_ngrok() {
    colorecho "Installing ngrok"
    if [[ $(uname -m) = 'x86_64' ]]
    then
        wget -O /tmp/ngrok.zip https://bin.equinox.io/c/4VmDzA7iaHb/ngrok-stable-linux-amd64.zip
    elif [[ $(uname -m) = 'aarch64' ]]
    then
        wget -O /tmp/ngrok.zip https://bin.equinox.io/c/4VmDzA7iaHb/ngrok-stable-linux-arm64.zip
    elif [[ $(uname -m) = 'armv7l' ]]
    then
        wget -O /tmp/ngrok.zip https://bin.equinox.io/c/4VmDzA7iaHb/ngrok-stable-linux-arm.zip
    else
        criticalecho-noexit "This installation function doesn't support architecture $(uname -m)" && return
    fi
    unzip -d /opt/tools/bin/ /tmp/ngrok.zip
    add-history ngrok
    add-test-command "ngrok version"
    add-to-list "ngrok,https://github.com/inconshreveable/ngrok,Expose a local server behind a NAT or firewall to the internet"
}

function install_objectwalker() {
    colorecho "Installing objectwalker"
    python3 -m pipx install git+https://github.com/p0dalirius/objectwalker
    add-history objectwalker
    add-test-command "objectwalker --help"
    add-to-list "objectwalker,https://github.com/p0dalirius/objectwalker,A python module to explore the object tree to extract paths to interesting objects in memory."
}

# Package dedicated to offensive miscellaneous tools
function package_misc() {
    set_go_env
    set_ruby_env
    install_misc_apt_tools
    install_goshs           # Web uploader/downloader page
    install_searchsploit    # Exploitdb local search engine
    install_shellerator     # Reverse shell generator
    install_uberfile        # file uploader/downloader commands generator
    install_arsenal         # Cheatsheets tool
    install_trilium         # notes taking tool
    install_ngrok           # expose a local development server to the Internet
    install_whatportis      # Search default port number
    install_objectwalker    # Python module to explore the object tree to extract paths to interesting objects in memory
}

function package_misc_configure() {
    configure_searchsploit
    configure_trilium
}