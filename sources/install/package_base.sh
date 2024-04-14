#!/bin/bash
# Author: The Exegol Project

source common.sh

function update() {
    colorecho "Updating, upgrading, cleaning"
    echo 'debconf debconf/frontend select Noninteractive' | debconf-set-selections
    apt-get -y update && apt-get -y install apt-utils dialog && apt-get -y upgrade && apt-get -y autoremove && apt-get clean
}

function install_exegol-history() {
    colorecho "Installing Exegol-history"
    #  git -C /opt/tools/ clone --depth 1 https://github.com/ThePorgs/Exegol-history
    # todo : below is something basic. A nice tool being created for faster and smoother workflow
    mkdir -p /opt/tools/Exegol-history
    rm -rf /opt/tools/Exegol-history/profile.sh
    {
      echo "#export INTERFACE='eth0'"
      echo "#export DOMAIN='DOMAIN.LOCAL'"
      echo "#export DOMAIN_SID='S-1-5-11-39129514-1145628974-103568174'"
      echo "#export USER='someuser'"
      echo "#export PASSWORD='somepassword'"
      echo "#export NT_HASH='c1c635aa12ae60b7fe39e28456a7bac6'"
      echo "#export DC_IP='192.168.56.101'"
      echo "#export DC_HOST='DC01.DOMAIN.LOCAL'"
      echo "#export TARGET='192.168.56.69'"
      echo "#export ATTACKER_IP='192.168.56.1'"
    } >> /opt/tools/Exegol-history/profile.sh
}

function install_rust_cargo() {
    # CODE-CHECK-WHITELIST=add-aliases,add-to-list,add-history
    colorecho "Installing rustc, cargo, rustup"
    # splitting curl | sh to avoid having additional logs put in curl output being executed because of catch_and_retry
    curl https://sh.rustup.rs -sSf -o /tmp/rustup.sh
    sh /tmp/rustup.sh -y
    source "$HOME/.cargo/env"
    add-test-command "cargo --version"
}

function filesystem() {
    colorecho "Preparing filesystem"
    mkdir -p /opt/tools/bin/ /data/ /var/log/exegol /.exegol/build_pipeline_tests/
    touch /.exegol/build_pipeline_tests/all_commands.txt
    touch /.exegol/installed_tools.csv
    echo "Tool,Link,Description" >> /.exegol/installed_tools.csv
}

function install_go() {
    # CODE-CHECK-WHITELIST=add-aliases,add-to-list,add-history
    colorecho "Installing go (Golang)"
    asdf plugin add golang https://github.com/asdf-community/asdf-golang.git
    asdf install golang latest
    # 1.19 needed by sliver
    asdf install golang 1.19
    asdf global golang latest
#    if command -v /usr/local/go/bin/go &>/dev/null; then
#        return
#    fi
#    cd /tmp/ || exit
#    if [[ $(uname -m) = 'x86_64' ]]
#    then
#        wget -O /tmp/go.tar.gz https://go.dev/dl/go1.21.5.linux-amd64.tar.gz
#    elif [[ $(uname -m) = 'aarch64' ]]
#    then
#        wget -O /tmp/go.tar.gz https://go.dev/dl/go1.21.5.linux-arm64.tar.gz
#    elif [[ $(uname -m) = 'armv7l' ]]
#    then
#        wget -O /tmp/go.tar.gz https://go.dev/dl/go1.21.5.linux-armv6l.tar.gz
#    else
#        criticalecho-noexit "This installation function doesn't support architecture $(uname -m)" && return
#    fi
#    rm -rf /usr/local/go
#    tar -C /usr/local -xzf /tmp/go.tar.gz
#    rm -rf /tmp/go.tar.gz
#    export PATH=$PATH:/usr/local/go/bin
    add-test-command "go version"
}

function deploy_exegol() {
    colorecho "Installing Exegol things"
    # Moving exegol files to /
    # It's copied and not moved for caching and updating purposes (reusing exegol_base to create exegol_base)
    # mkdir -p /opt/packages
    # chown -Rv _apt:root /opt/packages
    rm -rf /.exegol || true
    cp -r /root/sources/assets/exegol /.exegol
    cp -v /root/sources/assets/shells/history.d/_init ~/.zsh_history
    cp -v /root/sources/assets/shells/aliases.d/_init /opt/.exegol_aliases
    # Moving supported custom configurations in /opt
    mv /.exegol/skel/supported_setups.md /opt/
    mkdir -p /var/log/exegol
    # Setup perms
    chown -R root:root /.exegol
    chmod 500 /.exegol/*.sh
    find /.exegol/skel/ -type f -exec chmod 660 {} \;
}

function install_locales() {
    # CODE-CHECK-WHITELIST=add-aliases,add-history,add-test-command,add-to-list
    colorecho "Installing locales"
    fapt locales
    sed -i -e 's/# en_US.UTF-8 UTF-8/en_US.UTF-8 UTF-8/' /etc/locale.gen
    locale-gen
    export LC_ALL=en_US.UTF-8
    export LANG=en_US.UTF-8
    export LANGUAGE=en_US.UTF-8
}

function install_pyenv() {
    # CODE-CHECK-WHITELIST=add-aliases,add-history,add-to-list
    colorecho "Installing pyenv"
    fapt git curl build-essential
    curl -o /tmp/pyenv.run https://pyenv.run
    bash /tmp/pyenv.run
    local v
    # add pyenv to PATH
    export PATH="/root/.pyenv/bin:$PATH"
    # add python commands (pyenv shims) to PATH
    eval "$(pyenv init --path)"
    colorecho "Installing python2 (latest)"
    fapt libssl-dev zlib1g-dev libbz2-dev libreadline-dev libsqlite3-dev libncurses5-dev libncursesw5-dev libffi-dev liblzma-dev
    # Don't think it's needed, but if something fails, use command below
    # apt install xz-utils tk-dev
    for v in $PYTHON_VERSIONS; do
        colorecho "Installing python${v}"
        pyenv install "$v"
    done
    # allowing python2, python3 and python3.6 to be found
    #  --> python points to python3
    #  --> python3 points to python3.11
    #  --> python3.6 points to 3.6
    #  --> python2 points to latest python2
    # shellcheck disable=SC2086
    pyenv global $PYTHON_VERSIONS
    add-test-command "python --version"
    add-test-command "pip --version"
    add-test-command "python3 --version"
    add-test-command "pip3 --version"
    for v in $PYTHON_VERSIONS; do
        add-test-command "python${v} --version"
        add-test-command "pip${v} --version"
    done
}

function install_firefox() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing firefox"
    fapt firefox-esr
    mkdir /opt/tools/firefox
    mv /root/sources/assets/firefox/* /opt/tools/firefox/
    pip3 install -r /opt/tools/firefox/requirements.txt
    python3 /opt/tools/firefox/setup.py
    add-history firefox
    add-test-command "file /root/.mozilla/firefox/*.Exegol"
    add-test-command "firefox --version"
    add-to-list "firefox,https://www.mozilla.org,A web browser"
}

function install_rvm() {
    # CODE-CHECK-WHITELIST=add-aliases,add-history,add-to-list
    colorecho "Installing rvm"
    # allow to fetch keys when behind a firewall (https://serverfault.com/questions/168826/how-to-install-gpg-keys-from-behind-a-firewall)
    gpg --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys 409B6B1796C275462A1703113804BB82D39DC0E3 7D2BAF1CF37B13E2069D6956105BD0E739499BDB
    # kill all gpg processes
    # make sure gpgconf exists
    if command -v gpgconf > /dev/null; then
        gpgconf --kill all
    else
        :  # Do nothing, and return true
    fi
    # splitting curl | bash to avoid having additional logs put in curl output being executed because of catch_and_retry
    curl -sSL https://get.rvm.io -o /tmp/rvm.sh
    bash /tmp/rvm.sh --ruby="3.2.2" stable
    source /usr/local/rvm/scripts/rvm
    rvm autolibs read-fail
    rvm rvmrc warning ignore allGemfiles
    rvm use 3.2.2@default
    rvm install ruby-3.1.2
    rvm get head
    gem update
    add-test-command "rvm --version"
}

function install_fzf() {
    # CODE-CHECK-WHITELIST=add-history
    colorecho "Installing fzf"
    git -C /opt/tools clone --depth 1 https://github.com/junegunn/fzf.git
    yes|/opt/tools/fzf/install
    add-aliases fzf
    add-test-command "fzf-wordlists --help"
    add-test-command "fzf --help"
    add-to-list "fzf,https://github.com/junegunn/fzf,🌸 A command-line fuzzy finder"
}

function install_ohmyzsh() {
    # CODE-CHECK-WHITELIST=add-aliases,add-history,add-test-command,add-to-list
    if [[ -d "/root/.oh-my-zsh" ]]; then
        return
    fi
    colorecho "Installing oh-my-zsh, config, history, aliases"
    # splitting wget and sh to avoid having additional logs put in curl output being executed because of catch_and_retry
    wget -O /tmp/ohmyzsh.sh https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh
    sh /tmp/ohmyzsh.sh
    cp -v /root/sources/assets/shells/zshrc ~/.zshrc
    git -C ~/.oh-my-zsh/custom/plugins/ clone --depth 1 https://github.com/zsh-users/zsh-autosuggestions
    git -C ~/.oh-my-zsh/custom/plugins/ clone --depth 1 https://github.com/zsh-users/zsh-syntax-highlighting
    git -C ~/.oh-my-zsh/custom/plugins/ clone --depth 1 https://github.com/zsh-users/zsh-completions
    git -C ~/.oh-my-zsh/custom/plugins/ clone --depth 1 https://github.com/agkozak/zsh-z
    git -C ~/.oh-my-zsh/custom/plugins/ clone --depth 1 https://github.com/lukechilds/zsh-nvm
    zsh -c "source ~/.oh-my-zsh/custom/plugins/zsh-nvm/zsh-nvm.plugin.zsh" # this is needed to start an instance of zsh to have the plugin set up
}

function install_pipx() {
    # CODE-CHECK-WHITELIST=add-aliases,add-history,add-to-list
    colorecho "Installing pipx"
    pip3 install pipx
    pipx ensurepath
    add-test-command "pipx --version"
}

function install_yarn() {
    # CODE-CHECK-WHITELIST=add-aliases,add-history,add-to-list
    colorecho "Installing yarn"
    wget -O /tmp/yarn.gpg.armored https://dl.yarnpkg.com/debian/pubkey.gpg
    # doing wget, gpg, chmod, to avoid the warning of apt-key being deprecated
    gpg --dearmor --output /etc/apt/trusted.gpg.d/yarn.gpg /tmp/yarn.gpg.armored
    chmod 644 /etc/apt/trusted.gpg.d/yarn.gpg
    echo "deb https://dl.yarnpkg.com/debian/ stable main" | tee /etc/apt/sources.list.d/yarn.list
    apt-get update
    fapt yarn
    add-test-command "yarn --help"
}

function install_ultimate_vimrc() {
    # CODE-CHECK-WHITELIST=add-aliases,add-history,add-test-command,add-to-list
    if [[ -d "/root/.vim_runtime" ]]; then
        return
    fi
    colorecho "Installing The Ultimate vimrc"
    git clone --depth 1 https://github.com/amix/vimrc.git ~/.vim_runtime
    sh ~/.vim_runtime/install_awesome_vimrc.sh
}

function install_neovim() {
    colorecho "Installing neovim"
    # CODE-CHECK-WHITELIST=add-aliases,add-history
    if [[ $(uname -m) = 'x86_64' ]]
    then
        curl -LO https://github.com/neovim/neovim/releases/latest/download/nvim.appimage
        chmod u+x nvim.appimage
        ./nvim.appimage --appimage-extract
        mkdir /opt/tools/nvim
        cp -r squashfs-root/usr/* /opt/tools/nvim
        rm -rf squashfs-root nvim.appimage
        ln -v -s /opt/tools/nvim/bin/nvim /opt/tools/bin/nvim
    elif [[ $(uname -m) = 'aarch64' ]]
    then
        # Build take ~5min
        fapt gettext
        git clone https://github.com/neovim/neovim.git
        cd neovim || exit
        make CMAKE_BUILD_TYPE=RelWithDebInfo
        make install
        cd .. || exit
        rm -rf ./neovim
    fi
    add-test-command "nvim --version"
    add-to-list "neovim,https://neovim.io/,hyperextensible Vim-based text editor"
}

function install_mdcat() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing mdcat"
    source "$HOME/.cargo/env"
    cargo install mdcat
    add-history mdcat
    add-test-command "mdcat --version"
    add-to-list "mdcat,https://github.com/swsnr/mdcat,Fancy cat for Markdown"
}

function install_gf() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing gf"
    # A wrapper around grep, to help you grep for things
    go install -v github.com/tomnomnom/gf@latest
    asdf reshim golang
    # Enable autocompletion
    {
      # adding new-line
      echo ''
      echo '# Enable gf autocompletion'
      # FIXME GOPATH not set
      # shellcheck disable=SC2016
      echo 'source "$GOPATH"/pkg/mod/github.com/tomnomnom/gf@*/gf-completion.zsh'
    } >> ~/.zshrc
    cp -r "$(sh -c "go env GOPATH")"/pkg/mod/github.com/tomnomnom/gf@*/examples ~/.gf
    # Add patterns from 1ndianl33t
    git -C /opt/tools/ clone --depth 1 https://github.com/1ndianl33t/Gf-Patterns
    cp -r /opt/tools/Gf-Patterns/*.json ~/.gf
    # Remove repo to save space
    rm -r /opt/tools/Gf-Patterns
    add-history gf
    add-test-command "gf --list"
    add-test-command "ls ~/.gf |& grep 'redirect.json'"
    add-to-list "gf,https://github.com/tomnomnom/gf,A wrapper around grep to avoid typing common patterns"
}

function install_java11() {
    # CODE-CHECK-WHITELIST=add-history,add-aliases,add-to-list
    colorecho "Installing java 11"
    if [[ $(uname -m) = 'x86_64' ]]
    then
        local arch="x64"

    elif [[ $(uname -m) = 'aarch64' ]]
    then
        local arch="aarch64"
    else
        criticalecho-noexit "This installation function doesn't support architecture $(uname -m)" && return
    fi
    local jdk_url
    jdk_url=$(curl --location --silent "https://api.github.com/repos/adoptium/temurin11-binaries/releases" | grep 'browser_download_url.*jdk_'"$arch"'_linux.*tar.gz"' | grep -o 'https://[^"]*' | sort | tail -n1)
    curl --location -o /tmp/openjdk11-jdk.tar.gz "$jdk_url"
    tar -xzf /tmp/openjdk11-jdk.tar.gz --directory /tmp
    mkdir -p "/usr/lib/jvm"
    mv /tmp/jdk-11* /usr/lib/jvm/java-11-openjdk
    add-test-command "/usr/lib/jvm/java-11-openjdk/bin/java --version"
}

function install_java21() {
    # CODE-CHECK-WHITELIST=add-history,add-aliases,add-to-list
    colorecho "Installing java 11"
    if [[ $(uname -m) = 'x86_64' ]]
    then
        wget -O /tmp/openjdk21-jdk.tar.gz "https://download.java.net/java/GA/jdk21.0.2/f2283984656d49d69e91c558476027ac/13/GPL/openjdk-21.0.2_linux-x64_bin.tar.gz"

    elif [[ $(uname -m) = 'aarch64' ]]
    then
        wget -O /tmp/openjdk21-jdk.tar.gz "https://download.java.net/java/GA/jdk21.0.2/f2283984656d49d69e91c558476027ac/13/GPL/openjdk-21.0.2_linux-aarch64_bin.tar.gz"
    else
        criticalecho-noexit "This installation function doesn't support architecture $(uname -m)" && return
    fi
    tar -xzf /tmp/openjdk21-jdk.tar.gz --directory /tmp
    mkdir -p "/usr/lib/jvm"
    mv /tmp/jdk-21* /usr/lib/jvm/java-21-openjdk
    add-test-command "/usr/lib/jvm/java-21-openjdk/bin/java --version"
}

function add_debian_repository_components() {
    # add non-free non-free-firmware contrib repository
    # adding at the end of the line start with Components of the repository to add
    colorecho "add non-free non-free-firmware contrib repository"
    local source_file="/etc/apt/sources.list.d/debian.sources"
    local out_file="/etc/apt/sources.list.d/debian2.sources"

    while IFS= read -r line; do
      if [[ "$line" == "Components"* ]]; then
        echo  "${line} non-free non-free-firmware contrib" >> "$out_file"
      else
        echo "$line" >> "$out_file"
      fi
    done < "$source_file"
    mv "$out_file" "$source_file"
}

function post_install() {
    # Function used to clean up post-install files
    colorecho "Cleaning..."
    local listening_processes
    updatedb
    rm -rfv /tmp/*
    rm -rfv /var/lib/apt/lists/*
    rm -rfv /root/sources
    rm -rfv /root/.cache
    rm -rfv /root/.gradle/caches
    colorecho "Stop listening processes"
    listening_processes=$(ss -lnpt | awk -F"," 'NR>1 {split($2,a,"="); print a[2]}')
    if [[ -n $listening_processes ]]; then
        echo "Listening processes detected"
        ss -lnpt
        echo "Kill processes"
        # shellcheck disable=SC2086
        kill -9 $listening_processes
    fi
    add-test-command "if [[ $(sudo ss -lnpt | tail -n +2 | wc -l) -ne 0 ]]; then ss -lnpt && false;fi"
    colorecho "Sorting tools list"
    (head -n 1 /.exegol/installed_tools.csv && tail -n +2 /.exegol/installed_tools.csv | sort -f ) | tee /tmp/installed_tools.csv.sorted
    mv /tmp/installed_tools.csv.sorted /.exegol/installed_tools.csv
    colorecho "Adding end-of-preset in zsh_history"
    echo "# -=-=-=-=-=-=-=- YOUR COMMANDS BELOW -=-=-=-=-=-=-=- #" >> /opt/.exegol_history
    cp /opt/.exegol_history ~/.zsh_history
    cp /opt/.exegol_history ~/.bash_history
    colorecho "Removing desktop icons"
    if [ -d "/root/Desktop" ]; then rm -r /root/Desktop; fi
}

function install_asdf() {
    # CODE-CHECK-WHITELIST=add-aliases,add-history
    colorecho "Install asdf"
    # creates ~/.asdf/
    git -C "$HOME" clone --depth 1 --branch v0.13.1 https://github.com/asdf-vm/asdf .asdf
    source "$HOME/.asdf/asdf.sh"
    # completions file
    source "$HOME/.asdf/completions/asdf.bash"
    add-test-command "asdf version"
    add-to-list "asdf,https://github.com/asdf-vm/asdf,Extendable version manager with support for ruby python go etc"
}

# Package dedicated to the basic things the env needs
function package_base() {
    update
    colorecho "Installing apt-fast for faster dep installs"
    apt-get install -y curl sudo wget
    # splitting curl | bash to avoid having additional logs put in curl output being executed because of catch_and_retry
    curl -sL https://git.io/vokNn -o /tmp/apt-fast-install.sh
    bash /tmp/apt-fast-install.sh
    deploy_exegol
    install_exegol-history
    fapt software-properties-common
    add_debian_repository_components
    apt-get update
    colorecho "Starting main programs install"
    fapt man git lsb-release pciutils pkg-config zip unzip kmod gnupg2 wget \
    libffi-dev  zsh asciinema npm gem automake autoconf make cmake time gcc g++ file lsof \
    less x11-apps net-tools vim nano jq iputils-ping iproute2 tidy mlocate libtool \
    dos2unix ftp sshpass telnet nfs-common ncat netcat-traditional socat rdate putty \
    screen p7zip-full p7zip-rar unrar xz-utils xsltproc parallel tree ruby ruby-dev ruby-full bundler \
    nim perl libwww-perl openjdk-17-jdk openvpn openresolv \
    logrotate tmux tldr bat libxml2-utils virtualenv chromium libsasl2-dev \
    libldap2-dev libssl-dev isc-dhcp-client sqlite3 dnsutils samba ssh snmp faketime php \
    python3 grc emacs-nox xsel xxd libnss3-tools
    apt-mark hold tzdata  # Prevent apt upgrade error when timezone sharing is enable

    filesystem
    install_locales
    cp -v /root/sources/assets/shells/exegol_shells_rc /opt/.exegol_shells_rc
    cp -v /root/sources/assets/shells/bashrc ~/.bashrc

    install_asdf

    # setup Python environment
    # the order matters (if 2 is before 3, `python` will point to Python 2)
    PYTHON_VERSIONS="3.11 3.12 3.10 3.6 2"
    install_pyenv
    pip2 install --no-cache-dir virtualenv
    local v
    # https://stackoverflow.com/questions/75608323/how-do-i-solve-error-externally-managed-environment-everytime-i-use-pip3
    # TODO: do we really want to unset EXTERNALLY-MANAGED? Not sure it's the best course of action
    # with pyenv, not sure the command below is needed anymore
    # rm /usr/lib/python3.*/EXTERNALLY-MANAGED
    for v in $PYTHON_VERSIONS; do
        # shellcheck disable=SC2086
        pip${v} install --upgrade pip
        # shellcheck disable=SC2086
        pip${v} install wheel
    done
    install_pipx

    # change default shell
    chsh -s /bin/zsh

    add-history dnsutils
    add-history samba
    add-history ssh
    add-history snmp
    add-history faketime

    add-aliases php
    add-aliases python3
    add-aliases grc
    add-aliases emacs-nox
    add-aliases xsel
    add-aliases pyftpdlib

    # Rust, Cargo, rvm
    install_rust_cargo
    install_rvm                                         # Ruby Version Manager

    # java11 install, and java17 as default
    install_java11
    install_java21
    ln -s -v /usr/lib/jvm/java-17-openjdk-* /usr/lib/jvm/java-17-openjdk    # To avoid determining the correct path based on the architecture
    update-alternatives --set java /usr/lib/jvm/java-17-openjdk-*/bin/java  # Set the default openjdk version to 17

    install_go                                          # Golang language
    install_ohmyzsh                                     # Awesome shell
    install_fzf                                         # Fuzzy finder
    add-history curl
    install_yarn
    install_ultimate_vimrc                              # Make vim usable OOFB
    install_neovim
    install_mdcat                                       # cat markdown files
    add-aliases bat
    add-test-command "bat --version"
    DEBIAN_FRONTEND=noninteractive fapt macchanger      # Macchanger
    install_gf                                          # wrapper around grep
    install_firefox

    cp -v /root/sources/assets/grc/grc.conf /etc/grc.conf # grc

    # openvpn
    # Fixing openresolv to update /etc/resolv.conf without resolvectl daemon (with a fallback if no DNS server are supplied)
    LINE=$(($(grep -n 'up)' /etc/openvpn/update-resolv-conf | cut -d ':' -f1) +1))
    sed -i "${LINE}"'i cp /etc/resolv.conf /etc/resolv.conf.backup' /etc/openvpn/update-resolv-conf

    LINE=$(($(grep -n 'resolvconf -a' /etc/openvpn/update-resolv-conf | cut -d ':' -f1) +1))
    # shellcheck disable=SC2016
    sed -i "${LINE}"'i [ "$(resolvconf -l "tun*" | grep -vE "^(\s*|#.*)$")" ] && /sbin/resolvconf -u || cp /etc/resolv.conf.backup /etc/resolv.conf' /etc/openvpn/update-resolv-conf
    ((LINE++))
    sed -i "${LINE}"'i rm /etc/resolv.conf.backup' /etc/openvpn/update-resolv-conf
    add-test-command "openvpn --version"

    # logrotate
    mv /root/sources/assets/logrotate/* /etc/logrotate.d/
    chmod 644 /etc/logrotate.d/*

    # tmux
    cp -v /root/sources/assets/shells/tmux.conf ~/.tmux.conf
    touch ~/.hushlogin

    # TLDR
    mkdir -p ~/.local/share/tldr
    tldr -u

    # NVM (install in conctext)
    zsh -c "source ~/.zshrc && nvm install node && nvm use default"

    # Set Global config path to vendor
    # All programs using bundle will store their deps in vendor/
    bundle config path vendor/

    # OpenSSL activate legacy support
    cat /root/sources/assets/patches/openssl.patch >> /etc/ssl/openssl.cnf
    add-test-command "echo -n '1337' | openssl dgst -md4"
    add-test-command "python3 -c 'import hashlib;print(hashlib.new(\"md4\", \"1337\".encode()).digest())'"

    # Global python dependencies
    pip3 install -r /root/sources/assets/python/requirements.txt
}
