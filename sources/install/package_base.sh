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
    echo "#export INTERFACE='eth0'" >> /opt/tools/Exegol-history/profile.sh
    echo "#export DOMAIN='DOMAIN.LOCAL'" >> /opt/tools/Exegol-history/profile.sh
    echo "#export DOMAIN_SID='S-1-5-11-39129514-1145628974-103568174'" >> /opt/tools/Exegol-history/profile.sh
    echo "#export USER='someuser'" >> /opt/tools/Exegol-history/profile.sh
    echo "#export PASSWORD='somepassword'" >> /opt/tools/Exegol-history/profile.sh
    echo "#export NT_HASH='c1c635aa12ae60b7fe39e28456a7bac6'" >> /opt/tools/Exegol-history/profile.sh
    echo "#export DC_IP='192.168.56.101'" >> /opt/tools/Exegol-history/profile.sh
    echo "#export DC_HOST='DC01.DOMAIN.LOCAL'" >> /opt/tools/Exegol-history/profile.sh
    echo "#export TARGET='192.168.56.69'" >> /opt/tools/Exegol-history/profile.sh
    echo "#export ATTACKER_IP='192.168.56.1'" >> /opt/tools/Exegol-history/profile.sh
}

function install_rust_cargo() {
    # CODE-CHECK-WHITELIST=add-aliases,add-to-list,add-history
    colorecho "Installing rustc, cargo, rustup"
    curl https://sh.rustup.rs -sSf | sh -s -- -y
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
    if command -v /usr/local/go/bin/go &>/dev/null; then
        return
    fi
    colorecho "Installing go (Golang)"
    cd /tmp/ || exit
    if [[ $(uname -m) = 'x86_64' ]]
    then
        wget -O /tmp/go.tar.gz https://go.dev/dl/go1.20.linux-amd64.tar.gz
    elif [[ $(uname -m) = 'aarch64' ]]
    then
        wget -O /tmp/go.tar.gz https://go.dev/dl/go1.20.linux-arm64.tar.gz
    elif [[ $(uname -m) = 'armv7l' ]]
    then
        wget -O /tmp/go.tar.gz https://go.dev/dl/go1.20.linux-armv6l.tar.gz
    else
        criticalecho-noexit "This installation function doesn't support architecture $(uname -m)" && return
    fi
    rm -rf /usr/local/go
    tar -C /usr/local -xzf /tmp/go.tar.gz
    rm -rf /tmp/go.tar.gz
    export PATH=$PATH:/usr/local/go/bin
    add-test-command "go version"
}

function deploy_exegol() {
    colorecho "Installing Exegol things"
    # Moving exegol files to /
    # It's copied and not moved for caching and updating purposes (reusing exegol_base to create exegol_base)
    mkdir -p /opt/packages
    chown -Rv _apt:root /opt/packages
    rm -rf /.exegol || true
    cp -r /root/sources/assets/exegol /.exegol
    cp -v /root/sources/assets/zsh/history ~/.zsh_history
    cp -v /root/sources/assets/zsh/aliases /opt/.exegol_aliases
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
    colorecho "Configuring locales"
    apt-get -y install locales
    sed -i -e 's/# en_US.UTF-8 UTF-8/en_US.UTF-8 UTF-8/' /etc/locale.gen
    locale-gen
}

function install_python-pip() {
    colorecho "Installing python-pip (for Python2.7)"
    curl --insecure https://bootstrap.pypa.io/pip/2.7/get-pip.py -o get-pip.py
    python get-pip.py
    rm get-pip.py
    add-test-command "pip --version"
}

function install_firefox() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing firefox"
    fapt firefox-esr
    mkdir /opt/tools/firefox
    mv /root/sources/assets/firefox/* /opt/tools/firefox/
    python3 -m pip install -r /opt/tools/firefox/requirements.txt
    python3 /opt/tools/firefox/setup.py
    add-history firefox
    add-test-command "file /root/.mozilla/firefox/*.Exegol"
    add-test-command "firefox --version"
    add-to-list "firefox,https://www.mozilla.org,A web browser"
}

function install_rvm() {
    # CODE-CHECK-WHITELIST=add-aliases,add-history,add-to-list
    colorecho "Installing rvm"
    gpg --keyserver hkp://keyserver.ubuntu.com --recv-keys 409B6B1796C275462A1703113804BB82D39DC0E3 7D2BAF1CF37B13E2069D6956105BD0E739499BDB
    curl -sSL https://get.rvm.io | bash -s stable --ruby
    source /usr/local/rvm/scripts/rvm
    rvm autolibs read-fail
    rvm rvmrc warning ignore allGemfiles
    gem update
    add-test-command "rvm --help"
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
    if [ -d /root/.oh-my-zsh ]; then
        return
    fi
    colorecho "Installing oh-my-zsh, config, history, aliases"
    sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)"
    cp -v /root/sources/assets/zsh/zshrc ~/.zshrc
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
    python3 -m pip install pipx
    pipx ensurepath
    add-test-command "pipx --version"
}

function install_yarn() {
    # CODE-CHECK-WHITELIST=add-aliases,add-history,add-to-list
    colorecho "Installing yarn"
    curl -sS https://dl.yarnpkg.com/debian/pubkey.gpg | apt-key add -
    echo "deb https://dl.yarnpkg.com/debian/ stable main" | tee /etc/apt/sources.list.d/yarn.list
    apt update
    fapt yarn
    add-test-command "yarn --help"
}

function install_ultimate_vimrc() {
    # CODE-CHECK-WHITELIST=add-aliases,add-history,add-test-command,add-to-list
    if [ -d /root/.vim_runtime ]; then
        return
    fi
    colorecho "Installing The Ultimate vimrc"
    git clone --depth 1 https://github.com/amix/vimrc.git ~/.vim_runtime
    sh ~/.vim_runtime/install_awesome_vimrc.sh
}

function install_mdcat() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing mdcat"
    cargo install mdcat
    source "$HOME/.cargo/env"
    add-history mdcat
    add-test-command "mdcat --version"
    add-to-list "mdcat,https://github.com/swsnr/mdcat,Fancy cat for Markdown"
}

function install_gf() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing gf"
    # A wrapper around grep, to help you grep for things
    go install -v github.com/tomnomnom/gf@latest
    # Enable autocompletion
    echo 'source $GOPATH/pkg/mod/github.com/tomnomnom/gf@*/gf-completion.zsh' >> ~/.zshrc
    cp -r /root/go/pkg/mod/github.com/tomnomnom/gf@*/examples ~/.gf
    # Add patterns from 1ndianl33t
    git -C /opt/tools/ clone --depth 1 https://github.com/1ndianl33t/Gf-Patterns
    cp -r /opt/tools/Gf-Patterns/*.json ~/.gf
    # Remove repo to save space
    rm -r /opt/tools/Gf-Patterns
    add-history gf
    add-test-command "gf --list"
    add-test-command "ls ~/.gf | grep 'redirect.json'"
    add-to-list "gf,https://github.com/tomnomnom/gf,A wrapper around grep to avoid typing common patterns"
}

function post_install() {
    # Function used to clean up post-install files
    colorecho "Cleaning..."
    updatedb
    rm -rfv /tmp/*
    colorecho "Sorting tools list"
    (head -n 1 /.exegol/installed_tools.csv && tail -n +2 /.exegol/installed_tools.csv | sort -f ) | tee /tmp/installed_tools.csv.sorted
    mv /tmp/installed_tools.csv.sorted /.exegol/installed_tools.csv
    colorecho "Adding end-of-preset in zsh_history"
    echo "# -=-=-=-=-=-=-=- YOUR COMMANDS BELOW -=-=-=-=-=-=-=- #" >> ~/.zsh_history
}

# Package dedicated to the basic things the env needs
function package_base() {
    update
    colorecho "Installing apt-fast for faster dep installs"
    apt-get install -y curl sudo wget
    /bin/bash -c "$(curl -sL https://git.io/vokNn)" # Install apt-fast
    deploy_exegol
    install_exegol-history
    fapt software-properties-common
    add-apt-repository contrib
    add-apt-repository non-free
    apt-get update
    chsh -s /bin/zsh
    colorecho "Starting main programs install"
    fapt man git lsb-release pciutils pkg-config zip unzip kmod gnupg2 python2 wget \
    gnupg2 python2-dev python3-dev python3-venv libffi-dev python3-pip zsh asciinema \
    python-setuptools python3-setuptools npm gem automake autoconf make cmake time gcc g++ file lsof \
    less x11-apps net-tools vim nano jq iputils-ping iproute2 tidy mlocate libtool \
    dos2unix ftp sshpass telnet nfs-common ncat netcat-traditional socat rdate putty \
    screen p7zip-full p7zip-rar unrar xz-utils xsltproc parallel tree ruby ruby-dev ruby-full bundler \
    nim perl libwww-perl openjdk-17-jre openjdk-11-jre openjdk-11-jdk-headless openjdk-17-jdk-headless openjdk-11-jdk openjdk-17-jdk openvpn openresolv logrotate tmux tldr bat python3-pyftpdlib libxml2-utils \
    virtualenv chromium libsasl2-dev python-dev libldap2-dev libssl-dev isc-dhcp-client sqlite3

    fapt-history dnsutils samba ssh snmp faketime
    fapt-aliases php python3 grc emacs-nox xsel

    install_rust_cargo
    install_rvm                                         # Ruby Version Manager
    ln -s /bin/mkdir /usr/bin/mkdir                     # Some tools need this path for build

    ln -s -v /usr/lib/jvm/java-11-openjdk-* /usr/lib/jvm/java-11-openjdk    # To avoid determining the correct path based on the architecture
    ln -s -v /usr/lib/jvm/java-17-openjdk-* /usr/lib/jvm/java-17-openjdk    # To avoid determining the correct path based on the architecture
    update-alternatives --set java /usr/lib/jvm/java-17-openjdk-*/bin/java  # Set the default openjdk version to 17

    ln -fs /usr/bin/python2.7 /usr/bin/python # Default python is set to 2.7
    install_python-pip                                  # Pip. Should we set pip2 to default?
    python3 -m pip install --upgrade pip
    filesystem
    install_go                                          # Golang language
    set_go_env
    install_locales
    install_ohmyzsh                                     # Awesome shell
    install_fzf                                         # Fuzzy finder
    python3 -m pip install wheel
    python -m pip install wheel
    install_pipx
    add-history curl
    install_yarn
    install_ultimate_vimrc                              # Make vim usable OOFB
    install_mdcat                                       # cat markdown files
    add-aliases bat
    add-test-command "bat --version"
    DEBIAN_FRONTEND=noninteractive fapt macchanger      # Macchanger
    install_gf                                          # wrapper around grep
    fapt-noexit rar                                     # rar (Only AMD)
    install_firefox

    cp -v /root/sources/assets/grc/grc.conf /etc/grc.conf # grc

    # openvpn
    # Fixing openresolv to update /etc/resolv.conf without resolvectl daemon (with a fallback if no DNS server are supplied)
    line=$(($(grep -n 'up)' /etc/openvpn/update-resolv-conf | cut -d ':' -f1) +1))
    sed -i ${line}'i cp /etc/resolv.conf /etc/resolv.conf.backup' /etc/openvpn/update-resolv-conf

    line=$(($(grep -n 'resolvconf -a' /etc/openvpn/update-resolv-conf | cut -d ':' -f1) +1))
    sed -i ${line}'i [ "$(resolvconf -l "tun*" | grep -vE "^(\s*|#.*)$")" ] && /sbin/resolvconf -u || cp /etc/resolv.conf.backup /etc/resolv.conf' /etc/openvpn/update-resolv-conf
    line=$(($line + 1))
    sed -i ${line}'i rm /etc/resolv.conf.backup' /etc/openvpn/update-resolv-conf
    add-test-command "openvpn --version"

    # logrotate
    mv /root/sources/assets/logrotate/* /etc/logrotate.d/
    chmod 644 /etc/logrotate.d/*

    # tmux
    cp -v /root/sources/assets/tmux/tmux.conf ~/.tmux.conf
    touch ~/.hushlogin

    # TLDR
    mkdir -p ~/.local/share/tldr
    tldr -u

    # NVM (install in conctext)
    zsh -c "source ~/.zshrc && nvm install node"

    # Set Global config path to vendor
    # All programs using bundle will store their deps in vendor/
    bundle config path vendor/

    # Remote Graphical Desktop installation
}

# FOR DEBUGGING, FAST MINIMAL INSTALL
# TODO MOVE THIS IN ANOTHER SEPARATE FILE
function package_base_debug() {
    update
    colorecho "Installing apt-fast for faster dep installs"
    apt-get install -y curl sudo wget
    /bin/bash -c "$(curl -sL https://git.io/vokNn)" # Install apt-fast
    deploy_exegol
    install_exegol-history
    fapt software-properties-common
    add-apt-repository contrib
    add-apt-repository non-free
    apt-get update
    colorecho "Starting main programs install"
    fapt sudo git curl zsh asciinema zip wget ncat dnsutils python2 python3 python3-setuptools python3-pip vim nano procps automake autoconf make bundler mlocate

    fapt-history dnsutils samba ssh snmp faketime
    fapt-aliases php python3 grc emacs-nox xsel

    ln -fs /usr/bin/python2.7 /usr/bin/python # Default python is set to 2.7
#    python3 -m pip install --upgrade pip
    filesystem
    install_locales
    install_ohmyzsh                                     # Awesome shell
    install_fzf                                         # Fuzzy finder
    install_pipx
    add-history curl

    # Set Global config path to vendor
    # All programs using bundle will store their deps in vendor/
    bundle config path vendor/
}
