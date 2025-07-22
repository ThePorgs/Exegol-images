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
    git -C /opt/tools/ clone --depth 1 https://github.com/ThePorgs/Exegol-history
    cd /opt/tools/Exegol-history || exit
    pipx install --system-site-packages /opt/tools/Exegol-history
    # Temp fix add default profile.sh back to root directory
    if check_temp_fix_expiry "2025-09-01"; then
      [ -f /opt/tools/Exegol-history/profile.sh ] || cp /opt/tools/Exegol-history/exegol_history/config/profile.sh /opt/tools/Exegol-history/profile.sh
    fi
    add-aliases exegol-history
    add-history exegol-history
    add-test-command "exh -h"
    add-to-list "exegol-history,https://github.com/ThePorgs/Exegol-history,Credentials management for Exegol"
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
    mkdir -p /opt/tools/bin/ /data/ /var/log/exegol /.exegol/ /opt/rules/ /opt/lists
    touch /.exegol/unit_tests_all_commands.txt
    touch /.exegol/installed_tools.csv
    echo "Tool,Link,Description" >> /.exegol/installed_tools.csv
}

function install_go() {
    # CODE-CHECK-WHITELIST=add-aliases,add-to-list,add-history
    colorecho "Installing go (Golang)"
    asdf plugin add golang https://github.com/asdf-community/asdf-golang.git
    # 1.19 needed by sliver
    asdf install golang 1.19
    #asdf install golang latest
    #asdf set --home golang latest
    # With golang 1.23 many package build are broken, temp fix to use 1.22.2 as golang latest
    local temp_fix_limit="2025-09-01"
    if check_temp_fix_expiry "$temp_fix_limit"; then
      # 1.24.1 needed for GoExec
      asdf install golang 1.24.1
      # 1.23 needed by BloodHound-CE, and sensepost/ruler
      asdf install golang 1.23.0
      # Default GO version: 1.22.2
      asdf install golang 1.22.2
      asdf set --home golang 1.22.2
    fi

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
    set_python_env
    local v
    colorecho "Installing python2 (latest)"
    fapt libssl-dev zlib1g-dev libbz2-dev libreadline-dev libsqlite3-dev libncurses5-dev libncursesw5-dev libffi-dev liblzma-dev
    # Don't think it's needed, but if something fails, use command below
    # apt install xz-utils tk-dev
    for v in $PYTHON_VERSIONS; do
        colorecho "Installing python${v}"
        pyenv install "$v"
    done
    # allowing python2, python3, python3.10, python3.11 and python3.13 to be found
    #  --> python points to python3
    #  --> python3 points to python3.11
    #  --> python3.13 points to 3.13
    #  --> python3.10 points to 3.10
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
    fapt python3-venv
    add-test-command "python3 -m venv -h"
}

function install_firefox() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing firefox"
    fapt firefox-esr
    mkdir /opt/tools/firefox
    mv /root/sources/assets/firefox/* /opt/tools/firefox/
    pip3 install -r /opt/tools/firefox/requirements.txt
    python3 /opt/tools/firefox/generate_policy.py
    add-history firefox
    add-test-command "cat /usr/lib/firefox-esr/distribution/policies.json|grep 'Exegol'"
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
    rvm install ruby-3.1.2  # needed by cewl, pass-station, evil-winrm
    rvm install ruby-3.1.5  # needed metasploit-framework
    rvm get head
    rvm cleanup all
    gem update
    add-test-command "rvm --version"
}

function install_fzf() {
    # CODE-CHECK-WHITELIST=add-history
    colorecho "Installing fzf"
    git -C /opt/tools clone --depth 1 https://github.com/junegunn/fzf.git
    yes|/opt/tools/fzf/install
    add-aliases fzf
    add-test-command "source ~/.fzf.zsh && fzf-wordlists --help"
    add-test-command "source ~/.fzf.zsh && fzf --help"
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

function install_pyftpdlib() {
    # CODE-CHECK-WHITELIST=add-history
    colorecho "Installing pyftpdlib"
    pip3 install pyftpdlib
    add-aliases pyftpdlib
    add-test-command "python3 -c 'import pyftpdlib'"
    add-to-list "pyftpdlib,https://github.com/giampaolo/pyftpdlib/,Extremely fast and scalable Python FTP server library"
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
    colorecho "Installing neovim/nvim"
    # CODE-CHECK-WHITELIST=add-aliases,add-history
    if [[ $(uname -m) = 'x86_64' ]]
    then
        curl --location --output nvim.appimage "https://github.com/neovim/neovim/releases/latest/download/nvim-linux-x86_64.appimage"
        chmod u+x nvim.appimage
        ./nvim.appimage --appimage-extract
        mkdir /opt/tools/nvim
        cp -rv squashfs-root/usr/* /opt/tools/nvim
        rm -rf squashfs-root nvim.appimage
        ln -v -s /opt/tools/nvim/bin/nvim /opt/tools/bin/nvim
    elif [[ $(uname -m) = 'aarch64' ]]
    then
        # Building, because when using release, error is raised: "./bin/nvim: /lib/aarch64-linux-gnu/libm.so.6: version `GLIBC_2.38' not found (required by ./bin/nvim)"
        # https://github.com/neovim/neovim/issues/32496
        # Would require a bump in glibc, using old releases, or manually building. So manual build it is.
        fapt gettext
        git clone --depth 1 https://github.com/neovim/neovim.git
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
      cat "$(sh -c "go env GOPATH")"/pkg/mod/github.com/tomnomnom/gf@*/gf-completion.zsh
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
    for x in /usr/lib/jvm/java-11-openjdk/bin/*; do
      BIN_NAME=$(echo "$x" | rev | cut -d '/' -f1 | rev)
      update-alternatives --install "/usr/bin/$BIN_NAME" "$BIN_NAME" "$x" 11;
    done
    ln -s -v /usr/lib/jvm/java-11-openjdk/bin/java /usr/bin/java11
    add-test-command "/usr/lib/jvm/java-11-openjdk/bin/java --version"
    add-test-command "java11 --version"
}

function install_java21() {
    # CODE-CHECK-WHITELIST=add-history,add-aliases,add-to-list
    colorecho "Installing java 21"
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
    for x in /usr/lib/jvm/java-21-openjdk/bin/*; do
      BIN_NAME=$(echo "$x" | rev | cut -d '/' -f1 | rev)
      update-alternatives --install "/usr/bin/$BIN_NAME" "$BIN_NAME" "$x" 21;
    done
    ln -s -v /usr/lib/jvm/java-21-openjdk/bin/java /usr/bin/java21
    add-test-command "/usr/lib/jvm/java-21-openjdk/bin/java --version"
    add-test-command "java21 --version"
}

function install_java24() {
    # CODE-CHECK-WHITELIST=add-history,add-aliases,add-to-list
    colorecho "Installing java 24"
    if [[ $(uname -m) = 'x86_64' ]]
    then
        wget -O /tmp/openjdk24-jdk.tar.gz "https://download.java.net/java/GA/jdk24/1f9ff9062db4449d8ca828c504ffae90/36/GPL/openjdk-24_linux-x64_bin.tar.gz"

    elif [[ $(uname -m) = 'aarch64' ]]
    then
        wget -O /tmp/openjdk24-jdk.tar.gz "https://download.java.net/java/GA/jdk24/1f9ff9062db4449d8ca828c504ffae90/36/GPL/openjdk-24_linux-aarch64_bin.tar.gz"
    else
        criticalecho-noexit "This installation function doesn't support architecture $(uname -m)" && return
    fi
    tar -xzf /tmp/openjdk24-jdk.tar.gz --directory /tmp
    mkdir -p "/usr/lib/jvm"
    mv /tmp/jdk-24* /usr/lib/jvm/java-24-openjdk
    for x in /usr/lib/jvm/java-24-openjdk/bin/*; do
      BIN_NAME=$(echo "$x" | rev | cut -d '/' -f1 | rev)
      update-alternatives --install "/usr/bin/$BIN_NAME" "$BIN_NAME" "$x" 24;
    done
    ln -s -v /usr/lib/jvm/java-24-openjdk/bin/java /usr/bin/java24
    add-test-command "/usr/lib/jvm/java-24-openjdk/bin/java --version"
    add-test-command "java24 --version"
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

function install_asdf() {
    # CODE-CHECK-WHITELIST=add-aliases,add-history
    colorecho "Installing asdf"
    local URL
    if [[ $(uname -m) = 'x86_64' ]]
    then
        URL=$(curl --location --silent "https://api.github.com/repos/asdf-vm/asdf/releases/latest" | grep 'browser_download_url.*asdf.*linux-amd64.tar.gz"' | grep -o 'https://[^"]*')
    elif [[ $(uname -m) = 'aarch64' ]]
    then
        URL=$(curl --location --silent "https://api.github.com/repos/asdf-vm/asdf/releases/latest" | grep 'browser_download_url.*asdf.*linux-arm64.tar.gz"' | grep -o 'https://[^"]*')
    else
        criticalecho-noexit "This installation function doesn't support architecture $(uname -m)" && return
    fi
    curl --location -o /tmp/asdf.tar.gz "$URL"
    tar -xf /tmp/asdf.tar.gz --directory /tmp
    rm /tmp/asdf.tar.gz
    mv /tmp/asdf /opt/tools/bin/asdf
    set_bin_path
    set_asdf_env
    # asdf completions
    mkdir -p "${ASDF_DATA_DIR:-$HOME/.asdf}/completions"
    asdf completion zsh > "${ASDF_DATA_DIR:-$HOME/.asdf}/completions/_asdf"
    add-test-command "asdf version"
    add-to-list "asdf,https://github.com/asdf-vm/asdf,Extendable version manager with support for ruby python go etc"
}

function install_openvpn() {
  # CODE-CHECK-WHITELIST=add-aliases,add-history
  colorecho "Installing OpenVPN"
  fapt openvpn openresolv

  # Fixing openresolv to update /etc/resolv.conf without resolvectl daemon (with a fallback if no DNS server are supplied)
  LINE=$(($(grep -n 'up)' /etc/openvpn/update-resolv-conf | cut -d ':' -f1) +1))
  sed -i "${LINE}"'i cp /etc/resolv.conf /etc/resolv.conf.backup' /etc/openvpn/update-resolv-conf

  LINE=$(($(grep -n 'resolvconf -a' /etc/openvpn/update-resolv-conf | cut -d ':' -f1) +1))
  # shellcheck disable=SC2016
  sed -i "${LINE}"'i [ "$((resolvconf -l "tun*" 2>/dev/null || resolvconf -l "tap*") | grep -vE "^(\s*|#.*)$")" ] && /sbin/resolvconf -u || cp /etc/resolv.conf.backup /etc/resolv.conf' /etc/openvpn/update-resolv-conf
  ((LINE++))
  sed -i "${LINE}"'i rm /etc/resolv.conf.backup' /etc/openvpn/update-resolv-conf

  add-test-command "openvpn --version"
  add-to-list "OpenVPN,https://openvpn.net/,Fast and Easy Zero-Trust VPN Fully in Your Control"
}

function install_wireguard() {
  # CODE-CHECK-WHITELIST=add-aliases,add-history
  colorecho "Installing WireGuard"
  fapt wireguard

  # Patch wireguard start script https://github.com/WireGuard/wireguard-tools/pull/5
  local temp_fix_limit="2025-12-01"
  if check_temp_fix_expiry "$temp_fix_limit"; then
    # shellcheck disable=SC2016
    sed -i 's/\[\[ \$proto == -4 \]\] && cmd sysctl -q net\.ipv4\.conf\.all\.src_valid_mark=1/[[ $proto == -4 ]] \&\& [[ $(sysctl -n net.ipv4.conf.all.src_valid_mark) -ne 1 ]] \&\& cmd sysctl -q net.ipv4.conf.all.src_valid_mark=1/' "$(which wg-quick)"
  fi
  add-test-command "wg-quick -h"
  add-to-list "wireguard,https://www.wireguard.com,WireGuard is an extremely simple yet fast and modern VPN that utilizes state-of-the-art cryptography"
}

# Package dedicated to the basic things the env needs
function package_base() {
    local start_time
    local end_time
    start_time=$(date +%s)
    update
    colorecho "Installing apt-fast for faster dep installs"
    apt-get install -y curl sudo wget
    # splitting curl | bash to avoid having additional logs put in curl output being executed because of catch_and_retry
    curl -sL https://git.io/vokNn -o /tmp/apt-fast-install.sh
    bash /tmp/apt-fast-install.sh
    deploy_exegol
    fapt software-properties-common
    add_debian_repository_components
    cp -v /root/sources/assets/apt/sources.list.d/* /etc/apt/sources.list.d/
    cp -v /root/sources/assets/apt/preferences.d/* /etc/apt/preferences.d/
    apt-get update
    colorecho "Starting main programs install"
    fapt man git lsb-release pciutils pkg-config zip unzip kmod gnupg2 wget \
    libffi-dev zsh asciinema npm gem automake autoconf make cmake time gcc g++ file lsof \
    less x11-apps net-tools vim nano jq iputils-ping iproute2 tidy mlocate libtool \
    dos2unix ftp sshpass telnet nfs-common ncat netcat-traditional socat rdate putty \
    screen p7zip-full p7zip-rar unrar xz-utils xsltproc parallel tree ruby ruby-dev ruby-full bundler \
    nim perl libwww-perl openjdk-17-jdk \
    logrotate tmux tldr bat libxml2-utils virtualenv chromium libsasl2-dev \
    libldap2-dev libssl-dev isc-dhcp-client sqlite3 dnsutils samba ssh snmp faketime php \
    python3 python3-dev grc emacs-nox xsel xxd libnss3-tools
    apt-mark hold tzdata  # Prevent apt upgrade error when timezone sharing is enable

    filesystem
    install_locales
    cp -v /root/sources/assets/shells/exegol_shells_rc /opt/.exegol_shells_rc
    cp -v /root/sources/assets/shells/bashrc ~/.bashrc

    install_asdf

    # setup Python environment
    # the order matters (if 2 is before 3, `python` will point to Python 2)
    PYTHON_VERSIONS="3.11 3.13 3.10 2"
    install_pyenv
    pip2 install --no-cache-dir virtualenv
    local v
    for v in $PYTHON_VERSIONS; do
        # shellcheck disable=SC2086
        pip${v} install --upgrade pip
        # shellcheck disable=SC2086
        pip${v} install wheel
    done
    install_pipx

    # change default shell
    chsh -s /bin/zsh

    add-history sshpass
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

    # Rust, Cargo, rvm
    install_rust_cargo
    install_rvm                                         # Ruby Version Manager

    # java11 install, java21 install, and java17 as default
    install_java11
    install_java21
    #install_java24  # Ready to be install when needed as replacement of java21 ?
    ln -s -v /usr/lib/jvm/java-17-openjdk-* /usr/lib/jvm/java-17-openjdk    # To avoid determining the correct path based on the architecture
    ln -s -v /usr/lib/jvm/java-17-openjdk/bin/java /usr/bin/java17          # Add java17 bin
    update-alternatives --set java /usr/lib/jvm/java-17-openjdk-*/bin/java  # Set the default openjdk version to 17

    install_go                                          # Golang language
    install_ohmyzsh                                     # Awesome shell
    install_fzf                                         # Fuzzy finder
    add-history curl
    install_yarn
    install_pyftpdlib
    install_ultimate_vimrc                              # Make vim usable OOFB
    install_neovim
    install_mdcat                                       # cat markdown files
    add-aliases bat
    add-test-command "bat --version"
    DEBIAN_FRONTEND=noninteractive fapt macchanger      # Macchanger
    install_gf                                          # wrapper around grep
    install_openvpn
    install_wireguard
    install_firefox

    cp -v /root/sources/assets/grc/grc.conf /etc/grc.conf # grc

    # logrotate
    mv /root/sources/assets/logrotate/* /etc/logrotate.d/
    chmod 644 /etc/logrotate.d/*

    # tmux
    cp -v /root/sources/assets/shells/tmux.conf ~/.tmux.conf
    touch ~/.hushlogin

    # TLDR
    mkdir -p ~/.local/share/tldr
    tldr -u

    # NVM (install in context)
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

    install_exegol-history

    post_install
    end_time=$(date +%s)
    local elapsed_time=$((end_time - start_time))
    colorecho "Package base completed in $elapsed_time seconds."
}
