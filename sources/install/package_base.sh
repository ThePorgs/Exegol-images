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

function install_python2() {
    PYTHONIOENCODING=UTF-8
    PYTHON_VERSION=2.7.18
    fapt gir1.2-rsvg-2.0 libdb5.3-dev libdjvulibre-dev libdjvulibre-text libdjvulibre21 libevent-extra-2.1-7 libevent-openssl-2.1-7 libevent-pthreads-2.1-7  libexif-dev libimath-3-1-29 \
    libimath-dev liblcms2-dev liblqr-1-0-dev libltdl-dev libmagickcore-6-arch-config libmagickcore-6-headers  libmagickcore-6.q16-6-extra libmagickcore-6.q16-dev libmagickwand-6-headers \
    libmagickwand-6.q16-dev libmariadb-dev-compat libopenexr-3-1-30 libopenexr-dev libopenjp2-7-dev librsvg2-dev libwmf-0.2-7 libwmf-dev libwmflite-0.2-7 libsqlite3-dev \
    default-libmysqlclient-dev libdb-dev libevent-dev libmagickcore-dev libmagickwand-dev libmaxminddb-dev libncursesw5-dev
    wget -O python.tar.xz "https://www.python.org/ftp/python/${PYTHON_VERSION%%[a-z]*}/Python-$PYTHON_VERSION.tar.xz"
    mkdir -p /usr/src/python 
    tar -xJC /usr/src/python --strip-components=1 -f python.tar.xz
    rm python.tar.xz
    cd /usr/src/python 
    gnuArch="$(dpkg-architecture --query DEB_BUILD_GNU_TYPE)" 
    ./configure --build="$gnuArch" --enable-optimizations --enable-option-checking=fatal --enable-shared --enable-unicode=ucs4 
    make -j "$(nproc)" PROFILE_TASK='-m test.regrtest --pgo test_array test_base64 test_binascii test_binhex test_binop test_bytes test_c_locale_coercion test_class test_cmath test_codecs test_compile test_complex test_csv test_decimal test_dict test_float test_fstring test_hashlib test_io test_iter test_json test_long test_math test_memoryview test_pickle test_re test_set test_slice test_struct test_threading test_time test_traceback test_unicode ' 
    make install 
    ldconfig 
    find /usr/local -depth \( \( -type d -a \( -name test -o -name tests -o -name idle_test \) \) -o \( -type f -a \( -name '*.pyc' -o -name '*.pyo' \) \) \) -exec rm -rf '{}' +
    rm -rf /usr/src/python
    add-test-command "python2 --version"
    cd /root/sources/install
}

function install_python-pip() {
    colorecho "Installing python-pip (for Python2.7)"
    PYTHON_PIP_VERSION=20.0.2
    PYTHON_GET_PIP_URL=https://raw.githubusercontent.com/pypa/get-pip/23.2.1/public/2.7/get-pip.py
    wget -O get-pip.py "$PYTHON_GET_PIP_URL"
    python2 get-pip.py "pip==$PYTHON_PIP_VERSION" --disable-pip-version-check --no-cache-dir
    pip --version
    find /usr/local -depth \( \( -type d -a \( -name test -o -name tests -o -name idle_test \) \) -o \( -type f -a \( -name '*.pyc' -o -name '*.pyo' \) \) \) -exec rm -rf '{}' +
    rm -f get-pip.py
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
    { command -v gpgconf > /dev/null && gpgconf --kill all || :; }
    curl -sSL https://get.rvm.io | bash -s stable --ruby=3.1.2
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
    apt-get update
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
        cd neovim
        make CMAKE_BUILD_TYPE=RelWithDebInfo
        make install
        cd ..
        rm -rf ./neovim
    fi
    add-test-command "nvim --version"
    add-to-list "neovim,https://neovim.io/,hyperextensible Vim-based text editor"
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

function add-repository() {
    source_file="/etc/apt/sources.list.d/debian.sources"  # Remplacez par le chemin de votre fichier
    out_file="/etc/apt/sources.list.d/debian2.sources"  # Remplacez par le chemin de votre fichier

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
    updatedb
    rm -rfv /tmp/*
    rm -rfv /var/lib/apt/lists/*
    rm -rfv /root/sources
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
    add-repository # add-apt-repository does not work
    apt-get update
    chsh -s /bin/zsh
    colorecho "Starting main programs install"
    fapt man git lsb-release pciutils pkg-config zip unzip kmod gnupg2 wget \
    python3-dev python3-venv libffi-dev python3-pip zsh asciinema \
    python3-setuptools npm gem automake autoconf make cmake time gcc g++ file lsof \
    less x11-apps net-tools vim nano jq iputils-ping iproute2 tidy mlocate libtool \
    dos2unix ftp sshpass telnet nfs-common ncat netcat-traditional socat rdate putty \
    screen p7zip-full p7zip-rar unrar xz-utils xsltproc parallel tree ruby ruby-dev ruby-full bundler \
    nim perl libwww-perl openjdk-17-jre openjdk-17-jdk-headless openjdk-17-jdk openvpn openresolv logrotate tmux tldr bat python3-pyftpdlib libxml2-utils \
    virtualenv chromium libsasl2-dev libldap2-dev libssl-dev isc-dhcp-client sqlite3 tk-dev libssl-dev
    install_python2
    install_python-pip                                  # Pip. Should we set pip2 to default?
    pip install --no-cache-dir virtualenv

    rm /usr/lib/python3.*/EXTERNALLY-MANAGED # https://stackoverflow.com/questions/75608323/how-do-i-solve-error-externally-managed-environment-everytime-i-use-pip3

    fapt-history dnsutils samba ssh snmp faketime
    fapt-aliases php python3 grc emacs-nox xsel

    install_rust_cargo
    install_rvm                                         # Ruby Version Manager

    ln -s -v /usr/lib/jvm/java-17-openjdk-* /usr/lib/jvm/java-17-openjdk    # To avoid determining the correct path based on the architecture
    update-alternatives --set java /usr/lib/jvm/java-17-openjdk-*/bin/java  # Set the default openjdk version to 17

    ln -fs /usr/local/bin/python /usr/bin/python2.7
    ln -fs /usr/local/bin/python /usr/bin/python2
    ln -fs /usr/local/bin/python /usr/bin/python
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
    install_neovim
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
    add-repository # add-apt-repository does not work
    apt-get update
    colorecho "Starting main programs install"
    fapt sudo git curl zsh asciinema zip wget ncat dnsutils python3 python3-setuptools python3-pip vim nano procps automake autoconf make bundler mlocate tk-dev gnupg2 gcc g++ libssl-dev
    install_python2
    install_python-pip                                  # Pip. Should we set pip2 to default?

    rm /usr/lib/python3.*/EXTERNALLY-MANAGED # https://stackoverflow.com/questions/75608323/how-do-i-solve-error-externally-managed-environment-everytime-i-use-pip3

    fapt-history dnsutils samba ssh snmp faketime
    fapt-aliases php python3 grc emacs-nox xsel

    ln -fs /usr/local/bin/python /usr/bin/python2.7
    ln -fs /usr/local/bin/python /usr/bin/python2
    ln -fs /usr/local/bin/python /usr/bin/python
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
