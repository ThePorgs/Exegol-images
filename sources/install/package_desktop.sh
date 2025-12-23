# Author: The Exegol Project

source common.sh

set -e

function install_kasmvnc() {
    # CODE-CHECK-WHITELIST=add-aliases,add-history,add-test-command,add-to-list
    colorecho "Installing kasmVNC"

    # Detect architecture
    local arch
    if [[ $(uname -m) = 'x86_64' ]]; then
        arch="amd64"
    elif [[ $(uname -m) = 'aarch64' ]]; then
        arch="arm64"
    else
        criticalecho-noexit "This installation function doesn't support architecture $(uname -m)" && return
    fi

    # Get latest release tag from GitHub API (not master branch)
    local kasmvnc_url
    kasmvnc_url=$(curl --location --silent "https://api.github.com/repos/kasmtech/KasmVNC/releases/latest" | grep 'browser_download_url.*kasmvncserver_bookworm.*_'"$arch"'.deb"' | grep -o 'https://[^"]*')
    wget -O /tmp/kasmvncserver.deb "${kasmvnc_url}"
    
    # Install kasmVNC package (use apt-get install for local .deb files to handle dependencies)
    # Will throw a notice about the download being performed unsandboxed
    fapt /tmp/kasmvncserver.deb
    rm /tmp/kasmvncserver.deb
    
    # Add user to ssl-cert group (required by kasmVNC)
    usermod -a -G ssl-cert root

    # https://kasmweb.com/kasmvnc/docs/master/serverside.html#users
    echo -e "123Pentest\n123Pentest\n" | vncpasswd -u test -w -r
    # TODO : add a standard user, and modify its password later. 
    # This is the user that will be used to connect to KasmVNC.

    # Customization
    if [[ -d "/usr/share/kasmvnc/www" ]]; then
        mkdir -p /usr/share/kasmvnc/www/app/images/icons/
        cp -rv /root/sources/assets/desktop/exegol_logo.png /usr/share/kasmvnc/www/app/images/icons/  
    fi
    # TODO : customize Title and icon in /usr/share/kasmvnc/www/vnc.html and index.html
    
    add-to-list "kasmvnc,https://github.com/kasmtech/KasmVNC,KasmVNC is a modern VNC server with built-in web client"
}

function install_xfce() {
    # CODE-CHECK-WHITELIST=add-aliases,add-history,add-test-command,add-to-list
    colorecho "Installing and configuring xfce desktop"

    # DEBUG TOOLS
    # TODO remove
    fapt terminator iproute2

    # Dependencies - keep tigervnc-viewer for VNC client and tigervnc-standalone-server for vnc server, but use kasmVNC server instead of tigervnc-server + noVNC for https server
    # kasmVNC has built-in web server, so no websockify needed
    fapt tigervnc-standalone-server tigervnc-xorg-extension tigervnc-viewer xfce4 dbus-x11 intltool libtool tigervnc-tools

    # Install kasmVNC (replaces tigervnc-standalone-server, novnc, and websockify - kasmVNC has built-in web server)
    install_kasmvnc

    # Icons
    fapt librsvg2-common papirus-icon-theme

    # VNC
    mkdir ~/.vnc
    cp /root/sources/assets/desktop/configuration/xstartup.conf ~/.vnc/xstartup
    chmod u+x ~/.vnc/xstartup

    # Theme
    mkdir /root/.themes
    cp /root/sources/assets/desktop/Prof_XFCE_2_1.tar.gz /tmp
    cd /tmp
    tar -xvf ./Prof_XFCE_2_1.tar.gz
    mv 'Prof--XFCE- 2.1' Prof_XFCE_2_1
    cp -r ./Prof_XFCE_2_1 /root/.themes/
    rm -rf /tmp/Prof*

    # Dock
    fapt xfce4-dev-tools libglib2.0-dev libgtk-3-dev libwnck-3-dev libxfce4ui-2-dev libxfce4panel-2.0-dev g++ build-essential
    git -C /tmp clone --branch xfce4-docklike-plugin-0.4.2 --depth 1 https://gitlab.xfce.org/panel-plugins/xfce4-docklike-plugin.git
    cd /tmp/xfce4-docklike-plugin
    sh autogen.sh --prefix=/tmp/
    make -j
    make install clean
    CUSTOM_PATH=$(find /usr/lib/ -name "xfce*"|head -n1)
    mv -v /tmp/lib/xfce4/panel/plugins/libdocklike.* "$CUSTOM_PATH/panel/plugins"
    mv -v /tmp/share/xfce4/panel/plugins/docklike.desktop /usr/share/xfce4/panel/plugins

    # Locale
    cp -rv /tmp/share/locale/* /usr/share/locale
    rm -rf /tmp/*

    # Wallpapers
    cp -rv /root/sources/assets/desktop/wallpapers /usr/share/backgrounds/exegol



    # Desktop
    touch /root/.Xauthority
    export DISPLAY=":0"
    update-alternatives --quiet --set vncserver $(update-alternatives --list vncserver|grep tiger)
    vncserver -localhost yes -geometry 1920x1080 -SecurityTypes Plain :1
    sleep 10
    xfconf-query -c xsettings -p /Net/ThemeName -s Prof_XFCE_2_1
    xfconf-query -c xsettings -p /Net/IconThemeName -s Papirus-Dark
    sed -i "s#Default#Prof_XFCE_2_1#g" /root/.config/xfce4/xfconf/xfce-perchannel-xml/xfwm4.xml
    mkdir /root/.config/xfce4/appfinder/
    mkdir /root/.config/terminator/
    cp /root/sources/assets/desktop/configuration/bookmarks /root/.config/xfce4/appfinder/bookmarks
    cp /root/sources/assets/desktop/configuration/config /root/.config/terminator/config
    cp /root/sources/assets/desktop/configuration/docklike-2.rc /root/.config/xfce4/panel/docklike-2.rc
    cp /root/sources/assets/desktop/configuration/xfce4-panel.xml /root/.config/xfce4/xfconf/xfce-perchannel-xml/xfce4-panel.xml
    cp /root/sources/assets/desktop/configuration/xfce4-desktop.xml /root/.config/xfce4/xfconf/xfce-perchannel-xml/xfce4-desktop.xml
    cp /root/sources/assets/desktop/configuration/xsettings.xml /root/.config/xfce4/xfconf/xfce-perchannel-xml/xsettings.xml

    # Menu
    # TODO : enable custom config in my-resources
    mkdir /root/.config/menus/
    cp /root/sources/assets/desktop/configuration/xfce-applications.menu ~/.config/menus/xfce-applications.menu
    cp /root/sources/assets/desktop/configuration/exegol.directory /usr/share/desktop-directories/exegol.directory
    cp /root/sources/assets/desktop/applications/* /usr/share/applications/

    # Stopping VNC server used for config
    vncserver -kill :1
    sleep 6
    update-alternatives --quiet --set vncserver $(update-alternatives --list vncserver|grep kasm)
    vncserver -select-de XFCE
    sleep 10
    vncserver -kill $(vncserver -list|grep -Po '^:[0-9]+')
    # Remove log files of temp vncserver run ## TODO check if more
    rm /root/.vnc/*.log /root/.xsession-errors
    [[ -d "/root/.config/xfce4/" ]] || echo "Directory /root/.config/xfce4/ does not exist."

    # Binaries
    cp /root/sources/assets/desktop/bin/* /usr/sbin/
    chmod +x /usr/sbin/desktop-*
}

function package_desktop() {
    set_env
    local start_time
    local end_time
    start_time=$(date +%s)
    install_xfce
    post_install
    end_time=$(date +%s)
    local elapsed_time=$((end_time - start_time))
    colorecho "Package desktop completed in $elapsed_time seconds."
}