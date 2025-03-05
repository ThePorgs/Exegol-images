#!/bin/bash
# Author: The Exegol Project

source common.sh

set -e

function install_xfce() {
    # CODE-CHECK-WHITELIST=add-aliases,add-history,add-test-command,add-to-list
    colorecho "Installing and configuring xfce desktop"

    # DEBUG TOOLS
    # TODO remove
    fapt terminator iproute2

    # Dependencies
    fapt tigervnc-standalone-server tigervnc-xorg-extension tigervnc-viewer novnc websockify xfce4 dbus-x11 intltool libtool tigervnc-tools

    # temp fix to use latest websockify (min 0.12.0 to fix fedora daemon issue) waiting for apt stable repo to be up-to-date
    local temp_fix_limit="2025-04-01"
    if [[ "$(date +%Y%m%d)" -gt "$(date -d $temp_fix_limit +%Y%m%d)" ]]; then
      criticalecho "Temp fix expired. Exiting."
    else
      # Install websockify (min 0.12.0) explicit from sid repo
      fapt python3-websockify/sid
    fi

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
    # TODO : enable custom config in my-resources
    cp -rv /root/sources/assets/desktop/wallpapers /usr/share/backgrounds/exegol

    # Favicon
    cp -rv /root/sources/assets/desktop/exegol_logo.png /usr/share/novnc/app/images/icons/
    sed -i "/novnc-.*.png/d" /usr/share/novnc/vnc.html
    sed -i "s#novnc-icon.svg#exegol_logo.png#" /usr/share/novnc/vnc.html
    sed -i "s#svg+xml#png#" /usr/share/novnc/vnc.html
    echo '<link rel="icon" sizes="any" type="image/png" href="app/images/icons/exegol_logo.png">' >> /usr/share/novnc/vnc.html

    # NoVNC title bar
    sed -i "s#<title>noVNC</title>#<title>Exegol</title>#" /usr/share/novnc/vnc.html
    sed -i 's#document.title = e.detail.name + " - noVNC";#document.title = "Exegol (" + e.detail.name.split(":")[0].replace("exegol-", "") + ")";#' /usr/share/novnc/app/ui.js

    # NoVNC index redirection
    echo '<html><head><meta http-equiv="refresh" content="0; URL=/vnc.html?resize=remote&path=websockify&autoconnect=true" /></head></html>' > /usr/share/novnc/index.html

    # Desktop
    touch /root/.Xauthority
    export DISPLAY=":0"
    vncserver -localhost yes -geometry 1920x1080 -SecurityTypes Plain :0
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
    vncserver -kill :0
    sleep 6
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
