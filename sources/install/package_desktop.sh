#!/bin/bash
# Author: The Exegol Project

source common.sh

set -e

function install_xfce() {

    # DEBUG TOOLS
    # TODO remove
    fapt terminator firefox-esr iproute2

    # Dependencies
    fapt tigervnc-standalone-server tigervnc-xorg-extension tigervnc-viewer novnc websockify xfce4 dbus-x11 intltool libtool

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
    git -C /tmp clone https://gitlab.xfce.org/panel-plugins/xfce4-docklike-plugin.git
    cd /tmp/xfce4-docklike-plugin
    sh autogen.sh --prefix=/tmp/
    make
    make install
    CUSTOM_PATH=`find /usr/lib/ -name "xfce*"|head -n1`
    mv /tmp/lib/xfce4/panel/plugins/libdocklike.* $CUSTOM_PATH/panel/plugins
    mv /tmp/share/xfce4/panel/plugins/docklike.desktop /usr/share/xfce4/panel/plugins

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

    # TODO: Remove me
    echo 'exegol4thewin' | vncpasswd -f > $HOME/.vnc/passwd

    # Desktop
    touch /root/.Xauthority
    export DISPLAY=":0"
    vncserver -localhost yes -geometry 1920x1080 -SecurityTypes VncAuth -passwd $HOME/.vnc/passwd :0
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
    [ -d "/root/.config/xfce4/" ] || echo "Directory /root/.config/xfce4/ does not exist."

    # Binaries
    cp /root/sources/assets/desktop/bin/* /opt/tools/bin
    chmod +x /opt/tools/bin/desktop-*
}

function package_desktop() {
    install_xfce
}