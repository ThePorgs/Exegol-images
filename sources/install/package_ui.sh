#!/bin/bash
# Author: The Exegol Project

source common.sh

set -e

function install_xfce() {

    # DEBUG TOOLS
    fapt terminator firefox-esr
    
    # DEPENDENCIES
    fapt tigervnc-standalone-server tigervnc-xorg-extension tigervnc-viewer novnc websockify xfce4 dbus-x11 papirus-icon-theme intltool libtool
    
    # Papirus (icons) dependencies
    fapt libaacs0 libavcodec58 libavformat58 libavutil56 libbluray2 libdvdnav4 libdvdread8 libpostproc55 libswresample3 libswscale5 libx264-160 libx265-192
    
    # VNC Configuration
    mkdir ~/.vnc
    cp /root/sources/assets/webui/configuration/xstartup.conf ~/.vnc/xstartup
    chmod u+x ~/.vnc/xstartup

    # Main theme Configuration
    mkdir /root/.themes
    cp /root/sources/assets/webui/Prof_XFCE_2_1.tar.gz /tmp
    cd /tmp
    tar -xvf ./Prof_XFCE_2_1.tar.gz
    mv 'Prof--XFCE- 2.1' Prof_XFCE_2_1
    cp -r ./Prof_XFCE_2_1 /root/.themes/
    rm -rf /tmp/Prof*

    # Get configuration files
    mkdir /root/.remote-desktop
    cp /root/sources/assets/webui/configuration/* /root/.remote-desktop/

    # Dock Dependencies + Configuration
    fapt xfce4-dev-tools libglib2.0-dev libgtk-3-dev libwnck-3-dev libxfce4ui-2-dev libxfce4panel-2.0-dev g++ build-essential
    git -C /tmp clone https://gitlab.xfce.org/panel-plugins/xfce4-docklike-plugin.git
    cd /tmp/xfce4-docklike-plugin
    sh autogen.sh --prefix=/tmp/
    make
    make install
    CUSTOM_PATH=`find /usr/lib/ -name "xfce*"|head -n1`
    mv /tmp/lib/xfce4/panel/plugins/libdocklike.* $CUSTOM_PATH/panel/plugins
    mv /tmp/share/xfce4/panel/plugins/docklike.desktop /usr/share/xfce4/panel/plugins
    # Locale configuration
    cp -rv /tmp/share/locale/* /usr/share/locale
    rm -rf /tmp/*
    
    
    # Wallpapers + favicon configuration
    cp /root/.remote-desktop/wallpaper* /usr/share/backgrounds/xfce
    cp /root/sources/assets/webui/logo.png /usr/share/novnc/app/images/icons/
    sed -i "/novnc-.*.png/d" /usr/share/novnc/vnc.html
    sed -i "s#novnc-icon.svg#logo.png#" /usr/share/novnc/vnc.html
    sed -i "s#svg+xml#png#" /usr/share/novnc/vnc.html
    
    # TODO: Remove me
    echo 'exegol4thewin' | vncpasswd -f > $HOME/.vnc/passwd

    # Binaries setup
    cp /root/sources/assets/webui/bin/* /opt/tools/bin
    chmod +x /opt/tools/bin/desktop-*
}

function package_webui() {
    install_xfce
}