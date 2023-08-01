#!/bin/bash
# Author: The Exegol Project

source common.sh

set -e

function install_xfce() {
    fapt tigervnc-standalone-server tigervnc-xorg-extension tigervnc-viewer novnc websockify xfce4 dbus-x11 papirus-icon-theme cairo-dock
    mkdir ~/.vnc
    cp /root/sources/assets/webui/xstartup.conf ~/.vnc/xstartup
    chmod u+x ~/.vnc/xstartup

    # Debug Theme
    cd /tmp
    cp /root/sources/assets/webui/Mc-OS-CTLina-XFCE-Dark.tar.xz /tmp
    tar -xvf ./Mc-OS-CTLina-XFCE-Dark.tar.xz
    mv Mc-OS-CTLina-XFCE-Dark McOS-CTLina
    
    mkdir /root/.themes
    cp -r ./McOS-CTLina /root/.themes/

    # Backgroup wallpaper
    cp /root/sources/assets/webui/wallpaper.png /usr/share/backgrounds/xfce/

    cp /root/sources/assets/webui/xsettings.xml /root/.vnc/xsettings.xml

    # TODO: Remove me
    echo 'exegol4thewin' | vncpasswd -f > $HOME/.vnc/passwd

    cp /root/sources/assets/webui/bin/* /opt/tools/bin
    chmod +x /opt/tools/bin/desktop-*
}

function package_webui() {
    install_xfce
}