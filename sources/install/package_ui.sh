#!/bin/bash
# Author: The Exegol Project

source common.sh

set -e

function install_xfce() {
    fapt xz-utils
    fapt tigervnc-standalone-server novnc websockify xfce4 dbus-x11 plank
    mkdir ~/.vnc
    cp /root/sources/assets/webui/xstartup.conf ~/.vnc/xstartup
    chmod u+x ~/.vnc/xstartup

    # Debug Theme
    cd /tmp
    cp /root/sources/assets/webui/Mc-OS-CTLina-XFCE-Dark.tar.xz /tmp
    tar -xvf ./Mc-OS-CTLina-XFCE-Dark.tar.xz
    mv Mc-OS-CTLina-XFCE-Dark McOS-CTLina
    
    # Debug Icons
    cp /root/sources/assets/webui/papirus-icon-theme-20230601.tar.gz ./
    tar -zxvf papirus-icon-theme-20230601.tar.gz


    mkdir /root/.themes
    cp -r ./McOS-CTLina /root/.themes/

    # Backgroup wallpaper
    cp /root/sources/assets/webui/wallpaper.png /usr/share/backgrounds/xfce/

    # Icons
    cp -r ./Papirus-Dark /usr/share/icons/Papirus-Dark
    cp /root/sources/assets/webui/xsettings.xml /root/.vnc/xsettings.xml

    # TODO: Remove me
    echo 'exegol4thewin' | vncpasswd -f > $HOME/.vnc/passwd

    cp /root/sources/assets/webui/bin/* /opt/tools/bin
    chmod +x /opt/tools/bin/desktop-*
}

function package_webui() {
    install_xfce
}