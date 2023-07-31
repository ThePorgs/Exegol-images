#!/bin/bash
# Author: The Exegol Project

source common.sh

# set -e

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
    # tar -zxvf papirus-icon-theme-20230601.tar.gz


    mkdir /root/.themes
    cp -r ./McOS-CTLina /root/.themes/

    # Appearance theme
    # xfconf-query -c xsettings -p /Net/ThemeName -s McOS-CTLina
    # xfconf-query -c xfwm4 -p /general/theme -s McOS-CTLina
    
    # Backgroup wallpaper
    # cp wallpaper.png /usr/share/images/desktop-base/
    # xfconf-query -c xfce4-desktop -p /backdrop/screen0/monitor0/last-image -s /root/sources/assets/webui/wallpaper.png
    # xfconf-query -c xfce4-desktop -p /backdrop/screen0/monitor1/last-image -s /root/sources/assets/webui/wallpaper.png

    # Icons
    # cp -r ./Papirus-Dark /usr/share/icons/Papirus-Dark
    # xfconf-query -c xsettings -p /Net/IconThemeName -s Papirus-Dark

    # TODO: Remove me
    echo 'exegol4thewin' | vncpasswd -f > $HOME/.vnc/passwd

    cp /root/sources/assets/webui/bin/* /opt/tools/bin
    chmod +x /opt/tools/bin/desktop-*
}

function install_mate() {
    echo "Installing Mate"
    fapt tigervnc-standalone-server novnc websockify mate-desktop-environment dbus-x11
    mkdir ~/.vnc
    cp /root/sources/assets/webui/xstartup.conf ~/.vnc/xstartup
    chmod u+x ~/.vnc/xstartup

    # TODO: Remove me
    echo 'exegol4thewin' | vncpasswd -f > $HOME/.vnc/passwd
    
    gsettings set org.mate.background picture-filename /root/sources/assets/webui/wallpaper.png
    cp /root/sources/assets/webui/bin/* /opt/tools/bin
    chmod +x /opt/tools/bin/desktop-*
}

function install_kde() {
    echo "Installing Kde"
    fapt tigervnc-standalone-server novnc websockify kde-plasma-desktop dbus-x11
    mkdir ~/.vnc
    cp /root/sources/assets/webui/xstartup.conf ~/.vnc/xstartup
    chmod u+x ~/.vnc/xstartup

    # TODO: Remove me
    echo 'exegol4thewin' | vncpasswd -f > $HOME/.vnc/passwd

    cp /root/sources/assets/webui/bin/* /opt/tools/bin
    chmod +x /opt/tools/bin/desktop-*
}

function package_webui() {
    install_xfce
    # install_mate
    # install_kde
}