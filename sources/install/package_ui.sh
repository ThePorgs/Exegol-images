#!/bin/bash
# Author: The Exegol Project

source common.sh

set -e

function install_xfce() {
    fapt tigervnc-standalone-server novnc websockify xfce4 dbus-x11
    mkdir ~/.vnc

    echo '#!/bin/bash' > ~/.vnc/xstartup
    echo "unset SESSION_MANAGER" >> ~/.vnc/xstartup
    echo "startxfce4" >> ~/.vnc/xstartup

    chmod u+x ~/.vnc/xstartup

    cp /root/sources/assets/webui/bin/* /opt/tools/bin

    chmod +x /opt/tools/bin/desktop-*
}

function install_mate() {
    echo "Installing Mate"
    fapt tigervnc-standalone-server novnc websockify mate-desktop-environment dbus-x11
    mkdir ~/.vnc

    cp /root/sources/assets/webui/config-mate.conf ~/.vnc/xstartup

    chmod u+x ~/.vnc/xstartup

    cp /root/sources/assets/webui/bin/* /opt/tools/bin

    chmod +x /opt/tools/bin/desktop-*
}

function package_webui() {
    # install_xfce
    install_mate
}