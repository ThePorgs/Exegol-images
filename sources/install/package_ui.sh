#!/bin/bash
# Author: The Exegol Project

source common.sh

set -e

function install_xfce() {

    # DEBUG TOOLS
    fapt terminator firefox-esr iproute2

    # DEPENDENCIES
    fapt tigervnc-standalone-server tigervnc-xorg-extension tigervnc-viewer novnc websockify xfce4 dbus-x11 papirus-icon-theme intltool libtool

    # Papirus (icons) dependencies (need to find correct lib)
    fapt libaa1 libaacs0 libaom0 libarchive13 libasound2-plugins libaspell15 libass9 libatasmart4 libatkmm-1.6-1v5 libavahi-glib1 libavc1394-0 libavcodec58 libavfilter7 libavformat58 libavresample4 libavutil56 libayatana-ido3-0.4-0 libayatana-indicator3-7 libbdplus0 libblockdev-crypto2 libblockdev-fs2 libblockdev-loop2 libblockdev-part-err2 libblockdev-part2 libblockdev-swap2 libblockdev-utils2 libblockdev2 libbluray2 libbs2b0 libcaca0 libcairomm-1.0-1v5 libcanberra-gtk3-0 libcanberra-gtk3-module libcanberra0 libcap2-bin libcdio-cdda2 libcdio-paranoia2 libcdio19 libcdparanoia0 libchromaprint1 libcodec2-0.9 libcue2 libdav1d4 libdc1394-25 libdca0 libde265-0 libdjvulibre-text libdjvulibre21 libdv4 libdvdnav4 libdvdread8 libdw1 libenchant-2-2 libetpan20 libevdev2 libevdocument3-4 libevview3-3 libexempi8 libexiv2-27 libfaad2 libfdisk1 libfftw3-double3 libflite1 libfluidsynth2 libfuse2 libgck-1-0 libgcr-base-3-1 libgcr-ui-3-1 libgd3 libgdata-common libgdata22 libgeoclue-2-0 libgeocode-glib0 libgexiv2-2 libgif7 libgjs0g libglibmm-2.4-1v5 libglu1-mesa libgme0 libgnome-autoar-0-0 libgnome-desktop-3-19 libgnome-menu-3-0 libgoa-1.0-0b libgoa-1.0-common libgpgme11 libgphoto2-6 libgphoto2-l10n libgphoto2-port12 libgraphene-1.0-0 libgs9 libgs9-common libgsf-1-114 libgsf-1-common libgsm1 libgspell-1-2 libgspell-1-common libgssdp-1.2-0 libgstreamer-gl1.0-0 libgstreamer-plugins-bad1.0-0 libgstreamer-plugins-base1.0-0 libgstreamer1.0-0 libgtkmm-3.0-1v5 libgupnp-1.2-0 libgupnp-igd-1.0-4 libgweather-3-16 libgweather-common libgxps2 libhunspell-1.7-0 libhyphen0 libical3 libidn11 libiec61883-0 libijs-0.35 libilmbase25 libimobiledevice6 libinstpatch-1.0-2 libiptcdata0 libjack-jackd2-0 libjavascriptcoregtk-4.0-18 libjbig2dec0 libjim0.79 libkate1 libkpathsea6 liblilv-0-0 liblockfile-bin liblockfile1 libltc11 libltdl7 liblua5.2-0 libmanette-0.2-0 libmbim-glib4 libmbim-proxy libmjpegutils-2.1-0 libmm-glib0 libmms0 libmodplug1 libmozjs-78-0 libmp3lame0 libmpcdec6 libmpeg2encpp-2.1-0 libmpg123-0 libmplex2-2.1-0 libmtp-common libmtp-runtime libmtp9 libmusicbrainz5-2 libmusicbrainz5cc2v5 libmysofa1 libnautilus-extension1a libneon27-gnutls libnfs13 libnice10 libnm0 libnorm1 libnspr4 libnss3 libntfs-3g883 libnuma1 libofa0 libopenal-data libopenal1 libopenexr25 libopenjp2-7 libopenmpt0 libopenni2-0 liborc-0.4-0 libosinfo-1.0-0 libpam-cap libpam-gnome-keyring libpangomm-1.4-1v5 libpaper-utils libpaper1 libparted-fs-resize0 libparted2 libpgm-5.3-0 libpipewire-0.3-0 libpipewire-0.3-modules libplist3 libpocketsphinx3 libpolkit-agent-1-0 libpoppler-glib8 libpoppler102 libpostproc55 libpulsedsp libqmi-glib5 libqmi-proxy libquvi-0.9-0.9.3 libquvi-scripts-0.9 librabbitmq4 libraw1394-11 librsvg2-2 librsvg2-common librubberband2 libsamplerate0 libsbc1 libsdl2-2.0-0 libsecret-1-0 libsecret-common libserd-0-0 libshine3 libshout3 libsigc++-2.0-0v5 libslang2 libsmbclient libsnappy1v5 libsndio7.0 libsord-0-0 libsoundtouch1 libsoxr0 libspa-0.2-modules libspandsp2 libspectre1 libspeex1 libspeexdsp1 libsphinxbase3 libsratom-0-0 libsrt1.4-gnutls libsrtp2-1 libssh-gcrypt-4 libstemmer0d libswresample3 libswscale5 libsynctex2 libtag1v5 libtag1v5-vanilla libtext-iconv-perl libtheora0 libtotem-plparser-common libtotem-plparser18 libtracker-control-2.0-0 libtracker-miner-2.0-0 libtracker-sparql-2.0-0 libtwolame0 libuchardet0 libudfread0 libudisks2-0 libusb-1.0-0 libusbmuxd6 libv4l-0 libv4lconvert0 libva-drm2 libva-x11-2 libva2 libvdpau-va-gl1 libvdpau1 libvidstab1.1 libvisual-0.4-0 libvo-aacenc0 libvo-amrwbenc0 libvolume-key1 libvorbisfile3 libwacom-bin libwacom-common libwacom2 libwavpack1 libwebkit2gtk-4.0-37 libwebrtc-audio-processing1 libwildmidi2 libwoff1 libwpe-1.0-1 libwpebackend-fdo-1.0-1 libx264-160 libx265-192 libxkbregistry0 libxslt1.1 libxss1 libxv1 libxvidcore4 libzbar0 libzeitgeist-2.0-0 libzmq5 libzvbi-common libzvbi0

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
    mkdir -p /root/.remote-desktop/applications
    cp /root/sources/assets/webui/configuration/* /root/.remote-desktop/
    cp /root/sources/assets/webui/applications/* /root/.remote-desktop/applications/

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
    rm -rf /usr/share/backgrounds/xfce/xfce*
    cp /root/.remote-desktop/wallpaper* /usr/share/backgrounds/xfce
    cp /root/sources/assets/webui/logo.png /usr/share/novnc/app/images/icons/
    sed -i "/novnc-.*.png/d" /usr/share/novnc/vnc.html
    sed -i "s#novnc-icon.svg#logo.png#" /usr/share/novnc/vnc.html
    sed -i "s#svg+xml#png#" /usr/share/novnc/vnc.html
    echo '<link rel="icon" sizes="any" type="image/png" href="app/images/icons/logo.png">' >> /usr/share/novnc/vnc.html
    
    # Title bar configuration
    sed -i "s#<title>noVNC</title>#<title>Exegol</title>#" /usr/share/novnc/vnc.html
    sed -i 's#document.title = e.detail.name + " - noVNC";#document.title = "Exegol (" + e.detail.name.split(":")[0].replace("exegol-", "") + ")";#' /usr/share/novnc/app/ui.js

    # TODO: Remove me
    echo 'exegol4thewin' | vncpasswd -f > $HOME/.vnc/passwd

    # Binaries setup
    cp /root/sources/assets/webui/bin/* /opt/tools/bin
    chmod +x /opt/tools/bin/desktop-*
}

function package_webui() {
    install_xfce
}