#!/bin/bash

# Set variables
GUACVERSION="1.5.0"
MCJVER="8.0.26"
TOMCAT="tomcat9 tomcat9-admin tomcat9-common tomcat9-user"
SERVER="http://apache.org/dyn/closer.cgi?action=download&filename=guacamole/${GUACVERSION}"
TOMCAT_HOME="/root/.tomcat"

apt-get update
export DEBIAN_FRONTEND=noninteractive

# Install dependencies
apt-get -y install build-essential libcairo2-dev libjpeg62-turbo-dev libpng-dev libossp-uuid-dev libavcodec-dev libavformat-dev libavutil-dev \
libswscale-dev freerdp2-dev libpango1.0-dev libssh2-1-dev libtelnet-dev libvncserver-dev libpulse-dev libssl-dev \
libvorbis-dev libwebp-dev libwebsockets-dev freerdp2-x11 libtool-bin ghostscript dpkg-dev wget crudini libc-bin \
${TOMCAT}

# Download requirements
wget -q --show-progress -O guacamole-server-${GUACVERSION}.tar.gz ${SERVER}/source/guacamole-server-${GUACVERSION}.tar.gz
tar -xzf guacamole-server-${GUACVERSION}.tar.gz

# Custom style
mkdir custom-war
cd custom-war
wget -q --show-progress -O guacamole-${GUACVERSION}.war ${SERVER}/binary/guacamole-${GUACVERSION}.war
unzip guacamole-${GUACVERSION}.war
rm guacamole-${GUACVERSION}.war
echo '<link rel="stylesheet" href="theme.css">' >> index.html
mv ../theme.css ./
zip -r /etc/guacamole/guacamole.war *
cd ..
rm -rf custom-war

# TODO: /etc/guacamole/guacamole.war disapear at the end of install - Weird

mkdir -p /etc/guacamole/{extensions,lib}

# Install guacamole-server
cd guacamole-server-${GUACVERSION}
export CFLAGS="-Wno-error"
./configure --with-init-dir=/etc/init.d --enable-allow-freerdp-snapshots
make
make install
ldconfig

# Configure guacamole
cd ../
rm -f /etc/guacamole/guacamole.properties

# Create a new tomcat instance on port 1337
tomcat9-instance-create ${TOMCAT_HOME}
sed -i 's#8080#6336##' ${TOMCAT_HOME}/conf/server.xml
ln -sf /etc/guacamole/guacamole.war ${TOMCAT_HOME}/webapps/ROOT.war

cat >> /etc/guacamole/guacd.conf <<- "EOF"
[server]
bind_host = 127.0.0.1
bind_port = 4822
EOF

# Add login mapping
cp user-mapping.xml /etc/guacamole/

# Install kde plasma desktop
apt install -y kde-plasma-desktop dbus-x11
update-alternatives --set x-session-manager /usr/bin/startplasma-x11

# Install RDP server
apt install -y xrdp
pkill xrdp

sed -i "s/EnableSyslog=1/EnableSyslog=0/g" /etc/xrdp/sesman.ini
sed -i "s#port=3389#port=tcp://127.0.0.1:3389##" /etc/xrdp/xrdp.ini # RDP localhost

apt-get remove -y bluedevil bluez && apt autoremove -y # https://github.com/jriddell/kdeneon-docker/issues/1

# Edit root password
echo -e "exegol4thewin\nexegol4thewin" | passwd root

# Set default wallpaper
kwriteconfig5 --file "$HOME/.config/plasma-org.kde.plasma.desktop-appletsrc" --group 'Containments' --group '1' --group 'Wallpaper' --group 'org.kde.image' --group 'General' --key 'Image' "/workspace/wallpaper.png"

# Dark mode
## TODO : FIX
kwriteconfig5 --file kdeglobals --group "General" --key "ColorScheme" "BreezeDark"
kwriteconfig5 --file kdeglobals --group "General" --key "Name" "BreezeDark"
kwriteconfig5 --file kdeglobals --group "General" --key "Style" "BreezeDark"
kwriteconfig5 --file kdeglobals --group "Icons" --key "Theme" "BreezeDark"

# Cleanup
#rm -rf guacamole-*
#rm -rf user-mapping.xml
#rm -rf install.sh

# Stop services
service guacd stop
JAVA_HOME=/usr/lib/jvm/java-1.17.0-openjdk-arm64 ${TOMCAT_HOME}/bin/shutdown.sh
xrdp -k
pkill xrdp-sesman

# Unset variables
unset GUACVERSION
unset MCJVER
unset TOMCAT
unset SERVER
unset TOMCAT_HOME
