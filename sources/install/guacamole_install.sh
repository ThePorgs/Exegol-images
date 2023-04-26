#!/bin/bash
# Author: The Exegol Project

source common.sh

set -e

# Set variables
GUACVERSION="1.5.1"
SERVER="http://apache.org/dyn/closer.cgi?action=download&filename=guacamole/${GUACVERSION}"
TOMCAT_HOME="/root/.tomcat"

export DEBIAN_FRONTEND=noninteractive

# Install dependencies
apt install -y libcairo2-dev libjpeg62-turbo-dev libpng-dev libossp-uuid-dev libavcodec-dev libavformat-dev libavutil-dev \
libswscale-dev freerdp2-dev libpango1.0-dev libssh2-1-dev libtelnet-dev libvncserver-dev libpulse-dev libssl-dev \
libvorbis-dev libwebp-dev libwebsockets-dev freerdp2-x11 libtool-bin ghostscript dpkg-dev wget crudini libc-bin \
tomcat9 tomcat9-admin tomcat9-common tomcat9-user kde-plasma-desktop xrdp xorgxrdp dbus-x11

# Setup workspace
mkdir /tmp/guacamole
cd /tmp/guacamole/

# Download requirements
wget -q --show-progress -O guacamole-server-${GUACVERSION}.tar.gz ${SERVER}/source/guacamole-server-${GUACVERSION}.tar.gz
tar -xzf guacamole-server-${GUACVERSION}.tar.gz

mkdir -p /etc/guacamole/{extensions,lib}

# Custom style
mkdir custom-war
cd custom-war
wget -q --show-progress -O guacamole-${GUACVERSION}.war ${SERVER}/binary/guacamole-${GUACVERSION}.war
unzip guacamole-${GUACVERSION}.war
rm guacamole-${GUACVERSION}.war
echo '<link rel="stylesheet" href="theme.css">' >> index.html
cp /root/sources/assets/guacamole/theme.css ./
cp /root/sources/assets/guacamole/logo.png ./images/logo.png
cp /root/sources/assets/guacamole/logo.png ./images/logo-144.png
cp /root/sources/assets/guacamole/logo.png ./images/logo-64.png
sed -i "s#guac-tricolor.svg#logo.png#" ./1.guacamole.8c18237a4a94ee9845d9.css
sed -i "s#Apache Guacamole#Exegol#" ./translations/en.json
zip -r /etc/guacamole/guacamole.war *
cd ..
rm -rf custom-war

# Install guacamole-server
cd guacamole-server-${GUACVERSION}
export CFLAGS="-Wno-error"
./configure --with-init-dir=/etc/init.d --enable-allow-freerdp-snapshots
make
make install
ldconfig
cd ../

# Create a new tomcat instance
tomcat9-instance-create ${TOMCAT_HOME}
sed -i 's#8080#6336##' ${TOMCAT_HOME}/conf/server.xml
ln -sf /etc/guacamole/guacamole.war ${TOMCAT_HOME}/webapps/ROOT.war

cat >> /etc/guacamole/guacd.conf <<- "EOF"
[server]
bind_host = 127.0.0.1
bind_port = 5665
EOF

rm -f /etc/guacamole/guacamole.properties

# Add login mapping
cp /root/sources/assets/guacamole/user-mapping.xml /etc/guacamole/
hashpass=$(echo -n "exegol4thewin"|md5sum|cut -d ' ' -f1)
sed -i "s/CHANGEME/$hashpass/" /etc/guacamole/user-mapping.xml
cp /root/sources/assets/guacamole/guacamole.properties /etc/guacamole/

update-alternatives --set x-session-manager /usr/bin/startplasma-x11

# Configure xrdp
sed -i "s#port=3389#port=tcp://127.0.0.1:5225##" /etc/xrdp/xrdp.ini

# Edit root password
echo -e "exegol4thewin\nexegol4thewin" | passwd root

cp /root/sources/assets/guacamole/desktop-start /opt/tools/bin
cp /root/sources/assets/guacamole/desktop-stop /opt/tools/bin
cp /root/sources/assets/guacamole/desktop-restart /opt/tools/bin

chmod +x /opt/tools/bin/desktop-*

cp /root/sources/assets/guacamole/wallpaper.png /usr/share/wallpapers/Next/contents/images/1920x1080.jpg
mkdir -p /root/.config/
cp /root/sources/assets/guacamole/kdeglobals /root/.config/

/opt/tools/bin/desktop-stop

# Remove tmp
cd /root/sources/install
rm -rf /tmp/guacamole

# Unset variables
unset GUACVERSION
unset SERVER
unset TOMCAT_HOME

add-test-command "ls desktop-start"
add-test-command "ls desktop-stop"
add-test-command "ls desktop-restart"