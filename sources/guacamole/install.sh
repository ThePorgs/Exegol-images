#!/bin/bash

# Set versions
GUACVERSION="1.4.0"
MCJVER="8.0.26"

# Set variables
mysqlHost="localhost"
mysqlPort="3306"
mysqlRootPwd="exegol4thewin"
guacDb="guacamole_db"
guacUser="guacamole_user"
guacPwd="guacamole_password"
TOMCAT="tomcat9 tomcat9-admin tomcat9-common tomcat9-user"
MYSQL="default-mysql-server default-mysql-client mysql-common"
SERVER="http://apache.org/dyn/closer.cgi?action=download&filename=guacamole/${GUACVERSION}"
TOMCAT_HOME="/root/.tomcat"

debconf-set-selections <<< "mysql-server mysql-server/root_password password ${mysqlRootPwd}"
debconf-set-selections <<< "mysql-server mysql-server/root_password_again password ${mysqlRootPwd}"
source /etc/os-release
apt-get update
export DEBIAN_FRONTEND=noninteractive

# Install dependencies
apt-get -y install build-essential libcairo2-dev libjpeg62-turbo-dev libpng-dev libossp-uuid-dev libavcodec-dev libavformat-dev libavutil-dev \
libswscale-dev freerdp2-dev libpango1.0-dev libssh2-1-dev libtelnet-dev libvncserver-dev libpulse-dev libssl-dev \
libvorbis-dev libwebp-dev libwebsockets-dev freerdp2-x11 libtool-bin ghostscript dpkg-dev wget crudini libc-bin \
${MYSQL} ${TOMCAT}

# Download requirements
wget -q --show-progress -O guacamole-server-${GUACVERSION}.tar.gz ${SERVER}/source/guacamole-server-${GUACVERSION}.tar.gz
tar -xzf guacamole-server-${GUACVERSION}.tar.gz
wget -q --show-progress -O guacamole-${GUACVERSION}.war ${SERVER}/binary/guacamole-${GUACVERSION}.war
wget -q --show-progress -O guacamole-auth-jdbc-${GUACVERSION}.tar.gz ${SERVER}/binary/guacamole-auth-jdbc-${GUACVERSION}.tar.gz
tar -xzf guacamole-auth-jdbc-${GUACVERSION}.tar.gz
wget -q --show-progress -O mysql-connector-java-${MCJVER}.tar.gz https://dev.mysql.com/get/Downloads/Connector-J/mysql-connector-java-${MCJVER}.tar.gz
tar -xzf mysql-connector-java-${MCJVER}.tar.gz

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
mv -f guacamole-${GUACVERSION}.war /etc/guacamole/guacamole.war
mv -f mysql-connector-java-${MCJVER}/mysql-connector-java-${MCJVER}.jar /etc/guacamole/lib/mysql-connector-java.jar
rm -f /etc/guacamole/guacamole.properties
touch /etc/guacamole/guacamole.properties
echo "mysql-hostname: ${mysqlHost}" >> /etc/guacamole/guacamole.properties
echo "mysql-port: ${mysqlPort}" >> /etc/guacamole/guacamole.properties
echo "mysql-database: ${guacDb}" >> /etc/guacamole/guacamole.properties
echo "mysql-username: ${guacUser}" >> /etc/guacamole/guacamole.properties
echo "mysql-password: ${guacPwd}" >> /etc/guacamole/guacamole.properties

# Create a new tomcat instance@
tomcat9-instance-create ${TOMCAT_HOME} 
ln -sf /etc/guacamole/guacamole.war ${TOMCAT_HOME}/webapps/

# Configure mysql
export MYSQL_PWD=${mysqlRootPwd}
service mariadb restart
systemctl enable mysql
mysqlconfig="/etc/mysql/mariadb.conf.d/50-server.cnf"
timezone="$( cat /etc/timezone )"
mysql_tzinfo_to_sql /usr/share/zoneinfo 2>/dev/null | mysql -u root -D mysql -h ${mysqlHost} -P ${mysqlPort}
crudini --set ${mysqlconfig} mysqld default_time_zone "${timezone}"
service mariadb restart
guacUserHost="localhost"
SQLCODE="DROP DATABASE IF EXISTS ${guacDb};
CREATE DATABASE IF NOT EXISTS ${guacDb};
CREATE USER IF NOT EXISTS '${guacUser}'@'${guacUserHost}' IDENTIFIED BY \"${guacPwd}\";
GRANT SELECT,INSERT,UPDATE,DELETE ON ${guacDb}.* TO '${guacUser}'@'${guacUserHost}';
FLUSH PRIVILEGES;"
echo ${SQLCODE} | mysql -u root -D mysql -h ${mysqlHost} -P ${mysqlPort}
cat guacamole-auth-jdbc-${GUACVERSION}/mysql/schema/*.sql | mysql -u root -D ${guacDb} -h ${mysqlHost} -P ${mysqlPort}
cat >> /etc/guacamole/guacd.conf <<- "EOF"
[server]
bind_host = 0.0.0.0
bind_port = 4822
EOF

# Add login mapping
cp user-mapping.xml /etc/guacamole/

# Install xrdp + kde
#apt install -y kde-plasma-desktop
apt install -y xfce4 xfce4-goodies xorg dbus-x11 x11-xserver-utils
apt install -y xrdp

sed -i "s/EnableSyslog=1/EnableSyslog=0/g" /etc/xrdp/sesman.ini

# Edit root password
echo -e "exegol4thewin\nexegol4thewin" | passwd root

# Cleanup
rm -rf guacamole-*
rm -rf mysql-connector-java-*
rm -rf user-mapping.xml
rm -rf install.sh 
unset MYSQL_PWD

# Start services
service guacd start 
systemctl enable guacd
service mariadb restart
JAVA_HOME=/usr/lib/jvm/java-1.17.0-openjdk-arm64 ${TOMCAT_HOME}/bin/startup.sh
service xrdp start

echo "http://127.0.0.1:9000/guacamole"
