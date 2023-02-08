#!/bin/bash

# https://guacamole.apache.org/releases/
GUACVERSION="1.4.0"

# https://dev.mysql.com/downloads/connector/j/
MCJVER="8.0.26"

# Initialize variable values
#mysqlHost="localhost"
#mysqlPort="3306"
#mysqlRootPwd="exegol4thewin"
#guacDb="guacamole_db"
#guacUser="guacamole_user"
#guacPwd="guacamole_password"
TOMCAT="tomcat9 tomcat9-admin tomcat9-common tomcat9-user"
#MYSQL="default-mysql-server default-mysql-client mysql-common"

#debconf-set-selections <<< "mysql-server mysql-server/root_password password ${mysqlRootPwd}"
#debconf-set-selections <<< "mysql-server mysql-server/root_password_again password ${mysqlRootPwd}"

source /etc/os-release
apt-get update
export DEBIAN_FRONTEND=noninteractive

# Required packages
apt-get -y install build-essential libcairo2-dev libjpeg62-turbo-dev libpng-dev libossp-uuid-dev libavcodec-dev libavformat-dev libavutil-dev \
libswscale-dev freerdp2-dev libpango1.0-dev libssh2-1-dev libtelnet-dev libvncserver-dev libpulse-dev libssl-dev \
libvorbis-dev libwebp-dev libwebsockets-dev freerdp2-x11 libtool-bin ghostscript dpkg-dev wget crudini libc-bin \
${TOMCAT}

# Set SERVER to be the preferred download server from the Apache CDN
SERVER="http://apache.org/dyn/closer.cgi?action=download&filename=guacamole/${GUACVERSION}"

# Download Guacamole Server
wget -q --show-progress -O guacamole-server-${GUACVERSION}.tar.gz ${SERVER}/source/guacamole-server-${GUACVERSION}.tar.gz
tar -xzf guacamole-server-${GUACVERSION}.tar.gz

# Download Guacamole Client
wget -q --show-progress -O guacamole-${GUACVERSION}.war ${SERVER}/binary/guacamole-${GUACVERSION}.war

# Download Guacamole no auth extensions
# Copy guacamole-auth-noauth-0.9.7.tar from host
tar -xvf guacamole-auth-noauth-0.9.7.tar
cp guacamole-auth-noauth-0.9.7/guacamole-auth-noauth-0.9.7.jar /etc/guacamole/extensions
cp guacamole-auth-noauth-0.9.7/doc/example/noauth-config.xml /etc/guacamole


#wget -q --show-progress -O mysql-connector-java-${MCJVER}.tar.gz https://dev.mysql.com/get/Downloads/Connector-J/mysql-connector-java-${MCJVER}.tar.gz
#tar -xzf mysql-connector-java-${MCJVER}.tar.gz

# Make directories
mkdir -p /etc/guacamole/{extensions,lib}

# Fix for #196
#mkdir -p /usr/sbin/.config/freerdp
#chown daemon:daemon /usr/sbin/.config/freerdp

# Fix for #197
#mkdir -p /var/guacamole
#chown daemon:daemon /var/guacamole

# Install guacd (Guacamole-server)
cd guacamole-server-${GUACVERSION}

# Fix for warnings #222
export CFLAGS="-Wno-error"

./configure --with-init-dir=/etc/init.d --enable-allow-freerdp-snapshots
make
make install
ldconfig

cd ../
mv -f guacamole-${GUACVERSION}.war /etc/guacamole/guacamole.war
mv -f guacamole-auth-noauth-0.9.7.jar /etc/guacamole/extensions/

# Create Symbolic Link for Tomcat
ln -sf /etc/guacamole/guacamole.war /opt/tomcat/webapps/

# Deal with MySQL Connector/J
#mv -f mysql-connector-java-${MCJVER}/mysql-connector-java-${MCJVER}.jar /etc/guacamole/lib/mysql-connector-java.jar

# Configure guacamole.properties
rm -f /etc/guacamole/guacamole.properties
#touch /etc/guacamole/guacamole.properties
#echo "mysql-hostname: ${mysqlHost}" >> /etc/guacamole/guacamole.properties
#echo "mysql-port: ${mysqlPort}" >> /etc/guacamole/guacamole.properties
#echo "mysql-database: ${guacDb}" >> /etc/guacamole/guacamole.properties
#echo "mysql-username: ${guacUser}" >> /etc/guacamole/guacamole.properties
#echo "mysql-password: ${guacPwd}" >> /etc/guacamole/guacamole.properties

tomcat9-instance-create /opt/tomcat
JAVA_HOME=/usr/lib/jvm/java-1.17.0-openjdk-arm64 /opt/tomcat/bin/startup.sh
systemctl enable ${TOMCAT}

#export MYSQL_PWD=${mysqlRootPwd}
#service mariadb restart
#systemctl enable mysql

#mysqlconfig="/etc/mysql/mariadb.conf.d/50-server.cnf"
#timezone="$( cat /etc/timezone )"
   
       
# Fix for https://issues.apache.org/jira/browse/GUACAMOLE-760
#mysql_tzinfo_to_sql /usr/share/zoneinfo 2>/dev/null | mysql -u root -D mysql -h ${mysqlHost} -P ${mysqlPort}
#crudini --set ${mysqlconfig} mysqld default_time_zone "${timezone}"
#service mariadb restart


# Create ${guacDb} and grant ${guacUser} permissions to it

# SQL code
#guacUserHost="localhost"

# Create database & user, then set permissions
#SQLCODE="DROP DATABASE IF EXISTS ${guacDb};
#CREATE DATABASE IF NOT EXISTS ${guacDb};
#CREATE USER IF NOT EXISTS '${guacUser}'@'${guacUserHost}' IDENTIFIED BY \"${guacPwd}\";
#GRANT SELECT,INSERT,UPDATE,DELETE ON ${guacDb}.* TO '${guacUser}'@'${guacUserHost}';
#FLUSH PRIVILEGES;"

# Execute SQL code
#echo ${SQLCODE} | mysql -u root -D mysql -h ${mysqlHost} -P ${mysqlPort}
#at guacamole-auth-jdbc-${GUACVERSION}/mysql/schema/*.sql | mysql -u root -D ${guacDb} -h ${mysqlHost} -P ${mysqlPort}


# Create guacd.conf file required for 1.4.0
cat >> /etc/guacamole/guacd.conf <<- "EOF"
[server]
bind_host = 0.0.0.0
bind_port = 4822
EOF

# Ensure guacd is started
service guacd stop
service guacd start
systemctl enable guacd

# Cleanup
rm -rf guacamole-*
rm -rf mysql-connector-java-*
unset MYSQL_PWD

# Create Symbolic Link for Tomcat
ln -sf /etc/guacamole/guacamole.war /opt/tomcat/webapps/

# Done
echo -e "${BLUE}Installation Complete\n- Visit: http://localhost:8080/guacamole/\n- Default login (username/password): guacadmin/guacadmin\n***Be sure to change the password***.${NC}"
