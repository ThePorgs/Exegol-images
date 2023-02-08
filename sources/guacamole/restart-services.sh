#!/bin/bash

service guacd restart
service mariadb restart
service xrdp restart
JAVA_HOME=/usr/lib/jvm/java-1.17.0-openjdk-arm64 /opt/tomcat/bin/shutdown.sh
JAVA_HOME=/usr/lib/jvm/java-1.17.0-openjdk-arm64 /opt/tomcat/bin/startup.sh
