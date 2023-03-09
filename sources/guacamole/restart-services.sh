#!/bin/bash

pkill guacd
service guacd start
service xrdp restart
service xrdp-sesman stop
JAVA_HOME=/usr/lib/jvm/java-1.17.0-openjdk-arm64 /root/.tomcat/bin/shutdown.sh
JAVA_HOME=/usr/lib/jvm/java-1.17.0-openjdk-arm64 /root/.tomcat/bin/startup.sh
