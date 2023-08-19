#!/bin/bash
# Author: The Exegol Project

source common.sh

function install_mobile_apt_tools() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing mobile apt tools"
    fapt android-tools-adb zipalign apksigner apktool scrcpy

    add-history adb
    add-history zipalign
    add-history apksigner
    add-history apktool
    add-history scrcpy

    add-test-command "adb --help"
    add-test-command "zipalign --help |& grep 'verbose output'"
    add-test-command "apksigner --version"
    add-test-command "apktool --version"
    add-test-command "scrcpy --version"

    add-to-list "android-tools-adb,https://developer.android.com/studio/command-line/adb,A collection of tools for debugging Android applications"
    add-to-list "zipalign,https://developer.android.com/studio/command-line/zipalign,arguably the most important step to optimize your APK file"
    add-to-list "apksigner,https://source.android.com/security/apksigning,arguably the most important step to optimize your APK file"
    add-to-list "apktool,https://github.com/iBotPeaches/Apktool,It is a tool for reverse engineering 3rd party / closed / binary Android apps."
    add-to-list "scrcpy,https://github.com/Genymobile/scrcpy,Display and control your Android device."
}

function install_smali() {
    colorecho "Installing smali"
    mkdir /opt/tools/smali/
    wget https://bitbucket.org/JesusFreke/smali/downloads/smali-2.5.2.jar -O /opt/tools/smali/smali-2.5.2.jar
    add-aliases smali
    add-history smali
    add-test-command "smali --version"
    add-to-list "smali,https://github.com/JesusFreke/smali,A tool to disassemble and assemble Android's dex files"
}

function install_dex2jar() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing dex2jar"
    wget https://github.com/pxb1988/dex2jar/releases/latest/download/dex2jar-2.1.zip -O /tmp/dex2jar.zip
    unzip /tmp/dex2jar.zip -d /opt/tools/
    mv /opt/tools/dex-tools-2.1/ /opt/tools/dex2jar
    find /opt/tools/dex2jar -type f -name "*.sh" -exec ln -s '{}' /opt/tools/bin ';'
    add-history dex2jar
    add-test-command "d2j-dex2jar.sh --help"
    add-to-list "dex2jar,https://github.com/pxb1988/dex2jar,A tool to convert Android's dex files to Java's jar files"
}

function install_frida() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing frida"
    python3 -m pipx install frida-tools
    add-history frida
    add-test-command "frida --version"
    add-to-list "frida,https://github.com/frida/frida,Dynamic instrumentation toolkit"
}

function install_objection() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing objection"
    python3 -m pipx install git+https://github.com/sensepost/objection
    add-history objection
    add-test-command "objection --help"
    add-to-list "objection,https://github.com/sensepost/objection,Runtime mobile exploration"
}

function install_androguard() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing androguard"
    python3 -m pipx install androguard
    add-history androguard
    add-test-command "androguard --version"
    add-to-list "androguard,https://github.com/androguard/androguard,Reverse engineering and analysis of Android applications"
}

# Package dedicated to mobile apps pentest tools
function package_mobile() {
    set_ruby_env
    install_mobile_apt_tools
    install_smali
    install_dex2jar
    install_frida
    install_objection               # Runtime mobile exploration toolkit
    install_androguard              # Reverse engineering and analysis of Android applications
}