#!/bin/bash
# Author: The Exegol Project

source common.sh

function install_mobile_apt_tools() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing mobile apt tools"
    fapt android-tools-adb zipalign apksigner apktool

    add-history adb
    add-history zipalign
    add-history apksigner
    add-history apktool

    add-test-command "adb --help"
    add-test-command "zipalign --help |& grep 'verbose output'"
    add-test-command "apksigner --version"
    add-test-command "apktool --version"

    add-to-list "android-tools-adb,https://developer.android.com/studio/command-line/adb,A collection of tools for debugging Android applications"
    add-to-list "zipalign,https://developer.android.com/studio/command-line/zipalign,arguably the most important step to optimize your APK file"
    add-to-list "apksigner,https://source.android.com/security/apksigning,arguably the most important step to optimize your APK file"
    add-to-list "apktool,https://github.com/iBotPeaches/Apktool,It is a tool for reverse engineering 3rd party / closed / binary Android apps."
}

function install_scrpy() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing scrcpy"
    fapt ffmpeg libsdl2-2.0-0 adb \
                 meson ninja-build libsdl2-dev \
                 libavcodec-dev libavdevice-dev libavformat-dev libavutil-dev \
                 libswresample-dev libusb-1.0-0 libusb-1.0-0-dev
    git clone --depth 1 https://github.com/Genymobile/scrcpy
    # opening subshell to not have to cd back
    (
      cd scrcpy || exit
      ./install_release.sh
    )
    rm -rf ./scrcpy
    add-history scrcpy
    add-test-command "scrcpy --version"
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
    wget https://github.com/pxb1988/dex2jar/releases/download/v2.4/dex-tools-v2.4.zip -O /tmp/dex2jar.zip
    unzip /tmp/dex2jar.zip -d /opt/tools/
    mv -v /opt/tools/dex-tools-v2.4/ /opt/tools/dex2jar
    find /opt/tools/dex2jar -type f -name "*.sh" -exec ln -s '{}' /opt/tools/bin ';'
    add-history dex2jar
    add-test-command "d2j-dex2jar.sh --help"
    add-to-list "dex2jar,https://github.com/pxb1988/dex2jar,A tool to convert Android's dex files to Java's jar files"
}

function install_frida() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing frida"
    pipx install --system-site-packages frida-tools
    add-history frida
    add-test-command "frida --version"
    add-to-list "frida,https://github.com/frida/frida,Dynamic instrumentation toolkit"
}

function install_objection() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing objection"
    pipx install --system-site-packages git+https://github.com/sensepost/objection
    add-history objection
    add-test-command "objection --help"
    add-to-list "objection,https://github.com/sensepost/objection,Runtime mobile exploration"
}

function install_androguard() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing androguard"
    pipx install --system-site-packages androguard
    # https://github.com/androguard/androguard/issues/1060
    local temp_fix_limit="2024-11-01"
    if [[ "$(date +%Y%m%d)" -gt "$(date -d $temp_fix_limit +%Y%m%d)" ]]; then
      criticalecho "Temp fix expired. Exiting."
    else
      rm -rf /root/.local/share/pipx/venvs/androguard/lib/python3.*/site-packages/oscrypto*
      pipx inject androguard git+https://github.com/wbond/oscrypto@master
    fi
    add-history androguard
    add-test-command "androguard --version"
    add-to-list "androguard,https://github.com/androguard/androguard,Reverse engineering and analysis of Android applications"
}

function install_mobsf() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing Mobile Security Framework"
    fapt wkhtmltopdf
    git -C /opt/tools clone --depth 1 https://github.com/MobSF/Mobile-Security-Framework-MobSF MobSF
    cd /opt/tools/MobSF || exit
    # pipx --preinstall git+https://github.com/MobSF/yara-python-dex.git /opt/tools/MobSF would be needed for ARM64
    #  in the mean time, switching to manual venv and an alias for mobsf
    local temp_fix_limit="2024-11-01"
    if [[ "$(date +%Y%m%d)" -gt "$(date -d $temp_fix_limit +%Y%m%d)" ]]; then
      criticalecho "Temp fix expired. Exiting." # check if pipx supports preinstall now
    else
      python3 -m venv --system-site-packages ./venv
      ./venv/bin/python3 -m pip install git+https://github.com/MobSF/yara-python-dex.git
      ./venv/bin/python3 -m pip install .
      add-aliases mobsf # alias is only needed with venv and can be removed when switching back to pipx
    fi
    add-history mobsf
    add-test-command "/opt/tools/MobSF/venv/bin/python -c 'from mobsf.MobSF.settings import VERSION; print(VERSION)'"
    add-to-list "mobsf,https://github.com/MobSF/Mobile-Security-Framework-MobSF,Automated and all-in-one mobile application (Android/iOS/Windows) pen-testing malware analysis and security assessment framework"
}

# Package dedicated to mobile apps pentest tools
function package_mobile() {
    set_env
    local start_time
    local end_time
    start_time=$(date +%s)
    install_mobile_apt_tools
    install_scrpy
    install_smali
    install_dex2jar
    install_frida
    install_objection               # Runtime mobile exploration toolkit
    install_androguard              # Reverse engineering and analysis of Android applications
    install_mobsf                   # Automated mobile application testing framework
    end_time=$(date +%s)
    local elapsed_time=$((end_time - start_time))
    colorecho "Package mobile completed in $elapsed_time seconds."
}
