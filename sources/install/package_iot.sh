#!/bin/bash
# Author: The Exegol Project

source common.sh

function install_iot_apt_tools() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing IOT apt tools"
    fapt avrdude minicom

    add-history avrdude
    add-history minicom

    add-test-command "avrdude '-?'"
    add-test-command "minicom --version; minicom --version |& grep 'This program is free software'"
  
    local version
    version=$(avrdude '-?' |& grep version | awk '{print $3}' | tr -d ',')
    local version
    version=$(minicom --version | head -n 1 | awk '{print $3}')

    add-to-list "avrdude,https://github.com/avrdudes/avrdude,AVRDUDE is a command-line program that allows you to download/upload/manipulate the ROM and EEPROM contents of AVR microcontrollers using the in-system programming technique (ISP).,$version"
    add-to-list "minicom,https://doc.ubuntu-fr.org/minicom,Minicom is a text-based serial communication program for Unix-like operating systems.,$version"
}

# Package dedicated to IoT tools
function package_iot() {
    set_env
    local start_time
    local end_time
    start_time=$(date +%s)
    install_iot_apt_tools
    end_time=$(date +%s)
    local elapsed_time=$((end_time - start_time))
    colorecho "Package iot completed in $elapsed_time seconds."
}