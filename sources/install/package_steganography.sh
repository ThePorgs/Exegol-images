#!/bin/bash
# Author: The Exegol Project

source common.sh

function install_steganography_apt_tools() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing steganography apt tools"
    fapt stegosuite steghide exif exiv2 hexedit

    add-history stegosuite
    add-history steghide
    add-history exif
    add-history exiv2
    add-history hexedit

    add-test-command "stegosuite --help"
    add-test-command "steghide --version"
    add-test-command "exif --help"                              # Show and change EXIF information in JPEG files
    add-test-command "exiv2 --help"                             # Utility to read, write, delete and modify Exif, IPTC, XMP and ICC image metadata
    add-test-command "hexedit --help|& grep 'usage: hexedit'"   # View and edit files in hexadecimal or in ASCII
    
    
    add-to-list "stegosuite,https://github.com/osde8info/stegosuite,Stegosuite is a free steganography tool that allows you to hide data in image and audio files."
    add-to-list "steghide,https://github.com/StefanoDeVuono/steghide,steghide is a steganography program that is able to hide data in various kinds of image and audio files."
    add-to-list "exif,https://exiftool.org/,Utility to read / write and edit metadata in image / audio and video files"
    add-to-list "exiv2,https://github.com/Exiv2/exiv2,Image metadata library and toolset"
    add-to-list "hexedit,https://github.com/pixel/hexedit,View and edit binary files"
}

function install_zsteg() {
    colorecho "Installing zsteg"
    rvm use 3.2.2@zsteg --create
    gem install zsteg
    rvm use 3.2.2@default
    add-aliases zsteg
    add-history zsteg
    add-test-command "zsteg --help"
    add-to-list "zsteg,https://github.com/zed-0xff/zsteg,Detect steganography hidden in PNG and BMP images"
}

function install_stegolsb() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing stegolsb"
    pipx install --system-site-packages stego-lsb
    add-history stegolsb
    add-test-command "stegolsb --version"
    add-to-list "stegolsb,https://github.com/KyTn/STEGOLSB,Steganography tool to hide data in BMP images using least significant bit algorithm"
}

# Package dedicated to steganography tools
function package_steganography() {
    set_env
    local start_time
    local end_time
    start_time=$(date +%s)
    install_steganography_apt_tools
    install_zsteg                   # Detect stegano-hidden data in PNG & BMP
    install_stegolsb                # (including wavsteg)
    post_install
    end_time=$(date +%s)
    local elapsed_time=$((end_time - start_time))
    colorecho "Package steganography completed in $elapsed_time seconds."
}
