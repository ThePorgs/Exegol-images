#!/bin/bash
# Author: The Exegol Project

source package_base.sh
source package_misc.sh
source package_osint.sh
source package_web.sh
source package_ad.sh
source package_wordlists.sh
source package_mobile.sh
source package_iot.sh
source package_rfid.sh
source package_voip.sh
source package_sdr.sh
source package_network.sh
source package_wifi.sh
source package_forensic.sh
source package_cloud.sh
source package_steganography.sh
source package_reverse.sh
source package_crypto.sh
source package_code_analysis.sh
source package_cracking.sh
source package_c2.sh

function install_most_used_apt_tools() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing most used apt tools"
    fapt hydra smbclient hashcat fcrackzip

    add-history hydra
    add-history smbclient
    add-history hashcat
    add-history fcrackzip

    add-test-command "hydra -h |& grep 'more command line options'" # Login scanner
    add-test-command "smbclient --help"                             # Small dynamic library that allows iOS apps to access SMB/CIFS file servers
    add-test-command "hashcat --help"                               # Password cracker
    add-test-command "fcrackzip --help"                             # Zip cracker

    add-to-list "hydra,https://github.com/vanhauser-thc/thc-hydra,Hydra is a parallelized login cracker which supports numerous protocols to attack."
    add-to-list "weevely,https://github.com/epinna/weevely3,a webshell designed for post-exploitation purposes that can be extended over the network at runtime."
    add-to-list "smbclient,https://github.com/samba-team/samba,SMBclient is a command-line utility that allows you to access Windows shared resources"
    add-to-list "hashcat,https://hashcat.net/hashcat,A tool for advanced password recovery"
    add-to-list "fcrackzip,https://github.com/hyc/fcrackzip,Password cracker for zip archives."
}

# Package dedicated to most used offensive tools
function package_most_used() {
    set_env
    local start_time
    local end_time
    start_time=$(date +%s)
    install_most_used_apt_tools
    install_metasploit              # Offensive framework
    install_nmap                    # Port scanner
    install_seclists                # Awesome wordlists
    install_subfinder               # Subdomain bruteforcer
    install_autorecon               # External recon tool
    install_waybackurls             # Website history
    install_theharvester            # Gather emails, subdomains, hosts, employee names, open ports and banners
    install_simplyemail             # Gather emails
    install_ffuf                    # Web fuzzer (little favorites)
    install_joomscan                # Joomla scanner
    install_wpscan                  # Wordpress scanner
    install_droopescan              # Drupal scanner
    install_drupwn                  # Drupal scanner
    install_testssl                 # SSL/TLS scanner
    install_cloudfail               # Cloudflare misconfiguration detector
    install_eyewitness              # Website screenshoter
    install_wafw00f                 # Waf detector
    install_jwt_tool                # Toolkit for validating, forging, scanning and tampering JWTs
    install_gittools                # Dump a git repository from a website
    install_ysoserial               # Deserialization payloads
    install_responder               # LLMNR, NBT-NS and MDNS poisoner
    install_impacket                # Network protocols scripts
    install_enum4linux-ng           # Active Directory enumeration tool, improved Python alternative to enum4linux
    install_smbmap                  # Allows users to enumerate samba share drives across an entire domain
    install_nuclei                  # Vulnerability scanner
    install_evilwinrm               # WinRM shell
    install_john                    # Password cracker
    install_weevely                 # Weaponized web shell
    install_sqlmap                  # SQL injection scanner
    install_netexec                 # Crackmapexec repo
    install_sslscan                 # SSL/TLS scanner
    install_cyberchef               # A web based toolbox
    install_proxychains             # Network tool
    install_neo4j
    install_bloodhound
    install_bloodhound-py           # Ingestor for legacy BloodHound
    install_coercer                 # Python script to coerce auth through multiple methods
    post_install
    end_time=$(date +%s)
    local elapsed_time=$((end_time - start_time))
    colorecho "Package most_used completed in $elapsed_time seconds."
}
