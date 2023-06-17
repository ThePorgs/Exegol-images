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

# Package dedicated to most used offensive tools
function package_most_used() {
    set_go_env
    install_searchsploit            # Exploitdb local search engine
    install_metasploit              # Offensive framework
    install_nmap                    # Port scanner
    install_seclists                # Awesome wordlists
    install_subfinder               # Subdomain bruteforcer
    install_autorecon               # External recon tool
    install_waybackurls             # Website history
    install_theharvester            # Gather emails, subdomains, hosts, employee names, open ports and banners
    install_simplyemail             # Gather emails
    install_ffuf                    # Web fuzzer (little favorites)
    install_sqlmap                  # SQL injection scanner
    install_hydra                   # Login scanner
    install_joomscan                # Joomla scanner
    install_wpscan                  # Wordpress scanner
    install_droopescan              # Drupal scanner
    install_drupwn                  # Drupal scanner
    install_testssl                 # SSL/TLS scanner
    install_sslscan                 # SSL/TLS scanner
    install_weevely                 # Awesome secure and light PHP webshell
    install_cloudfail               # Cloudflare misconfiguration detector
    install_eyewitness              # Website screenshoter
    install_wafw00f                 # Waf detector
    install_jwt_tool                # Toolkit for validating, forging, scanning and tampering JWTs
    install_gittools                # Dump a git repository from a website
    install_ysoserial               # Deserialization payloads
    install_responder               # LLMNR, NBT-NS and MDNS poisoner
    install_crackmapexec            # Network scanner
    install_impacket                # Network protocols scripts
    install_enum4linux-ng           # Active Directory enumeration tool, improved Python alternative to enum4linux
    install_smbclient               # Small dynamic library that allows iOS apps to access SMB/CIFS file servers
    install_smbmap                  # Allows users to enumerate samba share drives across an entire domain
    install_nuclei                  # Vulnerability scanner
    install_evilwinrm               # WinRM shell
    install_john                    # Password cracker
    install_hashcat                 # Password cracker
    install_fcrackzip               # Zip cracker
}