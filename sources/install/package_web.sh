#!/bin/bash
# Author: The Exegol Project

source common.sh

# Package dedicated to applicative and active web pentest tools
function package_web() {
    install_web_apt_tools
    set_go_env
    install_gobuster                # Web fuzzer (pretty good for several extensions)
    install_kiterunner              # Web fuzzer (fast and pretty good for api bruteforce)
    install_amass                   # Web fuzzer
    install_ffuf                    # Web fuzzer (little favorites)
    install_dirsearch               # Web fuzzer
    install_ssrfmap                 # SSRF scanner
    install_gopherus                # SSRF helper
    # install_nosqlmap              # NoSQL scanner - FIXME
    install_xsstrike                # XSS scanner
    install_xspear                  # XSS scanner
    # install_xsser                 # XSS scanner FIXME missing install
    install_xsrfprobe               # CSRF scanner
    install_bolt                    # CSRF scanner
    install_kadimus                 # LFI scanner
    install_fuxploider              # File upload scanner
    # install_patator               # Login scanner # FIXME
    # install_joomscan              # Joomla scanner FIXME (https://github.com/ThePorgs/Exegol-images/actions/runs/3557732633/jobs/5977150292)
    install_wpscan                  # Wordpress scanner
    install_droopescan              # Drupal scanner
    install_drupwn                  # Drupal scanner
    install_cmsmap                  # CMS scanner (Joomla, Wordpress, Drupal)
    install_moodlescan              # Moodle scanner
    install_testssl                 # SSL/TLS scanner
    install_tls-scanner             # SSL/TLS scanner
    # install_sslyze                # SSL/TLS scanner FIXME
    install_cloudfail               # Cloudflare misconfiguration detector
    install_eyewitness              # Website screenshoter
    install_oneforall               # OneForAll is a powerful subdomain integration tool
    install_wafw00f                 # Waf detector
    install_corscanner              # CORS misconfiguration detector
    install_hakrawler               # Web endpoint discovery
    install_gowitness               # Web screenshot utility
    install_linkfinder              # Discovers endpoint JS files
    install_timing_attack           # Cryptocraphic timing attack
    install_updog                   # New HTTPServer
    install_jwt_tool                # Toolkit for validating, forging, scanning and tampering JWTs
    install_wuzz                    # Burp cli
    install_git-dumper              # Dump a git repository from a website
    install_gittools                # Dump a git repository from a website
    install_ysoserial               # Deserialization payloads
    # install_phpggc                # php deserialization payloads FIXME https://github.com/ambionics/phpggc/issues/142
    install_symfony-exploits        # symfony secret fragments exploit
    install_jdwp_shellifier         # exploit java debug
    install_httpmethods             # Tool for HTTP methods enum & verb tampering
    install_h2csmuggler             # Tool for HTTP2 smuggling
    install_byp4xx                  # Tool to automate 40x errors bypass attempts
    install_feroxbuster             # ffuf but with multithreaded recursion
    install_tomcatwardeployer       # Apache Tomcat auto WAR deployment & pwning tool
    install_clusterd                # Axis2/JBoss/ColdFusion/Glassfish/Weblogic/Railo scanner
    install_arjun                   # HTTP Parameter Discovery
    install_nuclei                  # Vulnerability scanner - Needed for gau install
    install_gau                     # fetches known URLs from AlienVault's Open Threat Exchange, the Wayback Machine, Common Crawl, and URLScan
    install_hakrevdns               # Reverse DNS lookups
    install_httprobe                # Probe http
    install_httpx                   # Probe http
    install_anew                    # A tool for adding new lines to files, skipping duplicates
    install_robotstester            # Robots.txt scanner
    install_naabu                   # Fast port scanner
    # install_gitrob                # Senstive files reconnaissance in github
    install_burpsuite
    install_smuggler                # HTTP Request Smuggling scanner
    install_php_filter_chain_generator # A CLI to generate PHP filters chain and get your RCE
    install_kraken                  # Kraken is a modular multi-language webshell.
    install_soapui                  # SoapUI is an open-source web service testing application for SOAP and REST
}

function package_web_configure() {
    set_go_env
    configure_nuclei
    configure_moodlescan
    configure_clusterd
}

function install_web_apt_tools() {
    fapt dirb wfuzz sqlmap sslscan weevely whatweb prips swaks
  
    add-history dirb
    add-history wfuzz
    add-history sqlmap
    add-history prips
    add-history swaks
  
    add-test-command "dirb | grep '<username:password>'" # Web fuzzer
    add-test-command "wfuzz --help"                      # Web fuzzer (second favorites) FIXME Pycurl is not compiled against Openssl
    add-test-command "sqlmap --version"                  # SQL injection scanner
    add-test-command "sslscan --version"                 # SSL/TLS scanner
    add-test-command "weevely --help"                    # Awesome secure and light PHP webshell
    add-test-command "whatweb --version"                 # Recognises web technologies including content management
    add-test-command "prips --help"                      # Print the IP addresses in a given range
    add-test-command "swaks --version"                   # Featureful, flexible, scriptable, transaction-oriented SMTP test tool

    add-to-list "dirb,https://github.com/v0re/dirb,Web Content Scanner"
    add-to-list "wfuzz,https://github.com/xmendez/wfuzz,WFuzz is a web application vulnerability scanner that allows you to find vulnerabilities using a wide range of attack payloads and fuzzing techniques"
    add-to-list "sqlmap,https://github.com/sqlmapproject/sqlmap,Sqlmap is an open-source penetration testing tool that automates the process of detecting and exploiting SQL injection flaws"
    add-to-list "sslscan,https://github.com/rbsec/sslscan,a tool for testing SSL/TLS encryption on servers"
    add-to-list "weevely,https://github.com/epinna/weevely3,a webshell designed for post-exploitation purposes that can be extended over the network at runtime."
    add-to-list "whatweb,https://github.com/urbanadventurer/WhatWeb,Next generation web scanner that identifies what websites are running."
    add-to-list "prips,https://manpages.ubuntu.com/manpages/focal/man1/prips.1.html,A utility for quickly generating IP ranges or enumerating hosts within a specified range."
    add-to-list "swaks,https://github.com/jetmore/swaks,Swaks is a featureful flexible scriptable transaction-oriented SMTP test tool."
}

function install_gobuster() {
    colorecho "Installing gobuster"
    go install -v github.com/OJ/gobuster/v3@latest
    add-history gobuster
    add-test-command "gobuster --help"
    add-to-list "gobuster,https://github.com/OJ/gobuster,Tool to discover hidden files and directories."
}

function install_kiterunner() {
    colorecho "Installing kiterunner (kr)"
    git -C /opt/tools/ clone --depth=1 https://github.com/assetnote/kiterunner.git
    cd /opt/tools/kiterunner
    wget https://wordlists-cdn.assetnote.io/data/kiterunner/routes-large.kite.tar.gz
    wget https://wordlists-cdn.assetnote.io/data/kiterunner/routes-small.kite.tar.gz
    make build
    ln -s "$(pwd)/dist/kr" /opt/tools/bin/kr
    add-history kiterunner
    add-test-command "kr --help"
    add-to-list "kiterunner,https://github.com/assetnote/kiterunner,Tool for operating Active Directory environments."
}

function install_amass(){
    colorecho "Installing Amass"
    go install -v github.com/owasp-amass/amass/v3/...@master
    add-test-command "amass -version"
    add-to-list "amass,https://github.com/OWASP/Amass,A DNS enumeration, attack surface mapping & external assets discovery tool"
}

function install_ffuf() {
    colorecho "Installing ffuf"
    go install -v github.com/ffuf/ffuf@latest
    add-history ffuf
    add-test-command "ffuf --help"
    add-to-list "ffuf,https://github.com/ffuf/ffuf,Fast web fuzzer written in Go."
}

function install_dirsearch() {
    colorecho "Installing dirsearch"
    python3 -m pipx install git+https://github.com/maurosoria/dirsearch
    add-history dirsearch
    add-test-command "dirsearch --help"
    add-to-list "dirsearch,https://github.com/maurosoria/dirsearch,Tool for searching files and directories on a web site."
}

function install_ssrfmap() {
    colorecho "Installing SSRFmap"
    git -C /opt/tools/ clone --depth=1 https://github.com/swisskyrepo/SSRFmap
    cd /opt/tools/SSRFmap
    python3 -m venv ./venv
    ./venv/bin/python3 -m pip install -r requirements.txt
    add-aliases ssrfmap
    add-test-command "ssrfmap --help"
    add-to-list "ssrfmap,https://github.com/swisskyrepo/SSRFmap,a tool for testing SSRF vulnerabilities."
}

function install_gopherus() {
    colorecho "Installing gopherus"
    git -C /opt/tools/ clone --depth=1 https://github.com/tarunkant/Gopherus
    cd /opt/tools/Gopherus
    virtualenv -p /usr/bin/python2 ./venv
    ./venv/bin/python2 -m pip install argparse requests
    add-aliases gopherus
    add-test-command "gopherus --help"
    add-to-list "gopherus,https://github.com/tarunkant/Gopherus,Gopherus is a simple command line tool for exploiting vulnerable Gopher servers."
}

function install_nosqlmap() {
    # TODO : Fix this tool - Python2 or python3 ?
    colorecho "Installing NoSQLMap"
    git -C /opt/tools clone --depth=1 https://github.com/codingo/NoSQLMap.git
    cd /opt/tools/NoSQLMap
    virtualenv -p /usr/bin/python2 ./venv
    ./venv/bin/python2 setup.py install
    add-aliases nosqlmap
    add-test-command "nosqlmap --help"
    add-to-list "nosqlmap,https://github.com/codingo/NoSQLMap,a Python tool for testing NoSQL databases for security vulnerabilities."
}

function install_xsstrike() {
    colorecho "Installing XSStrike"
    git -C /opt/tools/ clone --depth=1 https://github.com/s0md3v/XSStrike.git
    cd /opt/tools/XSStrike
    python3 -m venv ./venv
    ./venv/bin/python3 -m pip install -r requirements.txt
    add-aliases xsstrike
    add-test-command "XSStrike --help"
    add-to-list "xsstrike,https://github.com/s0md3v/XSStrike,a Python tool for detecting and exploiting XSS vulnerabilities."
}

function install_xspear() {
    colorecho "Installing XSpear"
    # TODO : gem venv
    gem install XSpear
    add-test-command "XSpear --help"
    add-to-list "xspear,https://github.com/hahwul/XSpear,a powerful XSS scanning and exploitation tool."
}

function install_xsrfprobe() {
    colorecho "Installing XSRFProbe"
    python3 -m pipx install git+https://github.com/0xInfection/XSRFProbe
    add-test-command "xsrfprobe --help"
    add-to-list "xsrfprobe,https://github.com/0xInfection/XSRFProbe,a tool for detecting and exploiting Cross-Site Request Forgery (CSRF) vulnerabilities"
}

function install_bolt() {
    colorecho "Installing Bolt"
    git -C /opt/tools/ clone --depth=1 https://github.com/s0md3v/Bolt.git
    cd /opt/tools/Bolt
    python3 -m venv ./venv
    ./venv/bin/python3 -m pip install -r requirements.txt
    add-aliases bolt
    add-test-command "bolt --help"
    add-to-list "bolt,https://github.com/s0md3v/bolt,TODO"
}

function install_kadimus() {
    colorecho "Installing kadimus"
    # TODO : Check if deps are already installed
    fapt libcurl4-openssl-dev libpcre3-dev libssh-dev
    git -C /opt/tools/ clone --depth=1 https://github.com/P0cL4bs/Kadimus
    cd /opt/tools/Kadimus
    make
    add-aliases kadimus
    add-history kadimus
    add-test-command "kadimus --help"
    add-to-list "kadimus,https://github.com/P0cL4bs/Kadimus,a tool for detecting and exploiting file upload vulnerabilities"
}

function install_fuxploider() {
    colorecho "Installing fuxploider"
    git -C /opt/tools/ clone --depth=1 https://github.com/almandin/fuxploider.git
    cd /opt/tools/fuxploider
    python3 -m venv ./venv
    ./venv/bin/python3 -m pip install -r requirements.txt
    add-aliases fuxploider
    add-test-command "fuxploider --help"
    add-to-list "fuxploider,https://github.com/almandin/fuxploider,a Python tool for finding and exploiting file upload forms/directories."
}

function install_wpscan(){
    colorecho "Installing wpscan"
    # TODO : Check if deps are already installed
    fapt procps ruby-dev apt-transport-https ca-certificates gnupg2
    curl -sSL https://rvm.io/pkuczynski.asc | gpg2 --import -
    curl -sSL https://get.rvm.io | bash -s stable --ruby
    # TODO : gem venv
    gem install nokogiri -v 1.11.4 # use this version to resolve the conflict with cewl
    gem install wpscan
    add-history wpscan
    add-test-command "wpscan --help"
    add-to-list "wpscan,https://github.com/wpscanteam/wpscan,A tool to enumerate WordPress-based websites"
}

function install_droopescan() {
    colorecho "Installing droopescan"
    python3 -m pipx install git+https://github.com/droope/droopescan.git
    add-test-command "droopescan --help"
    add-to-list "droopescan,https://github.com/droope/droopescan,Scan Drupal websites for vulnerabilities."
}

function install_drupwn() {
    colorecho "Installing drupwn"
    git -C /opt/tools/ clone https://github.com/immunIT/drupwn
    python3 -m pipx install git+https://github.com/immunIT/drupwn
    add-test-command "drupwn --help"
    add-aliases drupwn
    add-to-list "drupwn,https://github.com/immunIT/drupwn,Drupal security scanner."
}

function install_cmsmap() {
    colorecho "Installing CMSmap"
    python3 -m pipx install git+https://github.com/Dionach/CMSmap.git
    # TODO: Config ?
    # exploit-db path is required (misc package -> searchsploit)
    # cmsmap -U PC
    add-history cmsmap
    add-test-command "cmsmap --help; cmsmap --help |& grep 'Post Exploitation'"
    add-to-list "cmsmap,https://github.com/Dionach/CMSmap,Tool for security audit of web content management systems."
}

function install_moodlescan() {
    colorecho "Installing moodlescan"
    git -C /opt/tools/ clone --depth=1 https://github.com/inc0d3/moodlescan.git
    cd /opt/tools/moodlescan
    python3 -m venv ./venv
    ./venv/bin/python3 -m pip install -r requirements.txt
    add-aliases moodlescan
    add-history moodlescan
    add-test-command "moodlescan --help"
    add-to-list "moodlescan,https://github.com/inc0d3/moodlescan,Scan Moodle sites for information and vulnerabilities."
}

function configure_moodlescan() {
    cd /opt/tools/moodlescan
    ./venv/bin/python3 moodlescan.py -a
}

function install_testssl() {
    colorecho "Installing testssl"
    # TODO : Check if deps are already installed
    fapt bsdmainutils
    git -C /opt/tools/ clone --depth=1 https://github.com/drwetter/testssl.sh.git
    add-aliases testssl
    add-test-command "testssl --help"
    add-to-list "testssl,https://github.com/drwetter/testssl.sh,a tool for testing SSL/TLS encryption on servers"
}

function install_tls-scanner() {
    colorecho "Installing TLS-Scanner"
    fapt maven
    git -C /opt/tools/ clone https://github.com/tls-attacker/TLS-Scanner
    cd /opt/tools/TLS-Scanner
    git submodule update --init --recursive
    mvn clean package -DskipTests=true
    add-aliases tls-scanner
    add-history tls-scanner
    add-test-command "tls-scanner --help"
    add-to-list "tls-scanner,https://github.com/tls-attacker/tls-scanner,a simple script to check the security of a remote TLS/SSL web server"
}

function install_cloudfail() {
    colorecho "Installing CloudFail"
    git -C /opt/tools/ clone --depth=1 https://github.com/m0rtem/CloudFail
    cd /opt/tools/CloudFail
    python3 -m venv ./venv
    ./venv/bin/python3 -m pip install -r requirements.txt
    add-aliases cloudfail
    add-history cloudfail
    add-test-command "cloudfail.py --help"
    add-to-list "cloudfail,https://github.com/m0rtem/CloudFail,a reconnaissance tool for identifying misconfigured CloudFront domains."
}

function install_eyewitness() {
    colorecho "Installing EyeWitness"
    git -C /opt/tools/ clone --depth=1 https://github.com/FortyNorthSecurity/EyeWitness
    cd /opt/tools/EyeWitness
    python3 -m venv ./venv
    source ./venv/bin/activate
    ./Python/setup/setup.sh
    deactivate
    add-aliases eyewitness
    add-test-command "eyewitness --help"
    add-to-list "eyewitness,https://github.com/FortyNorthSecurity/EyeWitness,a tool to take screenshots of websites, provide some server header info, and identify default credentials if possible."
}

function install_oneforall() {
    colorecho "Installing OneForAll"
    git -C /opt/tools/ clone --depth=1 https://github.com/shmilylty/OneForAll.git
    cd /opt/tools/OneForAll
    python3 -m venv ./venv
    ./venv/bin/python3 -m pip install -r requirements.txt
    add-aliases oneforall
    add-test-command "oneforall version"
    add-to-list "oneforall,https://github.com/shmilylty/OneForAll,a powerful subdomain collection tool."
}

function install_wafw00f() {
    colorecho "Installing wafw00f"
    python3 -m pipx install wafw00F
    add-test-command "wafw00f --help"
    add-to-list "wafw00f,https://github.com/EnableSecurity/wafw00f,a Python tool that helps to identify and fingerprint web application firewall (WAF) products."
}

function install_corscanner() {
    colorecho "Installing CORScanner"
    git -C /opt/tools/ clone --depth=1 https://github.com/chenjj/CORScanner.git
    cd /opt/tools/CORScanner
    python3 -m venv ./venv
    ./venv/bin/python3 -m pip install -r requirements.txt
    add-aliases corscanner
    add-test-command "corscanner --help"
    add-to-list "corscanner,https://github.com/chenjj/CORScanner,a Python script for finding CORS misconfigurations."
}

function install_hakrawler() {
    colorecho "Installing hakrawler"
    go install -v github.com/hakluke/hakrawler@latest
    add-history hakrawler
    add-test-command "hakrawler --help"
    add-to-list "hakrawler,https://github.com/hakluke/hakrawler,a fast web crawler for gathering URLs and other information from websites"
}

function install_gowitness() {
    colorecho "Installing gowitness"
    go install -v github.com/sensepost/gowitness@latest
    add-history gowitness
    add-test-command "gowitness --help"
    add-test-command "gowitness single https://exegol.readthedocs.io" # check the chromium dependency
    add-to-list "gowitness,https://github.com/sensepost/gowitness,A website screenshot utility written in Golang."
}

function install_linkfinder() {
    colorecho "Installing LinkFinder"
    git -C /opt/tools/ clone --depth=1 https://github.com/GerbenJavado/LinkFinder.git
    cd /opt/tools/LinkFinder
    python3 -m venv ./venv
    ./venv/bin/python3 -m pip install -r requirements.txt
    add-aliases linkfinder
    add-test-command "linkfinder --help"
    add-to-list "linkfinder,https://github.com/GerbenJavado/LinkFinder,a Python script that finds endpoints and their parameters in JavaScript files."
}

function install_timing_attack() {
    colorecho "Installing timing_attack"
    # TODO: gem venv
    gem install timing_attack
    add-test-command "timing_attack --help"
    add-to-list "timing,https://github.com/ffleming/timing_attack,Tool to generate a timing profile for a given command."
}

function install_updog() {
    colorecho "Installing updog"
    python3 -m pipx install updog
    add-history updog
    add-test-command "updog --help"
    add-to-list "updog,https://github.com/sc0tfree/updog,Simple replacement for Python's SimpleHTTPServer."
}

function install_jwt_tool() {
    colorecho "Installing JWT tool"
    git -C /opt/tools/ clone --depth=1 https://github.com/ticarpi/jwt_tool
    cd /opt/tools/jwt_tool
    python3 -m venv ./venv
    ./venv/bin/python3 -m pip install -r requirements.txt
    add-aliases jwt_tool
    add-test-command "jwt_tool --help"
    add-to-list "jwt,https://github.com/ticarpi/jwt_tool,a command-line tool for working with JSON Web Tokens (JWTs)"
}

function install_wuzz() {
    colorecho "Installing wuzz"
    go install -v github.com/asciimoo/wuzz@latest
    add-test-command "wuzz --help"
    add-to-list "wuzz,https://github.com/asciimoo/wuzz,a command-line tool for interacting with HTTP(S) web services"
}

function install_git-dumper() {
    colorecho "Installing git-dumper"
    python3 -m pipx install git-dumper
    add-test-command "git-dumper --help"
    add-to-list "git-dumper,https://github.com/arthaud/git-dumper,Small script to dump a Git repository from a website."
}

function install_gittools() {
    colorecho "Installing GitTools"
    git -C /opt/tools/ clone --depth=1 https://github.com/internetwache/GitTools.git
    cd /opt/tools/GitTools/Finder
    python3 -m venv ./venv
    ./venv/bin/python3 -m pip install -r requirements.txt
    add-aliases gittools
    add-test-command "extractor --help|& grep 'USAGE: extractor.sh GIT-DIR DEST-DIR'"
    add-test-command "gitdumper --help|& grep 'USAGE: http://target.tld/.git/'"
    add-test-command "gitfinder -h"
    add-to-list "gittools,https://github.com/internetwache/GitTools,A collection of Git tools including a powerful Dumper for dumping Git repositories."
}

function install_ysoserial() {
    colorecho "Installing ysoserial"
    mkdir /opt/tools/ysoserial/
    wget -O /opt/tools/ysoserial/ysoserial.jar "https://jitpack.io/com/github/frohoff/ysoserial/master-SNAPSHOT/ysoserial-master-SNAPSHOT.jar"
    add-aliases ysoserial
    add-test-command "ysoserial --help|& grep 'spring-core:4.1.4.RELEASE'"
    add-to-list "ysoserial,https://github.com/frohoff/ysoserial,A proof-of-concept tool for generating payloads that exploit unsafe Java object deserialization."
}

function install_symfony-exploits(){
    colorecho "Installing symfony-exploits"
    git -C /opt/tools clone --depth=1 https://github.com/ambionics/symfony-exploits
    add-aliases symfony-exploits
    add-test-command "secret_fragment_exploit.py --help"
    add-to-list "symfony-exploits,https://github.com/ambionics/symfony-exploits,Collection of Symfony exploits and PoCs."
}

function install_jdwp_shellifier(){
    colorecho "Installing jdwp_shellifier"
    git -C /opt/tools/ clone --depth=1 https://github.com/IOActive/jdwp-shellifier
    add-aliases jdwp-shellifier
    add-test-command "jdwp-shellifier.py --help"
    add-to-list "jdwp,https://github.com/IOActive/jdwp-shellifier,This exploitation script is meant to be used by pentesters against active JDWP service, in order to gain Remote Code Execution."
}

function install_httpmethods() {
    colorecho "Installing httpmethods"
    git -C /opt/tools/ clone --depth=1 https://github.com/ShutdownRepo/httpmethods
    cd /opt/tools/httpmethods
    python3 -m venv ./venv
    ./venv/bin/python3 -m pip install -r requirements.txt
    add-aliases httpmethods
    add-history httpmethods
    add-test-command "httpmethods --help"
    add-to-list "httpmethods,https://github.com/ShutdownRepo/httpmethods,Tool for exploiting HTTP methods (e.g. PUT, DELETE, etc.)"
}

function install_h2csmuggler() {
    colorecho "Installing h2csmuggler"
    git -C /opt/tools/ clone --depth=1 https://github.com/BishopFox/h2csmuggler
    cd /opt/tools/h2csmuggler
    python3 -m venv ./venv
    ./venv/bin/python3 -m pip install h2
    add-aliases h2csmuggler
    add-test-command "h2csmuggler --help"
    add-to-list "h2csmuggler,https://github.com/BishopFox/h2csmuggler,HTTP Request Smuggling tool using H2C upgrade"
}

function install_byp4xx() {
    colorecho "Installing byp4xx"
    go install -v github.com/lobuhi/byp4xx@latest
    add-test-command "byp4xx"
    add-to-list "byp4xx,https://github.com/lobuhi/byp4xx,A Swiss Army knife for bypassing web application firewalls and filters."
}

function install_feroxbuster() {
    colorecho "Installing feroxbuster"
    mkdir /opt/tools/feroxbuster
    cd /opt/tools/feroxbuster
    curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/master/install-nix.sh | bash
    # Adding a symbolic link in order for autorecon to be able to find the Feroxbuster binary
    ln -s /opt/tools/feroxbuster/feroxbuster /opt/tools/bin/feroxbuster
    add-aliases feroxbuster
    add-history feroxbuster
    add-test-command "feroxbuster --help"
    add-to-list "feroxbuster,https://github.com/epi052/feroxbuster,Simple, fast and recursive content discovery tool"
}

function install_tomcatwardeployer() {
    colorecho "Installing tomcatWarDeployer"
    git -C /opt/tools/ clone --depth=1 https://github.com/mgeeky/tomcatWarDeployer.git
    cd /opt/tools/tomcatWarDeployer
    python3 -m venv ./venv
    ./venv/bin/python3 -m pip install -r requirements.txt
    add-aliases tomcatwardeployer
    add-test-command "tomcatWarDeployer --help"
    add-to-list "tomcatwardeployer,https://github.com/mgeeky/tomcatwardeployer,Script to deploy war file in Tomcat."
}

function install_clusterd() {
    colorecho "Installing clusterd"
    git -C /opt/tools/ clone --depth=1 https://github.com/hatRiot/clusterd.git
    cd /opt/tools/clusterd
    virtualenv -p /usr/bin/python2 ./venv
    ./venv/bin/python2 -m pip install -r requirements.txt
    add-history clusterd
    add-test-command "clusterd --help"
    add-to-list "clusterd,https://github.com/hatRiot/clusterd,A tool to distribute and remotely manage Hacking Team's RCS agents."
}

function configure_clusterd() {
    echo -e '#!/bin/sh\n(cd /opt/tools/clusterd/ && ./venv/bin/python2 clusterd.py $@)' > /usr/local/bin/clusterd
    chmod +x /usr/local/bin/clusterd
}

function install_arjun() {
    colorecho "Installing arjun"
    python3 -m pipx install arjun
    add-test-command "arjun --help"
    add-to-list "arjun,https://github.com/s0md3v/Arjun,HTTP parameter discovery suite."
}

function install_nuclei() {
    colorecho "Installing Nuclei"
    go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
    add-history nuclei
    add-test-command "nuclei --version"
    add-to-list "nuclei,https://github.com/projectdiscovery/nuclei,A fast and customizable vulnerability scanner that can detect a wide range of issues, including XSS, SQL injection, and misconfigured servers."
}

function configure_nuclei() {
    /root/go/bin/nuclei -update-templates
}

function install_gau() {
    colorecho "Installing gau"
    GO111MODULE=on go install -v github.com/lc/gau@latest
    add-test-command "gau --help"
    add-to-list "gau,https://github.com/lc/gau,Fast tool for fetching URLs"
}

function install_hakrevdns() {
    colorecho "Installing Hakrevdns"
    go install -v github.com/hakluke/hakrevdns@latest
    add-history hakrevdns
    add-test-command "hakrevdns --help|& grep 'Protocol to use for lookups'"
    add-to-list "hakrevdns,https://github.com/hakluke/hakrevdns,Reverse DNS lookup utility that can help with discovering subdomains and other information."
}

function install_httprobe() {
    colorecho "Installing httprobe"
    go install -v github.com/tomnomnom/httprobe@latest
    add-test-command "httprobe --help"
    add-to-list "httprobe,https://github.com/tomnomnom/httprobe,A simple utility for enumerating HTTP and HTTPS servers."
}

function install_httpx() {
    colorecho "Installing httpx"
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
    add-history httpx
    add-test-command "httpx --help"
    add-to-list "httpx,https://github.com/projectdiscovery/httpx,A tool for identifying web technologies and vulnerabilities, including outdated software versions and weak encryption protocols."
}

function install_anew() {
    colorecho "Installing anew"
    go install -v github.com/tomnomnom/anew@latest
    add-test-command "anew --help"
    add-to-list "anew,https://github.com/tomnomnom/anew,A simple tool for filtering and manipulating text data, such as log files and other outputs."
}

function install_robotstester() {
    colorecho "Installing Robotstester"
    python3 -m pipx install git+https://github.com/p0dalirius/robotstester
    add-history robotstester
    add-test-command "robotstester --help"
    add-to-list "robotstester,https://github.com/p0dalirius/robotstester,Utility for testing whether a website's robots.txt file is correctly configured."
}

function install_naabu() {
    colorecho "Installing naabu"
    # TODO: Check if deps is already installed
    fapt libpcap-dev
    go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
    add-test-command "naabu --help"
    add-to-list "naabu,https://github.com/projectdiscovery/naabu,A fast and reliable port scanner that can detect open ports and services."
}

function install_burpsuite() {
    colorecho "Installing Burp"
    mkdir /opt/tools/BurpSuiteCommunity
    burp_version=$(curl -s "https://portswigger.net/burp/releases#community" | grep -P -o "\d{4}-\d-\d" | head -1 | tr - .)
    wget "https://portswigger.net/burp/releases/download?product=community&version=$burp_version&type=Jar" -O /opt/tools/BurpSuiteCommunity/BurpSuiteCommunity.jar
    # FIXME: set up the dark theme right away?
    # FIXME: add burp certificate to embedded firefox and chrome?
    # TODO: change Burp config to allow built-in browser to run
    add-aliases burpsuite
    add-to-list "burpsuite,https://portswigger.net/burp,Web application security testing tool."
}

function install_smuggler() {
    colorecho "Installing smuggler.py"
    git -C /opt/tools/ clone --depth=1 https://github.com/defparam/smuggler.git
    cd /opt/tools/smuggler
    python3 -m venv ./venv
    add-aliases smuggler
    add-history smuggler
    add-test-command "smuggler.py --help"
    add-to-list "smuggler,https://github.com/defparam/smuggler,Smuggler is a tool that helps pentesters and red teamers to smuggle data into and out of the network even when there are multiple layers of security in place."
}

function install_php_filter_chain_generator() {
    colorecho "Installing PHP_Filter_Chain_Generator"
    git -C /opt/tools/ clone --depth=1 https://github.com/synacktiv/php_filter_chain_generator.git
    add-aliases php_filter_chain_generator
    add-test-command "php_filter_chain_generator --help"
    add-to-list "PHP filter chain generator,https://github.com/synacktiv/php_filter_chain_generator,TODO"
}

function install_kraken() {
    colorecho "Installing Kraken"
    git -C /opt/tools clone --recurse-submodules https://github.com/kraken-ng/Kraken.git
    cd /opt/tools/Kraken
    python3 -m venv ./venv
    ./venv/bin/python3 -m pip install -r requirements.txt
    add-aliases kraken
    add-history kraken
    add-test-command "kraken.py -h"
    add-to-list "Modular multi-language webshell,https://github.com/kraken-ng/Kraken.git,Kraken is a modular multi-language webshell focused on web post-exploitation and defense evasion. It supports three technologies (PHP, JSP and ASPX) and is core is developed in Python."
}

function install_soapui() {
    colorecho "Installing SoapUI"
    mkdir -p /opt/tools/SoapUI/
    wget https://dl.eviware.com/soapuios/5.7.0/SoapUI-5.7.0-linux-bin.tar.gz -O /tmp/SoapUI.tar.gz
    tar xvf /tmp/SoapUI.tar.gz -C /opt/tools/SoapUI/ --strip=1
    add-aliases soapui
    add-test-command "/opt/tools/SoapUI/bin/testrunner.sh"
}
