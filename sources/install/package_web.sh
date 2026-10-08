#!/bin/bash
# Author: The Exegol Project

source common.sh

function install_web_apt_tools() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing web apt tools"
    fapt dirb prips swaks

    add-history dirb
    add-history prips
    add-history swaks

    add-test-command "dirb | grep '<username:password>'" # Web fuzzer
    add-test-command "prips --help"                      # Print the IP addresses in a given range
    add-test-command "swaks --version"                   # Featureful, flexible, scriptable, transaction-oriented SMTP test tool

    local version
    version="$(apt_version dirb)"
    add-to-list "dirb,${version},https://github.com/v0re/dirb,Web Content Scanner"
    version="$(apt_version prips)"
    add-to-list "prips,${version},https://manpages.ubuntu.com/manpages/focal/man1/prips.1.html,A utility for quickly generating IP ranges or enumerating hosts within a specified range."
    version="$(apt_version swaks)"
    add-to-list "swaks,${version},https://github.com/jetmore/swaks,Swaks is a featureful flexible scriptable transaction-oriented SMTP test tool."
}

function install_weevely() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing weevely"
    pipx install --python 3.13 --system-site-packages git+https://github.com/epinna/weevely3
    add-history weevely
    add-test-command "weevely --help"
    local version
    version="$(pipx_version weevely3)"
    add-to-list "weevely,${version},https://github.com/epinna/weevely3,a webshell designed for post-exploitation purposes that can be extended over the network at runtime."
}

function install_whatweb() {
    colorecho "Installing whatweb"
    git -C /opt/tools clone --depth 1 https://github.com/urbanadventurer/WhatWeb.git
    rvm use 3.2.2@whatweb --create
    gem install addressable
    bundle install --gemfile /opt/tools/WhatWeb/Gemfile
    rvm use 3.2.2@default
    add-aliases whatweb
    add-history whatweb
    add-test-command "whatweb --version"
    local version
    version="$(git_version /opt/tools/WhatWeb)"
    add-to-list "whatweb,${version},https://github.com/urbanadventurer/WhatWeb,Next generation web scanner that identifies what websites are running."

}

function install_wfuzz() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing wfuzz"
    apt --purge remove python3-pycurl -y
    fapt libcurl4-openssl-dev libssl-dev
    #pip3 install pycurl wfuzz  # uncomment when issue is fix
    mkdir /usr/share/wfuzz
    git -C /tmp clone --depth 1 https://github.com/xmendez/wfuzz.git
    # Wait for fix / PR to be merged: https://github.com/xmendez/wfuzz/issues/366 (still open 2026-09-21)
    local temp_fix_limit="2027-03-21"
    if check_temp_fix_expiry "$temp_fix_limit"; then
      pip3 install pycurl  # remove this line and uncomment the first when issue is fix
      sed -i 's/pyparsing>=2.4\*;/pyparsing>=2.4.2;/' /tmp/wfuzz/setup.py
      pip3 install /tmp/wfuzz/
    fi
    mv /tmp/wfuzz/wordlist/* /usr/share/wfuzz
    rm -rf /tmp/wfuzz
    add-history wfuzz
    add-test-command "wfuzz --help"
    add-test-command "test -d '/usr/share/wfuzz/' || exit 1"
    local version
    version="$(cli_version wfuzz --version)"
    add-to-list "wfuzz,${version},https://github.com/xmendez/wfuzz,WFuzz is a web application vulnerability scanner that allows you to find vulnerabilities using a wide range of attack payloads and fuzzing techniques"
}

function install_gobuster() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing gobuster"
    go install -v github.com/OJ/gobuster/v3@latest
    asdf reshim golang
    add-history gobuster
    add-test-command "gobuster --help"
    local version
    version="$(go_version gobuster)"
    add-to-list "gobuster,${version},https://github.com/OJ/gobuster,Tool to discover hidden files and directories."
}

function install_kiterunner() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing kiterunner (kr)"
    git -C /opt/tools/ clone --depth 1 https://github.com/assetnote/kiterunner.git
    cd /opt/tools/kiterunner || exit
    wget https://wordlists-cdn.assetnote.io/data/kiterunner/routes-large.kite.tar.gz
    wget https://wordlists-cdn.assetnote.io/data/kiterunner/routes-small.kite.tar.gz
    make build
    ln -v -s "$(pwd)/dist/kr" /opt/tools/bin/kr
    add-history kiterunner
    add-test-command "kr --help"
    local version
    version="$(git_version /opt/tools/kiterunner)"
    add-to-list "kiterunner,${version},https://github.com/assetnote/kiterunner,Tool for operating Active Directory environments."
}

function install_amass() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing Amass"
    go install -v github.com/owasp-amass/amass/v3/...@master
    asdf reshim golang
    add-history amass
    add-test-command "amass -version"
    local version
    version="$(go_version ...)"
    add-to-list "amass,${version},https://github.com/OWASP/Amass,A DNS enumeration / attack surface mapping & external assets discovery tool"
}

function install_ffuf() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing ffuf"
    if [[ $(uname -m) = 'x86_64' ]]
    then
        local arch="amd64"

    elif [[ $(uname -m) = 'aarch64' ]]
    then
        local arch="arm64"
    else
        criticalecho-noexit "This installation function doesn't support architecture $(uname -m)" && return
    fi
    local ffuf_url
    ffuf_url=$(curl --location --silent "https://api.github.com/repos/ffuf/ffuf/releases/latest" | grep 'browser_download_url.*ffuf.*linux_'"$arch"'.tar.gz"' | grep -o 'https://[^"]*')
    curl --location -o /tmp/ffuf.tar.gz "$ffuf_url"
    tar -xf /tmp/ffuf.tar.gz --directory /opt/tools/bin/
    add-history ffuf
    add-test-command "ffuf --help"
    local version
    version="$(cli_version ffuf --version)"
    add-to-list "ffuf,${version},https://github.com/ffuf/ffuf,Fast web fuzzer written in Go."
}

function install_dirsearch() {
    colorecho "Installing dirsearch"
    git -C /opt/tools/ clone --depth 1 https://github.com/maurosoria/dirsearch
    cd /opt/tools/dirsearch || exit
    python3 -m venv --system-site-packages ./venv
    source ./venv/bin/activate
    pip3 install -r requirements.txt
    deactivate
    add-aliases dirsearch
    add-history dirsearch
    add-test-command "dirsearch.py --help"
    local version
    version="$(git_version /opt/tools/dirsearch)"
    add-to-list "dirsearch,${version},https://github.com/maurosoria/dirsearch,Tool for searching files and directories on a web site."
}

function install_ssrfmap() {
    colorecho "Installing SSRFmap"
    git -C /opt/tools/ clone --depth 1 https://github.com/swisskyrepo/SSRFmap
    cd /opt/tools/SSRFmap || exit
    # default python3 is 3.11; upstream requires >=3.12 (pyproject.toml)
    python3.13 -m venv --system-site-packages ./venv
    source ./venv/bin/activate
    # requirements.txt was removed 2026-08-10; project is uv-managed and not pip-installable (package=false)
    pip3 install dnslib==0.9.24 dnspython==2.6.1 flask==3.0.3 requests==2.31.0 tldextract==5.1.2
    deactivate
    add-aliases ssrfmap
    add-history ssrfmap
    add-test-command "ssrfmap.py --help"
    local version
    version="$(git_version /opt/tools/SSRFmap)"
    add-to-list "ssrfmap,${version},https://github.com/swisskyrepo/SSRFmap,a tool for testing SSRF vulnerabilities."
}

function install_gopherus() {
    colorecho "Installing gopherus"
    git -C /opt/tools/ clone --depth 1 https://github.com/tarunkant/Gopherus
    cd /opt/tools/Gopherus || exit
    virtualenv --python python2 ./venv
    source ./venv/bin/activate
    pip2 install argparse requests
    deactivate
    add-aliases gopherus
    add-history gopherus
    add-test-command "gopherus.py --help"
    local version
    version="$(git_version /opt/tools/Gopherus)"
    add-to-list "gopherus,${version},https://github.com/tarunkant/Gopherus,Gopherus is a simple command line tool for exploiting vulnerable Gopher servers."
}

function install_nosqlmap() {
    # CODE-CHECK-WHITELIST=add-history
    colorecho "Installing NoSQLMap"
    git -C /opt/tools clone --depth 1 https://github.com/codingo/NoSQLMap.git
    cd /opt/tools/NoSQLMap || exit
    virtualenv --python python2 ./venv
    sed -i 's/requests==2\.32\.4/requests==2.27.1/' setup.py
    catch_and_retry ./venv/bin/python2 setup.py install
    # https://github.com/codingo/NoSQLMap/issues/126
    rm -rf venv/lib/python2.7/site-packages/certifi-2023.5.7-py2.7.egg
    source ./venv/bin/activate
    pip2 install certifi==2018.10.15
    deactivate
    add-aliases nosqlmap
    add-test-command "nosqlmap.py --help"
    local version
    version="$(git_version /opt/tools/NoSQLMap)"
    add-to-list "nosqlmap,${version},https://github.com/codingo/NoSQLMap,a Python tool for testing NoSQL databases for security vulnerabilities."
}

function install_xsstrike() {
    colorecho "Installing XSStrike"
    git -C /opt/tools/ clone --depth 1 https://github.com/s0md3v/XSStrike.git
    cd /opt/tools/XSStrike || exit
    python3 -m venv --system-site-packages ./venv
    source ./venv/bin/activate
    pip3 install -r requirements.txt
    deactivate
    add-aliases xsstrike
    add-history xsstrike
    add-test-command "xsstrike.py --help"
    local version
    version="$(git_version /opt/tools/XSStrike)"
    add-to-list "xsstrike,${version},https://github.com/s0md3v/XSStrike,a Python tool for detecting and exploiting XSS vulnerabilities."
}

function install_xspear() {
    colorecho "Installing XSpear"
    rvm use 3.2.2@xspear --create
    gem install XSpear
    rvm use 3.2.2@default
    add-aliases XSpear
    add-history XSpear
    add-test-command "XSpear --help"
    local version
    version="$(gem_version XSpear)"
    add-to-list "XSpear,${version},https://github.com/hahwul/XSpear,a powerful XSS scanning and exploitation tool."
}

function install_xsser() {
    colorecho "Installing xsser"
    git -C /opt/tools clone --depth 1 https://github.com/epsylon/xsser.git
    cd /opt/tools/xsser || exit
    python3 -m venv --system-site-packages ./venv
    source ./venv/bin/activate
    pip3 install pycurl bs4 pygeoip gobject cairocffi selenium
    deactivate
    add-aliases xsser
    add-history xsser
    add-test-command "xsser --help"
    local version
    version="$(git_version /opt/tools/xsser)"
    add-to-list "xsser,${version},https://github.com/epsylon/xsser,XSS scanner."
}

function install_xsrfprobe() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing XSRFProbe"
    pipx install --system-site-packages git+https://github.com/0xInfection/XSRFProbe
    add-history xsrfprobe
    add-test-command "xsrfprobe --help"
    local version
    version="$(pipx_version XSRFProbe)"
    add-to-list "xsrfprobe,${version},https://github.com/0xInfection/XSRFProbe,a tool for detecting and exploiting Cross-Site Request Forgery (CSRF) vulnerabilities"
}

function install_bolt() {
    colorecho "Installing Bolt"
    git -C /opt/tools/ clone --depth 1 https://github.com/s0md3v/Bolt.git
    cd /opt/tools/Bolt || exit
    python3 -m venv --system-site-packages ./venv
    source ./venv/bin/activate
    pip3 install -r requirements.txt
    deactivate
    add-aliases bolt
    add-history bolt
    add-test-command "bolt.py --help"
    local version
    version="$(git_version /opt/tools/Bolt)"
    add-to-list "bolt,${version},https://github.com/s0md3v/bolt,Bolt crawls the target website to the specified depth and stores all the HTML forms found in a database for further processing."
}

function install_fuxploider() {
    colorecho "Installing fuxploider"
    git -C /opt/tools/ clone --depth 1 https://github.com/almandin/fuxploider.git
    cd /opt/tools/fuxploider || exit
    python3 -m venv --system-site-packages ./venv
    source ./venv/bin/activate
    pip3 install -r requirements.txt
    deactivate
    add-aliases fuxploider
    add-history fuxploider
    add-test-command "fuxploider.py --help"
    local version
    version="$(git_version /opt/tools/fuxploider)"
    add-to-list "fuxploider,${version},https://github.com/almandin/fuxploider,a Python tool for finding and exploiting file upload forms/directories."
}

function install_patator() {
    colorecho "Installing patator"
    fapt libmariadb-dev libcurl4-openssl-dev libssl-dev ldap-utils libpq-dev ike-scan unzip default-jdk libsqlite3-dev libsqlcipher-dev
    git -C /opt/tools clone --depth 1 https://github.com/lanjelot/patator.git
    cd /opt/tools/patator || exit
    python3.13 -m venv --system-site-packages ./venv
    source ./venv/bin/activate
    # setuptools 82 dropped pkg_resources: https://github.com/pypa/setuptools/issues/5174
    # Follow-up: patator is hatchling now; switch to pip install . / pipx and drop this pin.
    local temp_fix_limit="2027-03-21"
    if check_temp_fix_expiry "$temp_fix_limit"; then
      echo 'setuptools<82' > build-constraints.txt
      pip3 install --build-constraint build-constraints.txt -r requirements.txt
    fi
    #pip3 install -r requirements.txt
    deactivate
    add-aliases patator
    add-history patator
    add-test-command "patator.py ftp_login --help"
    local version
    version="$(git_version /opt/tools/patator)"
    add-to-list "patator,${version},https://github.com/lanjelot/patator,Login scanner."
}

function install_joomscan() {
    colorecho "Installing joomscan"
    git -C /opt/tools/ clone --depth 1 https://github.com/rezasp/joomscan
    add-aliases joomscan
    add-history joomscan
    add-test-command "joomscan --version"
    local version
    version="$(git_version /opt/tools/joomscan)"
    add-to-list "joomscan,${version},https://github.com/rezasp/joomscan,A tool to enumerate Joomla-based websites"
}

function install_wpscan() {
    colorecho "Installing wpscan"
    rvm use 3.2.2@wpscan --create
    gem install wpscan
    rvm use 3.2.2@default
    add-aliases wpscan
    add-history wpscan
    add-test-command "wpscan --help"
    local version
    version="$(gem_version wpscan)"
    add-to-list "wpscan,${version},https://github.com/wpscanteam/wpscan,A tool to enumerate WordPress-based websites"
}

function install_droopescan() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing droopescan"
    pipx install --system-site-packages git+https://github.com/droope/droopescan.git
    add-history droopescan
    add-test-command "droopescan --help"
    local version
    version="$(pipx_version droopescan.git)"
    add-to-list "droopescan,${version},https://github.com/droope/droopescan,Scan Drupal websites for vulnerabilities."
}

function install_drupwn() {
    colorecho "Installing drupwn"
    git -C /opt/tools/ clone --depth 1 https://github.com/immunIT/drupwn
    cd /opt/tools/drupwn || exit
    python3 -m venv --system-site-packages ./venv
    source ./venv/bin/activate
    pip3 install -r ./requirements.txt
    deactivate
    add-aliases drupwn
    add-history drupwn
    add-test-command "drupwn --help"
    local version
    version="$(git_version /opt/tools/drupwn)"
    add-to-list "drupwn,${version},https://github.com/immunIT/drupwn,Drupal security scanner."
}

function install_cmsmap() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing CMSmap"
    pipx install --system-site-packages git+https://github.com/Dionach/CMSmap.git
    sed -i 's/wordlist =  wordlist\/rockyou.txt/wordlist =  \/usr\/share\/wordlists\/rockyou.txt/' /root/.local/share/pipx/venvs/cmsmap/lib/python3*/site-packages/cmsmap/cmsmap.conf
    sed -i 's/edbpath = \/usr\/share\/exploitdb/edbpath = \/opt\/tools\/exploitdb/' /root/.local/share/pipx/venvs/cmsmap/lib/python3*/site-packages/cmsmap/cmsmap.conf
    sed -i 's/edbtype = apt/edbtype = git/' /root/.local/share/pipx/venvs/cmsmap/lib/python3*/site-packages/cmsmap/cmsmap.conf
    # exploit-db path is required (misc package -> searchsploit)
    # cmsmap -U PC
    add-history cmsmap
    add-test-command "cmsmap --help; cmsmap --help |& grep 'Post Exploitation'"
    local version
    version="$(pipx_version CMSmap.git)"
    add-to-list "cmsmap,${version},https://github.com/Dionach/CMSmap,Tool for security audit of web content management systems."
}

function install_moodlescan() {
    colorecho "Installing moodlescan"
    git -C /opt/tools/ clone --depth 1 https://github.com/inc0d3/moodlescan.git
    cd /opt/tools/moodlescan || exit
    python3 -m venv --system-site-packages ./venv
    source ./venv/bin/activate
    pip3 install -r requirements.txt
    deactivate
    cd /opt/tools/moodlescan || exit
    # updating moodlescan database
    catch_and_retry ./venv/bin/python3 moodlescan.py -a
    add-aliases moodlescan
    add-history moodlescan
    add-test-command "moodlescan.py --help"
    local version
    version="$(git_version /opt/tools/moodlescan)"
    add-to-list "moodlescan,${version},https://github.com/inc0d3/moodlescan,Scan Moodle sites for information and vulnerabilities."
}

function install_testssl() {
    colorecho "Installing testssl"
    # TODO : Check if deps are already installed
    fapt bsdmainutils
    git -C /opt/tools/ clone --depth 1 https://github.com/drwetter/testssl.sh.git
    add-aliases testssl
    add-history testssl
    add-test-command "testssl.sh --help"
    local version
    version="$(git_version /opt/tools/testssl.sh)"
    add-to-list "testssl,${version},https://github.com/drwetter/testssl.sh,a tool for testing SSL/TLS encryption on servers"
}

function install_cloudfail() {
    colorecho "Installing CloudFail"
    git -C /opt/tools/ clone --depth 1 https://github.com/m0rtem/CloudFail
    cd /opt/tools/CloudFail || exit
    python3 -m venv --system-site-packages ./venv
    source ./venv/bin/activate
    pip3 install -r requirements.txt
    deactivate
    add-aliases cloudfail
    add-history cloudfail
    add-test-command "cloudfail.py --help"
    local version
    version="$(git_version /opt/tools/CloudFail)"
    add-to-list "cloudfail,${version},https://github.com/m0rtem/CloudFail,a reconnaissance tool for identifying misconfigured CloudFront domains."
}

function install_eyewitness() {
    colorecho "Installing EyeWitness"
    git -C /opt/tools/ clone --depth 1 https://github.com/FortyNorthSecurity/EyeWitness
    cd /opt/tools/EyeWitness || exit
    fapt jq cmake xvfb chromium chromium-driver
    python3 -m venv --system-site-packages ./venv
    source ./venv/bin/activate
    pip3 install -r ./setup/requirements.txt
    deactivate
    add-aliases eyewitness
    add-history eyewitness
    add-test-command "EyeWitness.py --help"
    local version
    version="$(git_version /opt/tools/EyeWitness)"
    add-to-list "eyewitness,${version},https://github.com/FortyNorthSecurity/EyeWitness,a tool to take screenshots of websites / provide some server header info / and identify default credentials if possible."
}

function install_oneforall() {
    colorecho "Installing OneForAll"
    git -C /opt/tools/ clone --depth 1 https://github.com/shmilylty/OneForAll.git
    cd /opt/tools/OneForAll || exit
    python3 -m venv --system-site-packages ./venv
    source ./venv/bin/activate
    pip3 install -r requirements.txt
    deactivate
    add-aliases oneforall
    add-history oneforall
    add-test-command "oneforall.py check"
    local version
    version="$(git_version /opt/tools/OneForAll)"
    add-to-list "oneforall,${version},https://github.com/shmilylty/OneForAll,a powerful subdomain collection tool."
}

function install_wafw00f() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing wafw00f"
    pipx install --system-site-packages wafw00F
    add-history wafw00f
    add-test-command "wafw00f --help"
    local version
    version="$(pipx_version wafw00F)"
    add-to-list "wafw00f,${version},https://github.com/EnableSecurity/wafw00f,a Python tool that helps to identify and fingerprint web application firewall (WAF) products."
}

function install_corscanner() {
    colorecho "Installing CORScanner"
    git -C /opt/tools/ clone --depth 1 https://github.com/chenjj/CORScanner.git
    cd /opt/tools/CORScanner || exit
    python3 -m venv --system-site-packages ./venv
    source ./venv/bin/activate
    pip3 install -r requirements.txt
    deactivate
    add-aliases corscanner
    add-history corscanner
    add-test-command "cors_scan.py --help"
    local version
    version="$(git_version /opt/tools/CORScanner)"
    add-to-list "corscanner,${version},https://github.com/chenjj/CORScanner,a Python script for finding CORS misconfigurations."
}

function install_hakrawler() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing hakrawler"
    go install -v github.com/hakluke/hakrawler@latest
    asdf reshim golang
    add-history hakrawler
    add-test-command "hakrawler --help"
    local version
    version="$(go_version hakrawler)"
    add-to-list "hakrawler,${version},https://github.com/hakluke/hakrawler,a fast web crawler for gathering URLs and other information from websites"
}

function install_gowitness() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing gowitness"
    asdf set golang 1.26.1
    go install -v github.com/sensepost/gowitness@latest
    asdf reshim golang
    add-history gowitness
    add-test-command "gowitness --help"
    local version
    version="$(go_version gowitness)"
    add-to-list "gowitness,${version},https://github.com/sensepost/gowitness,A website screenshot utility written in Golang."
}

function install_linkfinder() {
    colorecho "Installing LinkFinder"
    git -C /opt/tools/ clone --depth 1 https://github.com/GerbenJavado/LinkFinder.git
    cd /opt/tools/LinkFinder || exit
    python3 -m venv --system-site-packages ./venv
    source ./venv/bin/activate
    pip3 install -r requirements.txt
    deactivate
    add-aliases linkfinder
    add-history linkfinder
    add-test-command "linkfinder.py --help"
    local version
    version="$(git_version /opt/tools/LinkFinder)"
    add-to-list "linkfinder,${version},https://github.com/GerbenJavado/LinkFinder,a Python script that finds endpoints and their parameters in JavaScript files."
}

function install_timing_attack() {
    colorecho "Installing timing_attack"
    rvm use 3.2.2@timing_attack --create
    gem install timing_attack
    rvm use 3.2.2@default
    add-aliases timing_attack
    add-history timing_attack
    add-test-command "timing_attack --help"
    local version
    version="$(gem_version timing_attack)"
    add-to-list "timing,${version},https://github.com/ffleming/timing_attack,Tool to generate a timing profile for a given command."
}

function install_updog() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing updog"
    pipx install --system-site-packages updog
    add-history updog
    add-test-command "updog --help"
    local version
    version="$(pipx_version updog)"
    add-to-list "updog,${version},https://github.com/sc0tfree/updog,Simple replacement for Python's SimpleHTTPServer."
}

function install_jwt_tool() {
    colorecho "Installing JWT tool"
    git -C /opt/tools/ clone --depth 1 https://github.com/ticarpi/jwt_tool
    cd /opt/tools/jwt_tool || exit
    python3 -m venv --system-site-packages ./venv
    source ./venv/bin/activate
    pip3 install -r requirements.txt
    # Running the tool to create the initial configuration and force it to returns 0
    python3 jwt_tool.py || :
    deactivate

    # Configuration
    sed -i 's/^proxy = 127.0.0.1:8080/#proxy = 127.0.0.1:8080/' /root/.jwt_tool/jwtconf.ini
    sed -i 's|^wordlist = jwt-common.txt|wordlist = /opt/tools/jwt_tool/jwt-common.txt|' /root/.jwt_tool/jwtconf.ini
    sed -i 's|^commonHeaders = common-headers.txt|commonHeaders = /opt/tools/jwt_tool/common-headers.txt|' /root/.jwt_tool/jwtconf.ini
    sed -i 's|^commonPayloads = common-payloads.txt|commonPayloads = /opt/tools/jwt_tool/common-payloads.txt|' /root/.jwt_tool/jwtconf.ini

    add-aliases jwt_tool
    add-history jwt_tool
    add-test-command "jwt_tool.py --help"
    local version
    version="$(git_version /opt/tools/jwt_tool)"
    add-to-list "jwt,${version},https://github.com/ticarpi/jwt_tool,a command-line tool for working with JSON Web Tokens (JWTs)"
}

function install_wuzz() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing wuzz"
    go install -v github.com/asciimoo/wuzz@latest
    asdf reshim golang
    add-history wuzz
    add-test-command "wuzz --help"
    local version
    version="$(go_version wuzz)"
    add-to-list "wuzz,${version},https://github.com/asciimoo/wuzz,a command-line tool for interacting with HTTP(S) web services"
}

function install_git-dumper() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing git-dumper"
    pipx install --system-site-packages git-dumper
    add-history git-dumper
    add-test-command "git-dumper --help"
    local version
    version="$(pipx_version git-dumper)"
    add-to-list "git-dumper,${version},https://github.com/arthaud/git-dumper,Small script to dump a Git repository from a website."
}

function install_gittools() {
    colorecho "Installing GitTools"
    git -C /opt/tools/ clone --depth 1 https://github.com/internetwache/GitTools.git
    cd /opt/tools/GitTools/Finder || exit
    python3 -m venv --system-site-packages ./venv
    source ./venv/bin/activate
    pip3 install -r requirements.txt
    deactivate
    add-aliases gittools
    add-history gittools
    add-test-command "extractor.sh --help|& grep 'USAGE: extractor.sh GIT-DIR DEST-DIR'"
    add-test-command "gitdumper.sh --help|& grep 'USAGE: http://target.tld/.git/'"
    add-test-command "gitfinder.py -h"
    local version
    version="$(git_version /opt/tools/GitTools)"
    add-to-list "gittools,${version},https://github.com/internetwache/GitTools,A collection of Git tools including a powerful Dumper for dumping Git repositories."
}

function install_ysoserial() {
    colorecho "Installing ysoserial"
    mkdir /opt/tools/ysoserial/
    wget -O /opt/tools/ysoserial/ysoserial.jar "https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar"
    add-aliases ysoserial
    add-history ysoserial
    add-test-command "ysoserial --help|& grep 'spring-core:4.1.4.RELEASE'"
    add-test-command "ysoserial CommonsCollections4 'whoami'"
    local version
    version="$(cli_version ysoserial --version)"
    add-to-list "ysoserial,${version},https://github.com/frohoff/ysoserial,A proof-of-concept tool for generating payloads that exploit unsafe Java object deserialization."
}

function install_phpggc() {
    colorecho "Installing phpggc"
    git -C /opt/tools clone --depth 1 https://github.com/ambionics/phpggc.git
    add-aliases phpggc
    add-history phpggc
    add-test-command "phpggc --help"
    local version
    version="$(git_version /opt/tools/phpggc)"
    add-to-list "phpggc,${version},https://github.com/ambionics/phpggc,Exploit generation tool for the PHP platform."
}

function install_symfony-exploits(){
    colorecho "Installing symfony-exploits"
    git -C /opt/tools clone --depth 1 https://github.com/ambionics/symfony-exploits
    add-aliases symfony-exploits
    add-history symfony-exploits
    add-test-command "secret_fragment_exploit.py --help"
    local version
    version="$(git_version /opt/tools/symfony-exploits)"
    add-to-list "symfony-exploits,${version},https://github.com/ambionics/symfony-exploits,Collection of Symfony exploits and PoCs."
}

function install_jdwp_shellifier(){
    colorecho "Installing jdwp_shellifier"
    git -C /opt/tools/ clone --depth 1 https://github.com/IOActive/jdwp-shellifier
    add-aliases jdwp-shellifier
    add-history jdwp-shellifier
    add-test-command "jdwp-shellifier.py --help"
    local version
    version="$(git_version /opt/tools/jdwp-shellifier)"
    add-to-list "jdwp,${version},https://github.com/IOActive/jdwp-shellifier,This exploitation script is meant to be used by pentesters against active JDWP service / in order to gain Remote Code Execution."
}

function install_httpmethods() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing httpmethods"
    pipx install --system-site-packages git+https://github.com/ShutdownRepo/httpmethods
    add-history httpmethods
    add-test-command "httpmethods --help"
    local version
    version="$(pipx_version httpmethods)"
    add-to-list "httpmethods,${version},https://github.com/ShutdownRepo/httpmethods,Tool for exploiting HTTP methods (e.g. PUT / DELETE / etc.)"
}

function install_h2csmuggler() {
    colorecho "Installing h2csmuggler"
    git -C /opt/tools/ clone --depth 1 https://github.com/BishopFox/h2csmuggler
    cd /opt/tools/h2csmuggler || exit
    python3 -m venv --system-site-packages ./venv
    source ./venv/bin/activate
    pip3 install h2
    deactivate
    add-aliases h2csmuggler
    add-history h2csmuggler
    add-test-command "h2csmuggler.py --help"
    local version
    version="$(git_version /opt/tools/h2csmuggler)"
    add-to-list "h2csmuggler,${version},https://github.com/BishopFox/h2csmuggler,HTTP Request Smuggling tool using H2C upgrade"
}

function install_byp4xx() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing byp4xx"
    go install -v github.com/lobuhi/byp4xx@latest
    asdf reshim golang
    add-history byp4xx
    add-test-command byp4xx
    local version
    version="$(go_version byp4xx)"
    add-to-list "byp4xx,${version},https://github.com/lobuhi/byp4xx,A Swiss Army knife for bypassing web application firewalls and filters."
}

function install_feroxbuster() {
    colorecho "Installing feroxbuster"
    mkdir /opt/tools/feroxbuster
    cd /opt/tools/feroxbuster || exit
    # splitting curl | bash to avoid having additional logs put in curl output being executed because of catch_and_retry
    curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/master/install-nix.sh -o /tmp/install-feroxbuster.sh
    bash /tmp/install-feroxbuster.sh
    # Adding a symbolic link in order for autorecon to be able to find the Feroxbuster binary
    ln -v -s /opt/tools/feroxbuster/feroxbuster /opt/tools/bin/feroxbuster
    add-aliases feroxbuster
    add-history feroxbuster
    add-test-command "feroxbuster --help"
    local version
    version="$(cli_version feroxbuster --version)"
    add-to-list "feroxbuster,${version},https://github.com/epi052/feroxbuster,Simple / fast and recursive content discovery tool"
}

function install_tomcatwardeployer() {
    colorecho "Installing tomcatWarDeployer"
    git -C /opt/tools/ clone --depth 1 https://github.com/mgeeky/tomcatWarDeployer.git
    cd /opt/tools/tomcatWarDeployer || exit
    python3 -m venv --system-site-packages ./venv
    source ./venv/bin/activate
    pip3 install -r requirements.txt
    deactivate
    add-aliases tomcatwardeployer
    add-history tomcatwardeployer
    add-test-command "tomcatWarDeployer.py --help"
    local version
    version="$(git_version /opt/tools/tomcatWarDeployer)"
    add-to-list "tomcatwardeployer,${version},https://github.com/mgeeky/tomcatwardeployer,Script to deploy war file in Tomcat."
}

function install_arjun() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing arjun"
    pipx install --system-site-packages arjun
    add-history arjun
    add-test-command "arjun --help"
    local version
    version="$(pipx_version arjun)"
    add-to-list "arjun,${version},https://github.com/s0md3v/Arjun,HTTP parameter discovery suite."
}

function install_nuclei() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing Nuclei"
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
    asdf reshim golang
    nuclei -update-templates
    add-history nuclei
    add-test-command "nuclei --version"
    local version
    version="$(go_version nuclei)"
    add-to-list "nuclei,${version},https://github.com/projectdiscovery/nuclei,A fast and customizable vulnerability scanner that can detect a wide range of issues / including XSS / SQL injection / and misconfigured servers."
}

function install_gau() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing gau"
    go install github.com/lc/gau/v2/cmd/gau@latest
    asdf reshim golang
    add-history gau
    add-test-command "gau --help"
    local version
    version="$(go_version gau)"
    add-to-list "gau,${version},https://github.com/lc/gau,Fast tool for fetching URLs"
}

function install_hakrevdns() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing Hakrevdns"
    go install -v github.com/hakluke/hakrevdns@latest
    asdf reshim golang
    add-history hakrevdns
    add-test-command "hakrevdns --help|& grep 'Protocol to use for lookups'"
    local version
    version="$(go_version hakrevdns)"
    add-to-list "hakrevdns,${version},https://github.com/hakluke/hakrevdns,Reverse DNS lookup utility that can help with discovering subdomains and other information."
}

function install_httprobe() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing httprobe"
    go install -v github.com/tomnomnom/httprobe@latest
    asdf reshim golang
    add-history httprobe
    add-test-command "httprobe --help"
    local version
    version="$(go_version httprobe)"
    add-to-list "httprobe,${version},https://github.com/tomnomnom/httprobe,A simple utility for enumerating HTTP and HTTPS servers."
}

function install_httpx() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing httpx"
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
    asdf reshim golang
    add-history httpx
    add-test-command "httpx --help"
    local version
    version="$(go_version httpx)"
    add-to-list "httpx,${version},https://github.com/projectdiscovery/httpx,A tool for identifying web technologies and vulnerabilities / including outdated software versions and weak encryption protocols."
}

function install_alterx() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing alterx"
    go install -v github.com/projectdiscovery/alterx/cmd/alterx@latest
    asdf reshim golang
    add-history alterx
    add-test-command "alterx --help"
    local version
    version="$(go_version alterx)"
    add-to-list "alterx,${version},https://github.com/projectdiscovery/alterx,A tool for fast and customizable subdomain wordlist generator using DSL from ProjectDiscovery."
}

function install_chaos() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing chaos"
    go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest
    asdf reshim golang
    add-history chaos
    add-test-command "chaos --help"
    local version
    version="$(go_version chaos)"
    add-to-list "chaos,${version},https://github.com/projectdiscovery/alterx,A Go client to communicate with Chaos dataset API from ProjectDiscovery."
}

function install_uncover() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing uncover"
    go install -v github.com/projectdiscovery/uncover/cmd/uncover@latest
    asdf reshim golang
    add-history uncover
    add-test-command "uncover --help"
    local version
    version="$(go_version uncover)"
    add-to-list "uncover,${version},https://github.com/projectdiscovery/uncover,A tool to Quickly discover exposed hosts on the internet using multiple search engines from ProjectDiscovery."
}

function install_anew() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing anew"
    go install -v github.com/tomnomnom/anew@latest
    asdf reshim golang
    add-history anew
    add-test-command "anew --help"
    local version
    version="$(go_version anew)"
    add-to-list "anew,${version},https://github.com/tomnomnom/anew,A simple tool for filtering and manipulating text data / such as log files and other outputs."
}

function install_robotstester() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing Robotstester"
    pipx install --system-site-packages git+https://github.com/p0dalirius/robotstester
    add-history robotstester
    add-test-command "robotstester --help"
    local version
    version="$(pipx_version robotstester)"
    add-to-list "robotstester,${version},https://github.com/p0dalirius/robotstester,Utility for testing whether a website's robots.txt file is correctly configured."
}

function install_naabu() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing naabu"
    fapt libpcap-dev
    go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
    asdf reshim golang
    add-history naabu
    add-test-command "naabu --help"
    local version
    version="$(go_version naabu)"
    add-to-list "naabu,${version},https://github.com/projectdiscovery/naabu,A fast and reliable port scanner that can detect open ports and services."
}

function install_burpsuite() {
    colorecho "Installing Burp"
    mkdir /opt/tools/BurpSuiteCommunity
    curl 'https://portswigger.net/burp/releases/data?previousLastId=-1&lastId=-1&pageSize=10' -o /tmp/burp_relases.json
    burp_release=$(jq -r '.ResultSet.Results[] | select(.releaseChannels | contains(["Stable"])) | .builds[] | select(.BuildCategoryPlatformLabel == "JAR" and (.BuildCategoryId == "community" or .BuildCategoryId == "desktop")) | "\(.BuildCategoryId) \(.Version)"' /tmp/burp_relases.json | head -n 1)
    burp_version=$(echo "$burp_release" | cut -d ' ' -f2)
    burp_product=$(echo "$burp_release" | cut -d ' ' -f1)
    wget "https://portswigger.net/burp/releases/startdownload?product=$burp_product&version=$burp_version&type=Jar" -O /opt/tools/BurpSuiteCommunity/BurpSuiteCommunity.jar
    # TODO: two lines below should set up dark theme as default, does it work?
    mkdir -p /root/.BurpSuite/
    # proxy (server) config for burpsuite
    cp -v /root/sources/assets/burpsuite/conf.json /opt/tools/BurpSuiteCommunity/
    # user config for burpsuite (dark theme)
    cp -v /root/sources/assets/burpsuite/UserConfigCommunity.json /root/.BurpSuite/UserConfigCommunity.json
    # script to trust burp CA
    cp -v /root/sources/assets/burpsuite/trust-ca-burp.sh /opt/tools/BurpSuiteCommunity/
    chmod +x /opt/tools/BurpSuiteCommunity/trust-ca-burp.sh
    ln -v -s /opt/tools/BurpSuiteCommunity/trust-ca-burp.sh /opt/tools/bin/trust-ca-burp
    # init burp app files
    local burp_pid
    echo "Starting burp"
    echo y|/usr/lib/jvm/java-21-openjdk/bin/java -Djava.awt.headless=true -jar /opt/tools/BurpSuiteCommunity/BurpSuiteCommunity.jar --config-file=/opt/tools/BurpSuiteCommunity/conf.json > /dev/null &
    burp_pid=$!
    echo "Burp is running with PID: $burp_pid"
    local timeout_counter
    timeout_counter=0
    # Wait for Burp to init and start
    while ! (netstat -lnt|grep -qEo "(127.0.0.1|0.0.0.0):8080")
    do
      if ! kill -0 "$burp_pid" 2>/dev/null; then
        criticalecho "Burp exited before becoming ready."
        exit 1
      fi
      if [[ $timeout_counter -lt 300 ]]; then
        sleep 1
        timeout_counter=$((timeout_counter+1))
      else
        criticalecho "Burp starting timed out.."
        kill "$burp_pid" 2>/dev/null || true
        wait "$burp_pid" 2>/dev/null || true
        exit 1
      fi
    done
    echo "Burp started successfully. Killing the job now."
    kill "$burp_pid" 2>/dev/null || true
    wait "$burp_pid" 2>/dev/null || true
    # Cleanup local burp database
    rm -rf /root/.java/.userPrefs/burp
    rm -rf /tmp/burp*.tmp
    rm /tmp/burp_relases.json
    add-aliases burpsuite
    add-history burpsuite
    add-test-command "which burpsuite"
    #add-test-gui-command "BurpSuiteCommunity"
    local version
    version="$(normalize_version "${burp_version}")"
    add-to-list "burpsuite,${version},https://portswigger.net/burp,Web application security testing tool."
}

function install_smuggler() {
    colorecho "Installing smuggler.py"
    git -C /opt/tools/ clone --depth 1 https://github.com/defparam/smuggler.git
    cd /opt/tools/smuggler || exit
    python3 -m venv --system-site-packages ./venv
    add-aliases smuggler
    add-history smuggler
    add-test-command "smuggler.py --help"
    local version
    version="$(git_version /opt/tools/smuggler)"
    add-to-list "smuggler,${version},https://github.com/defparam/smuggler,Smuggler is a tool that helps pentesters and red teamers to smuggle data into and out of the network even when there are multiple layers of security in place."
}

function install_php_filter_chain_generator() {
    colorecho "Installing PHP_Filter_Chain_Generator"
    git -C /opt/tools/ clone --depth 1 https://github.com/synacktiv/php_filter_chain_generator.git
    add-aliases php_filter_chain_generator
    add-history php_filter_chain_generator
    add-test-command "php_filter_chain_generator.py --help"
    local version
    version="$(cli_version 'PHP filter chain generator' --version)"
    add-to-list "PHP filter chain generator,${version},https://github.com/synacktiv/php_filter_chain_generator,A CLI to generate PHP filters chain / get your RCE without uploading a file if you control entirely the parameter passed to a require or an include in PHP!"
}

function install_kraken() {
    colorecho "Installing Kraken"
    git -C /opt/tools clone --depth 1 --recursive --shallow-submodules https://github.com/kraken-ng/Kraken.git
    cd /opt/tools/Kraken || exit
    python3 -m venv --system-site-packages ./venv
    source ./venv/bin/activate
    pip3 install -r requirements.txt
    deactivate
    add-aliases kraken
    add-history kraken
    add-test-command "kraken.py -h"
    local version
    version="$(git_version /opt/tools/Kraken)"
    add-to-list "Kraken,${version},https://github.com/kraken-ng/Kraken,Kraken is a modular multi-language webshell focused on web post-exploitation and defense evasion. It supports three technologies (PHP / JSP and ASPX) and is core is developed in Python."
}

function install_soapui() {
    colorecho "Installing SoapUI"
    mkdir -p /opt/tools/SoapUI/
    wget https://dl.eviware.com/soapuios/5.7.0/SoapUI-5.7.0-linux-bin.tar.gz -O /tmp/SoapUI.tar.gz
    tar xvf /tmp/SoapUI.tar.gz -C /opt/tools/SoapUI/ --strip=1
    add-aliases soapui
    add-history soapui
    add-test-command "/opt/tools/SoapUI/bin/testrunner.sh"
    local version
    version="$(cli_version SoapUI --version)"
    add-to-list "SoapUI,${version},https://github.com/SmartBear/soapui,SoapUI is the world's leading testing tool for API testing."
}

function install_sqlmap() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing sqlmap"
    git -C /opt/tools/ clone --depth 1 https://github.com/sqlmapproject/sqlmap.git
    ln -s "/opt/tools/sqlmap/sqlmap.py" /opt/tools/bin/sqlmap
    add-history sqlmap
    add-test-command "sqlmap --version"
    local version
    version="$(git_version /opt/tools/sqlmap)"
    add-to-list "sqlmap,${version},https://github.com/sqlmapproject/sqlmap,Sqlmap is an open-source penetration testing tool that automates the process of detecting and exploiting SQL injection flaws"
}

function install_sslscan() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing sslscan"
    git -C /tmp clone --depth 1 https://github.com/rbsec/sslscan.git
    cd /tmp/sslscan || exit
    make static
    mv /tmp/sslscan/sslscan /opt/tools/bin/sslscan
    add-history sslscan
    add-test-command "sslscan --version"
    local version
    version="$(git_version /tmp/sslscan)"
    add-to-list "sslscan,${version},https://github.com/rbsec/sslscan,a tool for testing SSL/TLS encryption on servers"
}

function install_jsluice() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing jsluice"
    go install -v github.com/BishopFox/jsluice/cmd/jsluice@latest
    asdf reshim golang
    add-history jsluice
    add-test-command "jsluice --help"
    local version
    version="$(go_version jsluice)"
    add-to-list "jsluice,${version},https://github.com/BishopFox/jsluice,Extract URLs / paths / secrets and other interesting data from JavaScript source code."
}

function install_katana() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing katana"
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest
    asdf reshim golang
    add-history katana
    add-test-command "katana --help"
    local version
    version="$(go_version katana)"
    add-to-list "katana,${version},https://github.com/projectdiscovery/katana,A next-generation crawling and spidering framework."
}

function install_postman() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing Postman"
    local archive_name
    if [[ $(uname -m) = 'x86_64' ]]; then
        archive_name="linux_64"
    elif [[ $(uname -m) = 'aarch64' ]]; then
        archive_name="linux_arm64"
    fi
    curl -L "https://dl.pstmn.io/download/latest/${archive_name}" -o /tmp/postman.tar.gz
    tar -xf /tmp/postman.tar.gz --directory /tmp
    rm /tmp/postman.tar.gz
    mv /tmp/Postman /tmp/postman
    mv /tmp/postman /opt/tools/postman
    ln -s /opt/tools/postman/app/Postman /opt/tools/bin/postman
    fapt libsecret-1-0
    add-history postman
    add-test-command "which postman"
    #add-test-gui-command "postman"
    local version
    version="$(cli_version postman --version)"
    add-to-list "postman,${version},https://www.postman.com/,API platform for testing APIs"
}

function install_wpprobe() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing wpprobe"
    go install -v github.com/Chocapikk/wpprobe@latest
    asdf reshim golang
    add-history wpprobe
    add-test-command "wpprobe --help"
    local version
    version="$(go_version wpprobe)"
    add-to-list "wpprobe,${version},https://github.com/Chocapikk/wpprobe,A fast WordPress plugin enumeration tool."
}

function install_caido() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing Caido"
    fapt libxss1
    mkdir /opt/tools/caido
    local arch
    arch=$(uname -m)
    local caido_json
    caido_json=$(curl -s https://api.caido.io/releases/latest)

    # Desktop
    local caido_deb
    caido_deb=$(echo "$caido_json" | grep -o '"link":"[^"]*"' | cut -d'"' -f4 | grep "linux-${arch}\.deb$")
    local caido_file_name
    caido_file_name=$(basename "$caido_deb")
    wget "$caido_deb" -O "/opt/tools/caido/$caido_file_name"
    dpkg -i /opt/tools/caido/"$caido_file_name"

    # CLI
    caido_cli=$(echo "$caido_json" | grep -o '"link":"[^"]*"' | cut -d'"' -f4 | grep "caido-cli-v.*-linux-${arch}\.tar\.gz$")
    local caido_file_name_cli
    caido_file_name_cli=$(basename "$caido_cli")
    wget "$caido_cli" -O "/opt/tools/caido/$caido_file_name_cli"
    tar -xvzf "/opt/tools/caido/$caido_file_name_cli" -C /opt/tools/bin/

    rm /opt/tools/caido/"$caido_file_name" "/opt/tools/caido/$caido_file_name_cli"

    add-history caido
    add-test-gui-command "caido --no-sandbox"
    add-test-command "caido-cli --help"
    local version
    version="$(cli_version caido --version)"
    add-to-list "caido,${version},https://docs.caido.io/quickstart/,A lightweight web security auditing toolkit."
}

function install_token_exploiter() {
    # CODE-CHECK-WHITELIST=add-aliases,add-history
    colorecho "Installing Token Exploiter"
    pipx install --system-site-packages git+https://github.com/psyray/token-exploiter
    add-test-command "token-exploiter --help"
    local version
    version="$(pipx_version token-exploiter)"
    add-to-list "token-exploiter,${version},https://github.com/psyray/token-exploiter,Token Exploiter is a tool designed to analyze GitHub Personal Access Tokens."
}

function install_bbot() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing BBOT"
    pipx install --system-site-packages bbot
    add-history bbot
    add-test-command "bbot --help"
    local version
    version="$(pipx_version bbot)"
    add-to-list "BBOT,${version},https://github.com/blacklanternsecurity/bbot,BEE·bot is a multipurpose scanner inspired by Spiderfoot built to automate your Recon and ASM."
}

function install_subzy() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing subzy"
    asdf set golang 1.23.0
    go install -v github.com/PentestPad/subzy@latest
    asdf reshim golang
    add-history subzy
    add-test-command "subzy --help"
    local version
    version="$(go_version subzy)"
    add-to-list "subzy,${version},https://github.com/PentestPad/subzy,Subdomain takeover tool which checks for various cloud services and identifies if a subdomain is vulnerable."
}

function install_urldedupe() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing urldedupe"
    git -C /tmp clone --depth 1 https://github.com/ameenmaali/urldedupe.git
    cd /tmp/urldedupe || exit
    cmake CMakeLists.txt
    make
    cp /tmp/urldedupe/urldedupe /opt/tools/bin/urldedupe
    # Must leave before rm: a deleted cwd breaks later pipx/pyenv (getcwd).
    cd /tmp || exit
    rm -rf /tmp/urldedupe/
    add-history urldedupe
    add-test-command "urldedupe -h"
    local version
    version="$(cli_version urldedupe --version)"
    add-to-list "urldedupe,${version},https://github.com/ameenmaali/urldedupe,urldedupe is a c++ tool to quickly pass in a list of URLs and get back a list of deduplicated (unique) URL and query string combination."
}

function install_curlie() {
    # CODE-CHECK-WHITELIST=add-history,add-aliases
    colorecho "Installing curlie"
    if [[ $(uname -m) = 'x86_64' ]]
    then
        local arch="amd64"
    elif [[ $(uname -m) = 'aarch64' ]]
    then
        local arch="arm64"
    else
        criticalecho-noexit "This installation function doesn't support architecture $(uname -m)" && return
    fi
    local URL
    URL=$(curl --location --silent "https://api.github.com/repos/rs/curlie/releases/latest" | grep 'browser_download_url.*curlie.*linux.*'"$arch"'.*tar.gz"' | grep -o 'https://[^"]*')
    curl --location -o /tmp/curlie.tar.gz "$URL"
    tar -zxf /tmp/curlie.tar.gz --directory /tmp curlie
    rm /tmp/curlie.tar.gz
    mv /tmp/curlie /opt/tools/bin/curlie
    add-test-command "curlie"
    local version
    version="$(cli_version curlie --version)"
    add-to-list "curlie,${version},https://github.com/rs/curlie,Curlie is a frontend to curl that adds the ease of use of httpie without compromising on features and performance"
}

function install_xxeinjector() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing XXEinjector"
    wget https://raw.githubusercontent.com/enjoiz/XXEinjector/refs/heads/master/XXEinjector.rb -O /opt/tools/bin/XXEinjector.rb
    chmod +x /opt/tools/bin/XXEinjector.rb
    add-history xxeinjector
    add-test-command "XXEinjector.rb | grep Example"
    local version
    version="$(cli_version XXEinjector --version)"
    add-to-list "XXEinjector,${version},https://github.com/enjoiz/XXEinjector,A tool for XML External Entity (XXE) injection testing"
}

function install_tlsx() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing tlsx"
    asdf set golang 1.26.1
    go install -trimpath -ldflags="-s -w" -v github.com/projectdiscovery/tlsx/cmd/tlsx@latest
    asdf reshim golang
    add-history tlsx
    add-test-command "tlsx --version"
    local version
    version="$(go_version tlsx)"
    add-to-list "tlsx,${version},https://github.com/projectdiscovery/tlsx,A fast and configurable TLS grabber focused on TLS based data collection and analysis."
}

function install_vulnx() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing vulnx"
    asdf set golang 1.26.1
    go install -trimpath -ldflags="-s -w" -v github.com/projectdiscovery/vulnx/v2/cmd/vulnx@latest
    asdf reshim golang
    add-history vulnx
    add-test-command "vulnx --help"
    local version
    version="$(go_version vulnx)"
    add-to-list "vulnx,${version},https://github.com/projectdiscovery/vulnx,Modern CLI for exploring vulnerability data with powerful search filtering and analysis capabilities."
}

function install_urlfinder() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing URLFinder"
    go install -trimpath -ldflags="-s -w" -v github.com/projectdiscovery/urlfinder/cmd/urlfinder@latest
    asdf reshim golang
    add-history urlfinder
    add-test-command "urlfinder --version"
    local version
    version="$(go_version urlfinder)"
    add-to-list "urlfinder,${version},https://github.com/projectdiscovery/urlfinder,URLFinder is a high-speed passive URL discovery tool designed to simplify and accelerate web asset discovery."
}

function install_mapcidr() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing mapCIDR"
    asdf set golang 1.26.1
    go install -trimpath -ldflags="-s -w" -v github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest
    asdf reshim golang
    add-history mapcidr
    add-test-command "mapcidr --version"
    local version
    version="$(go_version mapcidr)"
    add-to-list "mapcidr,${version},https://github.com/projectdiscovery/mapcidr,Utility program to perform multiple operations for a given subnet/CIDR ranges."
}

function install_badsecrets() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing badsecrets"
    pipx install --system-site-packages badsecrets
    add-history badsecrets
    add-test-command "badsecrets 'eyJhbGciOiJIUzI1NiJ9.eyJJc3N1ZXIiOiJJc3N1ZXIiLCJVc2VybmFtZSI6IkJhZFNlY3JldHMiLCJleHAiOjE1OTMxMzM0ODMsImlhdCI6MTQ2NjkwMzA4M30.ovqRikAo_0kKJ0GVrAwQlezymxrLGjcEiW_s3UJMMCo' |& grep 'Known Secret Found'"
    local version
    version="$(pipx_version badsecrets)"
    add-to-list "badsecrets,${version},https://github.com/blacklanternsecurity/badsecrets,A pure python library for identifying the use of known or very weak cryptographic secrets across a variety of platforms."
}

# Package dedicated to applicative and active web pentest tools
function package_web() {
    set_env
    local start_time
    local end_time
    start_time=$(date +%s)
    install_web_apt_tools
    install_weevely                 # Weaponized web shell
    install_whatweb                 # Recognises web technologies including content management
    install_wfuzz                   # Web fuzzer (second favorites)
    install_gobuster                # Web fuzzer (pretty good for several extensions)
    install_kiterunner              # Web fuzzer (fast and pretty good for api bruteforce)
    install_amass                   # Web fuzzer
    install_ffuf                    # Web fuzzer (little favorites)
    install_dirsearch               # Web fuzzer
    install_ssrfmap                 # SSRF scanner
    install_gopherus                # SSRF helper
    install_nosqlmap                # NoSQL scanner
    install_xsstrike                # XSS scanner
    install_xspear                  # XSS scanner
    install_xsser                   # XSS scanner
    install_xsrfprobe               # CSRF scanner
    install_bolt                    # CSRF scanner
    install_fuxploider              # File upload scanner
    install_patator                 # Login scanner
    install_joomscan                # Joomla scanner
    install_wpscan                  # Wordpress scanner
    install_droopescan              # Drupal scanner
    install_drupwn                  # Drupal scanner
    install_cmsmap                  # CMS scanner (Joomla, Wordpress, Drupal)
    install_moodlescan              # Moodle scanner
    install_testssl                 # SSL/TLS scanner
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
    install_phpggc                  # php deserialization payloads
    install_symfony-exploits        # symfony secret fragments exploit
    install_jdwp_shellifier         # exploit java debug
    install_httpmethods             # Tool for HTTP methods enum & verb tampering
    install_h2csmuggler             # Tool for HTTP2 smuggling
    install_byp4xx                  # Tool to automate 40x errors bypass attempts
    install_feroxbuster             # ffuf but with multithreaded recursion
    install_tomcatwardeployer       # Apache Tomcat auto WAR deployment & pwning tool
    install_arjun                   # HTTP Parameter Discovery
    install_nuclei                  # Vulnerability scanner - Needed for gau install
    install_gau                     # fetches known URLs from AlienVault's Open Threat Exchange, the Wayback Machine, Common Crawl, and URLScan
    install_hakrevdns               # Reverse DNS lookups
    install_httprobe                # Probe http
    install_httpx                   # Probe http
    install_alterx                  # Subdomain wordlist generator
    install_chaos                   # Exposed hosts discovery using multiple search engines
    install_uncover                 # Quickly discover exposed hosts on the internet using multiple search engines.
    install_anew                    # A tool for adding new lines to files, skipping duplicates
    install_robotstester            # Robots.txt scanner
    install_naabu                   # Fast port scanner
    # install_gitrob                # Senstive files reconnaissance in github #FIXME: Go version too old ?
    install_burpsuite
    install_smuggler                # HTTP Request Smuggling scanner
    install_php_filter_chain_generator # A CLI to generate PHP filters chain and get your RCE
    install_kraken                  # Kraken is a modular multi-language webshell.
    install_soapui                  # SoapUI is an open-source web service testing application for SOAP and REST
    install_sqlmap                  # SQL injection scanner
    install_sslscan                 # SSL/TLS scanner
    install_jsluice                 # Extract URLs, paths, secrets, and other interesting data from JavaScript source code
    install_katana                  # A next-generation crawling and spidering framework
    install_postman                 # Postman - API platform for testing APIs
    install_wpprobe                 # WPProbe - Tool for detecting WordPress plugins using misconfigured REST API endpoints
    install_caido                   # Caido
    install_token_exploiter         # Github personal token Analyzer
    install_bbot                    # Recursive Scanner
    install_subzy                   # Subdomain takeover tool
    install_urldedupe               # Get back a list of deduplicated (unique) URL and query string combination. 
    install_curlie                  # Mix of cURL and HTTPie
    install_xxeinjector             # XXE injection testing tool
    install_tlsx
    install_vulnx
    install_urlfinder
    install_mapcidr
    install_badsecrets
    post_install
    end_time=$(date +%s)
    local elapsed_time=$((end_time - start_time))
    colorecho "Package web completed in $elapsed_time seconds."
}
