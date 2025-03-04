#!/bin/bash
# Author: The Exegol Project

source common.sh

function configure_tor() {
    echo 'SOCKSPort 127.0.0.1:9050' >> /etc/tor/torrc
}

function install_osint_apt_tools() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing OSINT apt tools"
    fapt exiftool exifprobe dnsenum tor whois recon-ng

    add-history exiftool
    add-history exifprobe
    add-history dnsenum
    add-history tor
    add-history whois
    add-history recon-ng
    
    add-test-command "wget -O /tmp/duck.png https://play-lh.googleusercontent.com/A6y8kFPu6iiFg7RSkGxyNspjOBmeaD3oAOip5dqQvXASnZp-Vg65jigJJLHr5mOEOryx && exiftool /tmp/duck.png && rm /tmp/duck.png" # For read exif information
    add-test-command "exifprobe -V; exifprobe -V |& grep 'Hubert Figuiere'"             # Probe and report structure and metadata content of camera image files
    add-test-command "dnsenum --help; dnsenum --help |& grep 'Print this help message'" # DNSEnum is a command-line tool that automatically identifies basic DNS records
    add-test-command "tor --help"                                                # Tor proxy
    add-test-command "whois --help"                                                     # See information about a specific domain name or IP address
    add-test-command "recon-ng --help"                                                  # External recon tool

    add-to-list "exiftool,https://github.com/exiftool/exiftool,ExifTool is a Perl library and command-line tool for reading / writing and editing meta information in image / audio and video files."
    add-to-list "exifprobe,https://github.com/hfiguiere/exifprobe,Exifprobe is a command-line tool to parse EXIF data from image files."
    add-to-list "dnsenum,https://github.com/fwaeytens/dnsenum,dnsenum is a tool for enumerating DNS information about a domain."
    add-to-list "tor,https://github.com/torproject/tor,Anonymity tool that can help protect your privacy and online identity by routing your traffic through a network of servers."
    add-to-list "whois,https://packages.debian.org/sid/whois,See information about a specific domain name or IP address."
    add-to-list "recon-ng,https://github.com/lanmaster53/recon-ng,External recon tool."
}

function install_youtubedl() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing youtube-dl"
    pipx install --system-site-packages youtube-dl
    add-history youtube-dl
    add-test-command "youtube-dl --version"
    add-to-list "youtubedl,https://github.com/ytdl-org/youtube-dl,Download videos from YouTube and other sites."
}

function install_sublist3r() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing Sublist3r"
    pipx install --system-site-packages git+https://github.com/aboul3la/Sublist3r
    add-history sublist3r
    add-test-command "sublist3r --help"
    add-to-list "sublist3r,https://github.com/aboul3la/Sublist3r,a Python tool designed to enumerate subdomains of websites."
}

function install_assetfinder() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing assetfinder"
    go install -v github.com/tomnomnom/assetfinder@latest
    asdf reshim golang
    add-history assetfinder
    add-test-command "assetfinder --help"
    add-to-list "assetfinder,https://github.com/tomnomnom/assetfinder,Tool to find subdomains and IP addresses associated with a domain."
}

function install_subfinder() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing subfinder"
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
    asdf reshim golang
    add-history subfinder
    add-test-command "subfinder -version"
    add-to-list "subfinder,https://github.com/projectdiscovery/subfinder,Tool to find subdomains associated with a domain."
}

function install_findomain() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing findomain"
    if [[ $(uname -m) = 'x86_64' ]]
    then
        wget -O /tmp/findomain.zip "https://github.com/findomain/findomain/releases/latest/download/findomain-linux.zip"
    elif [[ $(uname -m) = 'aarch64' ]]
    then
        wget -O /tmp/findomain.zip "https://github.com/findomain/findomain/releases/latest/download/findomain-aarch64.zip"
    else
        criticalecho-noexit "This installation function doesn't support architecture $(uname -m)" && return
    fi
    unzip -d /opt/tools/bin/ /tmp/findomain.zip
    chmod +x /opt/tools/bin/findomain
    rm /tmp/findomain.zip
    add-history findomain
    add-test-command "findomain --version"
    add-to-list "findomain,https://github.com/findomain/findomain,The fastest and cross-platform subdomain enumerator."
}

function install_holehe() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing holehe"
    pipx install --system-site-packages holehe
    add-history holehe
    add-test-command "holehe --help"
    add-to-list "holehe,https://github.com/megadose/holehe,mail osint tool finding out if it is used on websites."
}

function install_simplyemail() {
    colorecho "Installing SimplyEmail"
    git -C /opt/tools/ clone --branch master --depth 1 https://github.com/killswitch-GUI/SimplyEmail.git
    cd /opt/tools/SimplyEmail/ || exit
    fapt antiword odt2txt libxml2-dev libxslt1-dev
    virtualenv --python python2 ./venv
    source ./venv/bin/activate
    pip2 install -r ./setup/requirments.txt
    deactivate
    add-aliases simplyemail
    add-history simplyemail
    add-test-command "SimplyEmail.py -l"
    add-to-list "simplyemail,https://github.com/SimplySecurity/SimplyEmail,a scriptable command line tool for sending emails"
}

function install_theharvester() {
    colorecho "Installing theHarvester"
    git -C /opt/tools/ clone --depth 1 https://github.com/laramies/theHarvester
    cd /opt/tools/theHarvester || exit
    python3 -m venv --system-site-packages ./venv
    source ./venv/bin/activate
    pip3 install -r requirements.txt
    deactivate
    # The tool needs access to the proxies.yaml file in the folder.
    ln -s /opt/tools/theHarvester /usr/local/etc/
    add-aliases theharvester
    add-history theharvester
    add-test-command "theHarvester.py --help"
    add-to-list "theharvester,https://github.com/laramies/theHarvester,Tool for gathering e-mail accounts / subdomain names / virtual host / open ports / banners / and employee names from different public sources"
}

function install_h8mail() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing h8mail"
    pipx install --system-site-packages h8mail
    add-history h8mail
    add-test-command "h8mail --help"
    add-to-list "h8mail,https://github.com/khast3x/h8mail,Email OSINT and breach hunting."
}

function install_infoga() {
    colorecho "Installing infoga"
    git -C /opt/tools/ clone --depth 1 https://github.com/m4ll0k/Infoga
    find /opt/tools/Infoga/ -type f -print0 | xargs -0 dos2unix
    cd /opt/tools/Infoga || exit
    python2 -m virtualenv ./venv
    source ./venv/bin/activate
    pip2 install .
    deactivate
    add-aliases infoga
    add-history infoga
    add-test-command "infoga.py --help"
    add-to-list "infoga,https://github.com/m4ll0k/Infoga,Information gathering tool for hacking."
}

function install_pwnedornot() {
    colorecho "Installing pwnedornot"
    git -C /opt/tools/ clone --depth 1 https://github.com/thewhiteh4t/pwnedOrNot
    cd /opt/tools/pwnedOrNot || exit
    python3 -m venv --system-site-packages ./venv
    source ./venv/bin/activate
    pip3 install requests html2text
    deactivate
    mkdir -p "$HOME/.config/pwnedornot"
    cp config.json "$HOME/.config/pwnedornot/config.json"
    add-aliases pwnedornot
    add-history pwnedornot
    add-test-command "pwnedornot.py --help"
    add-to-list "pwnedornot,https://github.com/thewhiteh4t/pwnedOrNot,Check if a password has been leaked in a data breach."
}

function install_phoneinfoga() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing phoneinfoga"
    if [[ $(uname -m) = 'x86_64' ]]
    then
        wget -O /tmp/phoneinfoga.tar.gz "https://github.com/sundowndev/phoneinfoga/releases/latest/download/phoneinfoga_Linux_x86_64.tar.gz"
    elif [[ $(uname -m) = 'aarch64' ]]
    then
        wget -O /tmp/phoneinfoga.tar.gz "https://github.com/sundowndev/phoneinfoga/releases/latest/download/phoneinfoga_Linux_arm64.tar.gz"
    else
        criticalecho-noexit "This installation function doesn't support architecture $(uname -m)" && return
    fi
    tar xfv /tmp/phoneinfoga.tar.gz -C /opt/tools/bin/
    rm /tmp/phoneinfoga.tar.gz
    add-history phoneinfoga
    add-test-command "phoneinfoga help"
    add-to-list "phoneinfoga,https://github.com/sundowndev/PhoneInfoga,Information gathering & OSINT framework for phone numbers."
}

function install_maigret() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing maigret"
    pipx install --system-site-packages git+https://github.com/soxoj/maigret.git
    add-history maigret
    add-test-command "maigret --help"
    add-to-list "maigret,https://github.com/soxoj/maigret,Collects information about a target email (or domain) from Google and Bing search results"
}

function install_linkedin2username() {
    colorecho "Installing linkedin2username"
    git -C /opt/tools/ clone --depth 1 https://github.com/initstring/linkedin2username
    cd /opt/tools/linkedin2username || exit
    python3 -m venv --system-site-packages ./venv
    source ./venv/bin/activate
    pip3 install -r requirements.txt
    deactivate
    add-aliases linkedin2username
    add-history linkedin2username
    add-test-command "linkedin2username.py --help"
    add-to-list "linkedin2username,https://github.com/initstring/linkedin2username,Generate a list of LinkedIn usernames from a company name."
}

function install_toutatis() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing toutatis"
    pipx install --system-site-packages git+https://github.com/megadose/toutatis
    add-history toutatis
    add-test-command "toutatis --help"
    add-to-list "toutatis,https://github.com/megadose/Toutatis,Toutatis is a tool that allows you to extract information from instagrams accounts such as e-mails / phone numbers and more."
}

function install_waybackurls() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing waybackurls"
    go install -v github.com/tomnomnom/waybackurls@latest
    asdf reshim golang
    add-history waybackurls
    add-test-command "waybackurls -h"
    add-to-list "waybackurls,https://github.com/tomnomnom/waybackurls,Fetch all the URLs that the Wayback Machine knows about for a domain."
}

function install_carbon14() {
    colorecho "Installing Carbon14"
    git -C /opt/tools/ clone --depth 1 https://github.com/Lazza/Carbon14
    cd /opt/tools/Carbon14 || exit
    python3 -m venv --system-site-packages ./venv
    source ./venv/bin/activate
    pip3 install -r requirements.txt
    deactivate
    add-aliases carbon14
    add-history carbon14
    add-test-command "carbon14.py --help"
    add-to-list "carbon14,https://github.com/Lazza/carbon14,OSINT tool for estimating when a web page was written."
}

function install_photon() {
    colorecho "Installing photon"
    git -C /opt/tools/ clone --depth 1 https://github.com/s0md3v/photon
    cd /opt/tools/photon || exit
    python3 -m venv --system-site-packages ./venv
    source ./venv/bin/activate
    pip3 install -r requirements.txt
    deactivate
    add-aliases photon
    add-history photon
    add-test-command "photon.py --help"
    add-to-list "photon,https://github.com/s0md3v/Photon,a fast web crawler which extracts URLs / files / intel & endpoints from a target."
}

function install_ipinfo() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing ipinfo"
    # TODO: npm venv
    sudo npm install ipinfo-cli --global
    add-history ipinfo
    add-test-command "ipinfo 127.0.0.1"
    add-to-list "ipinfo,https://github.com/ipinfo/cli,Get information about an IP address or hostname."
}

function install_constellation() {
    # CODE-CHECK-WHITELIST=add-aliases,add-test-command
    colorecho "Installing constellation"
    if [[ $(uname -m) = 'x86_64' ]]
    then
        wget -O /tmp/constellation.tar.gz https://github.com/constellation-app/constellation/releases/download/v2.1.1/constellation-linux-v2.1.1.tar.gz
        tar xvf /tmp/constellation.tar.gz -C /opt/tools/
        rm /tmp/constellation.tar.gz
        ln -s /opt/tools/constellation/bin/constellation /opt/tools/bin/constellation
    else
        criticalecho-noexit "This installation function doesn't support architecture $(uname -m)" && return
    fi
    # TODO ARM64 install
    # TODO add-test-command
    add-history constellation
    add-to-list "constellation,https://github.com/constellation-app/Constellation,Find and exploit vulnerabilities in mobile applications."
}

function install_maltego() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing Maltego"
    wget https://maltego-downloads.s3.us-east-2.amazonaws.com/linux/Maltego.v4.3.0.deb -O /tmp/maltegov4.3_package.deb
    dpkg -i /tmp/maltegov4.3_package.deb
    add-history maltego
    add-test-command "file /usr/share/maltego/bin/maltego"
    add-to-list "maltego,https://www.paterva.com/web7/downloads.php,A tool used for open-source intelligence and forensics"
}

function install_spiderfoot() {
    colorecho "Installing Spiderfoot"
    git -C /opt/tools/ clone --depth 1 https://github.com/smicallef/spiderfoot
    cd /opt/tools/spiderfoot || exit
    python3 -m venv --system-site-packages ./venv
    source ./venv/bin/activate
    pip3 install -r requirements.txt
    deactivate
    add-aliases spiderfoot
    add-history spiderfoot
    add-test-command "spiderfoot --help"
    add-test-command "spiderfoot-cli --help"
    add-to-list "spiderfoot,https://github.com/smicallef/spiderfoot,A reconnaissance tool that automatically queries over 100 public data sources"
}

function install_finalrecon() {
    colorecho "Installing FinalRecon"
    git -C /opt/tools/ clone --depth 1 https://github.com/thewhiteh4t/FinalRecon
    cd /opt/tools/FinalRecon || exit
    python3 -m venv --system-site-packages ./venv
    source ./venv/bin/activate
    pip3 install -r requirements.txt
    # https://github.com/ThePorgs/Exegol-images/issues/372
    pip3 install aiodns
    deactivate
    add-aliases finalrecon
    add-history finalrecon
    add-test-command "finalrecon.py --help"
    add-to-list "finalrecon,https://github.com/thewhiteh4t/FinalRecon,A web reconnaissance tool that gathers information about web pages"
}

function install_osrframework() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing osrframework"
    pipx install --system-site-packages osrframework
    pipx inject osrframework 'urllib3<2'
    pipx inject osrframework 'pip==21.2'
    add-history osrframework
    add-test-command "osrframework-cli --help"
    add-to-list "osrframework,https://github.com/i3visio/osrframework,Include references to a bunch of different applications related to username checking / DNS lookups / information leaks research / deep web search / regular expressions extraction and many others."
}

function install_pwndb() {
    colorecho "Installing pwndb"
    git -C /opt/tools/ clone --depth 1 https://github.com/davidtavarez/pwndb.git
    cd /opt/tools/pwndb || exit
    python3 -m venv --system-site-packages ./venv
    source ./venv/bin/activate
    pip3 install -r requirements.txt
    pip3 install -U pysocks
    deactivate
    add-aliases pwndb
    add-history pwndb
    add-test-command "pwndb.py --help"
    add-to-list "pwndb,https://github.com/davidtavarez/pwndb,A command-line tool for searching the pwndb database of compromised credentials."
}

function install_githubemail() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing github-email"
    # TODO: npm venv
    npm install --global github-email
    add-history github-email
    add-test-command "github-email whatever"
    add-to-list "githubemail,https://github.com/paulirish/github-email,a command-line tool to retrieve a user's email from Github."
}

function install_recondog() {
    colorecho "Installing ReconDog"
    git -C /opt/tools/ clone --depth 1 https://github.com/s0md3v/ReconDog
    cd /opt/tools/ReconDog/ || exit
    python3 -m venv --system-site-packages ./venv
    source ./venv/bin/activate
    pip3 install -r requirements.txt
    deactivate
    add-aliases recondog
    add-history recondog
    add-test-command "recondog --help"
    add-to-list "recondog,https://github.com/s0md3v/ReconDog,a reconnaissance tool for performing information gathering on a target."
}

function install_gron() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing gron"
    go install -v github.com/tomnomnom/gron@latest
    asdf reshim golang
    add-history gron
    add-test-command "gron --help"
    add-to-list "gron,https://github.com/tomnomnom/gron,Make JSON greppable!"
}

function install_ignorant() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing ignorant"
    pipx install --system-site-packages git+https://github.com/megadose/ignorant
    add-history ignorant
    add-test-command "ignorant --help"
    add-to-list "ignorant,https://github.com/megadose/ignorant,holehe but for phone numbers."
}

function install_trevorspray() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing trevorspray"
    git -C /opt/tools/ clone --depth 1 https://github.com/blacklanternsecurity/TREVORspray
    cd /opt/tools/TREVORspray || exit
    # https://github.com/blacklanternsecurity/TREVORspray/pull/27
    sed -i "s/1.0.5/1.0.4/" pyproject.toml
    pipx install --system-site-packages .
    add-history trevorspray
    add-test-command "trevorspray --help"
    add-to-list "trevorspray,https://github.com/blacklanternsecurity/TREVORspray,TREVORspray is a modular password sprayer with threading SSH proxying loot modules / and more"
}

function install_gitfive() {
    # CODE-CHECK-WHITELIST=add-aliases,add-history
    # GitFive only works with Python 3.10+.
    colorecho "Installing GitFive"
    pipx install --system-site-packages git+https://github.com/mxrch/GitFive
    add-test-command "gitfive --help"
    add-to-list "GitFive,https://github.com/mxrch/GitFive,GitFive is an OSINT tool to investigate GitHub profiles."
}

function install_geopincer() {
    colorecho "Installing GeoPincer"
    git -C /opt/tools clone --depth 1 https://github.com/tloja/GeoPincer.git
    cd /opt/tools/GeoPincer || exit
    sed -i "s#regions.txt#/opt/tools/GeoPincer/regions.txt##" GeoPincer.py
    python3 -m venv --system-site-packages ./venv
    source ./venv/bin/activate
    pip3 install -r requirements.txt
    deactivate
    add-aliases geopincer
    add-history geopincer
    add-test-command "geopincer.py --help"
    add-to-list "GeoPincer,https://github.com/tloja/GeoPincer,GeoPincer is a script that leverages OpenStreetMap's Overpass API in order to search for locations."
}

function install_yalis() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing Yalis"
    git -C /opt/tools clone --depth 1 https://github.com/EatonChips/yalis
    cd /opt/tools/yalis || exit
    go build .
    mv ./yalis /opt/tools/bin/
    add-history yalis
    add-test-command 'yalis --help|& grep "Usage of yalis"'
    add-to-list "Yalis,https://github.com/EatonChips/yalis,Yet Another LinkedIn Scraper"
}

function install_murmurhash() {
    colorecho "Installing MurMurHash"
    git -C /opt/tools clone --depth 1 https://github.com/QU35T-code/MurMurHash
    cd /opt/tools/MurMurHash || exit
    python3 -m venv --system-site-packages ./venv
    source ./venv/bin/activate
    pip3 install -r requirements.txt
    deactivate
    add-aliases MurMurHash
    add-history MurMurHash
    add-test-command "MurMurHash.py"
    add-to-list "MurMurHash,https://github.com/QU35T-code/MurMurHash,This little tool is to calculate a MurmurHash value of a favicon to hunt phishing websites on the Shodan platform."
}

function install_blackbird() {
    colorecho "Installing Blackbird"
    git -C /opt/tools clone --depth 1 https://github.com/p1ngul1n0/blackbird
    cd /opt/tools/blackbird || exit
    sed -i "s#data.json#/opt/tools/blackbird/data.json#" blackbird.py
    sed -i "s#useragents.txt#/opt/tools/blackbird/useragents.txt#" blackbird.py
    python3 -m venv --system-site-packages ./venv
    source ./venv/bin/activate
    pip3 install -r requirements.txt
    deactivate
    add-aliases blackbird
    add-history blackbird
    add-test-command "blackbird.py --help"
    add-to-list "Blackbird,https://github.com/p1ngul1n0/blackbird,An OSINT tool to search fast for accounts by username across 581 sites."
}

function install_sherlock() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing Sherlock"
    pipx install sherlock-project
    add-history sherlock
    add-test-command "sherlock --help"
    add-to-list "Sherlock,https://github.com/sherlock-project/sherlock,Hunt down social media accounts by username across social networks."
}

function install_censys() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing Censys"
    pipx install --system-site-packages censys
    add-history censys
    add-test-command "censys --help"
    add-to-list "Censys,https://github.com/censys/censys-python,An easy-to-use and lightweight API wrapper for Censys APIs"
}

function install_gomapenum() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing GoMapEnum"
    git -C /opt/tools clone --depth 1 https://github.com/nodauf/GoMapEnum
    cd /opt/tools/GoMapEnum/src || exit
    go build .
    mv ./src /opt/tools/bin/gomapenum
    add-history gomapenum
    add-test-command "gomapenum --help"
    add-to-list "GoMapEnum,https://github.com/nodauf/GoMapEnum,Nothing new but existing techniques are brought together in one tool."
}

function install_pymeta() {
  # CODE-CHECK-WHITELIST=add-aliases
  colorecho "Installing pymeta"
  fapt exiftool
  git -C /opt/tools clone --depth 1 https://github.com/m8sec/pymeta
  cd /opt/tools/pymeta || exit
  python3 -m venv --system-site-packages ./venv
  source ./venv/bin/activate
  pip3 install .
  pip3 install -r requirements.txt
  deactivate
  ln -v -s /opt/tools/pymeta/venv/bin/pymeta /opt/tools/bin/
  add-history pymeta
  add-test-command "pymeta -h"
  add-to-list "pymeta,https://github.com/m8sec/pymeta,Google and Bing scraping osint tool"
}

# Package dedicated to osint, recon and passive tools
function package_osint() {
    set_env
    local start_time
    local end_time
    start_time=$(date +%s)
    install_osint_apt_tools
    install_youtubedl               # Command-line program to download videos from YouTube.com and other video sites
    install_sublist3r               # Fast subdomains enumeration tool
    install_assetfinder             # Find domains and subdomains potentially related to a given domain
    install_subfinder               # Subfinder is a subdomain discovery tool that discovers valid subdomains for websites
    install_findomain               # Findomain Monitoring Service use OWASP Amass, Sublist3r, Assetfinder and Subfinder
    install_holehe                  # Check if the mail is used on different sites
    install_simplyemail             # Gather emails
    install_theharvester            # Gather emails, subdomains, hosts, employee names, open ports and banners
    install_h8mail                  # Email OSINT & Password breach hunting tool
    # install_infoga                  # Gathering email accounts informations TODO : 404, it seems the repo has been removed
    install_pwnedornot              # OSINT Tool for Finding Passwords of Compromised Email Addresses
    # install_ghunt                 # Investigate Google Accounts with emails FIXME: Need python3.10 -> https://github.com/mxrch/GHunt/issues/398
    install_phoneinfoga             # Advanced information gathering & OSINT framework for phone numbers
    install_maigret                 # Search pseudos and information about users on many platforms
    install_linkedin2username       # Generate username lists for companies on LinkedIn
    install_toutatis                # Toutatis is a tool that allows you to extract information from instagrams accounts
    install_waybackurls             # Website history
    install_carbon14                # OSINT tool for estimating when a web page was written
    install_photon                  # Incredibly fast crawler designed for OSINT.
    install_ipinfo                  # Get information about an IP address using command line with ipinfo.io
    install_constellation           # A graph-focused data visualisation and interactive analysis application.
    install_maltego                 # Maltego is a software used for open-source intelligence and forensics
    install_spiderfoot              # SpiderFoot automates OSINT collection
    install_finalrecon              # A fast and simple python script for web reconnaissance
    install_osrframework            # OSRFramework, the Open Sources Research Framework
    # install_torbrowser            # Tor browser FIXME: Github project ?
    # configure_tor
    install_pwndb					# No need to say more, no ? Be responsible with this tool please !
    install_githubemail             # Retrieve a GitHub user's email even if it's not public
    install_recondog                # Informations gathering tool
    install_gron                    # JSON parser
    install_ignorant                # holehe but for phone numbers
    install_trevorspray             # modular password sprayer with threading, SSH proxying, loot modules, and more!
    # install_gitfive               # TODO : only works with python3.10+
    install_geopincer               # GeoPincer is a script that leverages OpenStreetMap's Overpass API in order to search for locations
    install_yalis                   # Yet Another LinkedIn Scraper
    install_murmurhash              # Little tool is to calculate a MurmurHash value
    #install_blackbird              Skipping install because of https://github.com/p1ngul1n0/blackbird/issues/119 # OSINT tool to search fast for accounts by username
    install_sherlock                # Hunt down social media accounts by username across social networks
    install_censys                  # An easy-to-use and lightweight API wrapper for Censys APIs
    install_gomapenum               # Nothing new but existing techniques are brought together in one tool.
    install_pymeta
    post_install
    end_time=$(date +%s)
    local elapsed_time=$((end_time - start_time))
    colorecho "Package osint completed in $elapsed_time seconds."
}
