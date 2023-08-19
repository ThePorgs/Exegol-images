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
    python3 -m pipx install youtube-dl
    add-history youtube-dl
    add-test-command "youtube-dl --version"
    add-to-list "youtubedl,https://github.com/ytdl-org/youtube-dl,Download videos from YouTube and other sites."
}

function install_sublist3r() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing Sublist3r"
    python3 -m pipx install git+https://github.com/aboul3la/Sublist3r
    add-history sublist3r
    add-test-command "sublist3r --help"
    add-to-list "sublist3r,https://github.com/aboul3la/Sublist3r,a Python tool designed to enumerate subdomains of websites."
}

function install_assetfinder() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing assetfinder"
    go install -v github.com/tomnomnom/assetfinder@latest
    add-history assetfinder
    add-test-command "assetfinder thehacker.recipes"
    add-to-list "assetfinder,https://github.com/tomnomnom/assetfinder,Tool to find subdomains and IP addresses associated with a domain."
}

function install_subfinder() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing subfinder"
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
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
    python3 -m pipx install holehe
    add-history holehe
    add-test-command "holehe --help"
    add-to-list "holehe,https://github.com/megadose/holehe,Exploit a vulnerable Samba service to gain root access."
}

function install_simplyemail() {
    colorecho "Installing SimplyEmail"
    git -C /opt/tools/ clone --branch master --depth 1 https://github.com/killswitch-GUI/SimplyEmail.git
    cd /opt/tools/SimplyEmail/
    fapt antiword odt2txt python-dev libxml2-dev libxslt1-dev
    virtualenv -p /usr/bin/python2 ./venv
    ./venv/bin/python2 -m pip install -r ./setup/requirments.txt
    add-aliases simplyemail
    add-history simplyemail
    add-test-command "SimplyEmail -l"
    add-to-list "simplyemail,https://github.com/SimplySecurity/SimplyEmail,a scriptable command line tool for sending emails"
}

function install_theharvester() {
    colorecho "Installing theHarvester"
    git -C /opt/tools/ clone --depth 1 https://github.com/laramies/theHarvester
    cd /opt/tools/theHarvester
    python3 -m venv ./venv
    ./venv/bin/python3 -m pip install -r requirements.txt
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
    python3 -m pipx install h8mail
    add-history h8mail
    add-test-command "h8mail --help"
    add-to-list "h8mail,https://github.com/khast3x/h8mail,Email OSINT and breach hunting."
}

function install_infoga() {
    colorecho "Installing infoga"
    git -C /opt/tools/ clone --depth 1 https://github.com/m4ll0k/Infoga
    find /opt/tools/Infoga/ -type f -print0 | xargs -0 dos2unix
    cd /opt/tools/Infoga
    python3 -m venv ./venv
    ./venv/bin/python3 -m pip install .
    add-aliases infoga
    add-history infoga
    add-test-command "infoga.py --help"
    add-to-list "infoga,https://github.com/m4ll0k/Infoga,Information gathering tool for hacking."
}

function install_buster() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing buster"
    git -C /opt/tools clone --depth 1 https://github.com/sham00n/buster
    cd /opt/tools/buster
    python3 -m venv ./venv
    source ./venv/bin/activate
    pip install cython requests beautifulsoup4 PyYaml lxml grequests gevent twint
    python3 setup.py install
    deactivate
    ln -s /opt/tools/buster/venv/bin/buster /opt/tools/bin
    add-history buster
    add-test-command "buster --help"
    add-to-list "buster,https://github.com/sham00n/Buster,Advanced OSINT tool"
}

function install_pwnedornot() {
    colorecho "Installing pwnedornot"
    git -C /opt/tools/ clone --depth 1 https://github.com/thewhiteh4t/pwnedOrNot
    cd /opt/tools/pwnedOrNot
    python3 -m venv ./venv
    ./venv/bin/python3 -m pip install requests html2text
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
    python3 -m pipx install git+https://github.com/soxoj/maigret.git
    add-history maigret
    add-test-command "maigret --help"
    add-to-list "maigret,https://github.com/soxoj/maigret,Collects information about a target email (or domain) from Google and Bing search results"
}

function install_linkedin2username() {
    colorecho "Installing linkedin2username"
    git -C /opt/tools/ clone --depth 1 https://github.com/initstring/linkedin2username
    cd /opt/tools/linkedin2username
    python3 -m venv ./venv
    ./venv/bin/python3 -m pip install -r requirements.txt
    add-aliases linkedin2username
    add-history linkedin2username
    add-test-command "linkedin2username.py --help"
    add-to-list "linkedin2username,https://github.com/initstring/linkedin2username,Generate a list of LinkedIn usernames from a company name."
}

function install_toutatis() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing toutatis"
    python3 -m pipx install git+https://github.com/megadose/toutatis
    add-history toutatis
    add-test-command "toutatis --help"
    add-to-list "toutatis,https://github.com/megadose/Toutatis,Toutatis is a tool that allows you to extract information from instagrams accounts such as e-mails / phone numbers and more."
}

function install_waybackurls() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing waybackurls"
    go install -v github.com/tomnomnom/waybackurls@latest
    add-history waybackurls
    add-test-command "waybackurls -h"
    add-to-list "waybackurls,https://github.com/tomnomnom/waybackurls,Fetch all the URLs that the Wayback Machine knows about for a domain."
}

function install_carbon14() {
    colorecho "Installing Carbon14"
    git -C /opt/tools/ clone --depth 1 https://github.com/Lazza/Carbon14
    cd /opt/tools/Carbon14
    python3 -m venv ./venv
    ./venv/bin/python3 -m pip install -r requirements.txt
    add-aliases carbon14
    add-history carbon14
    add-test-command "carbon14.py --help"
    add-to-list "carbon14,https://github.com/Lazza/carbon14,OSINT tool for estimating when a web page was written."
}

function install_photon() {
    colorecho "Installing photon"
    git -C /opt/tools/ clone --depth 1 https://github.com/s0md3v/photon
    cd /opt/tools/photon
    python3 -m venv ./venv
    ./venv/bin/python3 -m pip install -r requirements.txt
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
    cd /opt/tools/spiderfoot
    python3 -m venv ./venv
    ./venv/bin/python3 -m pip install -r requirements.txt
    add-aliases spiderfoot
    add-history spiderfoot
    add-test-command "spiderfoot --help"
    add-test-command "spiderfoot-cli --help"
    add-to-list "spiderfoot,https://github.com/smicallef/spiderfoot,A reconnaissance tool that automatically queries over 100 public data sources"
}

function install_finalrecon() {
    colorecho "Installing FinalRecon"
    git -C /opt/tools/ clone --depth 1 https://github.com/thewhiteh4t/FinalRecon
    cd /opt/tools/FinalRecon
    python3 -m venv ./venv
    ./venv/bin/python3 -m pip install -r requirements.txt
    add-aliases finalrecon
    add-history finalrecon
    add-test-command "finalrecon.py --help"
    add-to-list "finalrecon,https://github.com/thewhiteh4t/FinalRecon,A web reconnaissance tool that gathers information about web pages"
}

function install_osrframework() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing osrframework"
    python3 -m pipx install osrframework
    python3 -m pipx inject osrframework 'urllib3<2'
    python3 -m pipx inject osrframework 'pip==21.2'
    add-history osrframework
    add-test-command "osrframework-cli --help"
    add-to-list "osrframework,https://github.com/i3visio/osrframework,Include references to a bunch of different applications related to username checking / DNS lookups / information leaks research / deep web search / regular expressions extraction and many others."
}

function install_pwndb() {
    colorecho "Installing pwndb"
    git -C /opt/tools/ clone --depth 1 https://github.com/davidtavarez/pwndb.git
    cd /opt/tools/pwndb
    python3 -m venv ./venv
    ./venv/bin/python3 -m pip install -r requirements.txt
    add-aliases pwndb
    add-history pwndb
    add-test-command "pwndb --help"
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
    cd /opt/tools/ReconDog/
    python3 -m venv ./venv
    ./venv/bin/python3 -m pip install -r requirements.txt
    add-aliases recondog
    add-history recondog
    add-test-command "recondog --help"
    add-to-list "recondog,https://github.com/s0md3v/ReconDog,a reconnaissance tool for performing information gathering on a target."
}

function install_gron() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing gron"
    go install -v github.com/tomnomnom/gron@latest
    add-history gron
    add-test-command "gron --help"
    add-to-list "gron,https://github.com/tomnomnom/gron,Make JSON greppable!"
}

function install_ignorant() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing ignorant"
    python3 -m pipx install git+https://github.com/megadose/ignorant
    add-history ignorant
    add-test-command "ignorant --help"
    add-to-list "ignorant,https://github.com/megadose/ignorant,holehe but for phone numbers."
}

function install_trevorspray() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing trevorspray"
    git -C /opt/tools/ clone --depth 1 https://github.com/blacklanternsecurity/TREVORspray
    cd /opt/tools/TREVORspray
    # https://github.com/blacklanternsecurity/TREVORspray/pull/27
    sed -i "s/1.0.5/1.0.4/" pyproject.toml
    python3 -m pipx install .
    add-history trevorspray
    add-test-command "trevorspray --help"
    add-to-list "trevorspray,https://github.com/blacklanternsecurity/TREVORspray,TREVORspray is a modular password sprayer with threading SSH proxying loot modules / and more"
}

# Package dedicated to osint, recon and passive tools
function package_osint() {
    set_go_env
    set_ruby_env
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
    install_infoga                  # Gathering email accounts informations
    install_buster                  # An advanced tool for email reconnaissance
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
    install_pwndb					# No need to say more, no ? Be responsible with this tool please !
    install_githubemail             # Retrieve a GitHub user's email even if it's not public
    install_recondog                # Informations gathering tool
    install_gron                    # JSON parser
    install_ignorant                # holehe but for phone numbers
    install_trevorspray             # modular password sprayer with threading, SSH proxying, loot modules, and more!
}

function package_osint_configure() {
    configure_tor
}
