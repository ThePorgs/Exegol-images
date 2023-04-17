#!/bin/bash
# Author: The Exegol Project

RED='\033[1;31m'
BLUE='\033[1;34m'
GREEN='\033[1;32m'
NOCOLOR='\033[0m'

### Support functions

function colorecho () {
  echo -e "${BLUE}[EXEGOL] $*${NOCOLOR}"
}

function criticalecho () {
  echo -e "${RED}[EXEGOL ERROR] $*${NOCOLOR}" 2>&1
  exit 1
}

function criticalecho-noexit () {
  echo -e "${RED}[EXEGOL ERROR] $*${NOCOLOR}" 2>&1
}

function add-aliases() {
  colorecho "Adding aliases for: $*"
  # Removing add empty lines and the last trailing newline if any, and adding a trailing newline.
  grep -vE "^\s*$" "/root/sources/zsh/aliases.d/$*" >> /opt/.exegol_aliases
}

function add-history() {
  colorecho "Adding history commands for: $*"
  # Removing add empty lines and the last trailing newline if any, and adding a trailing newline.
  grep -vE "^\s*$" "/root/sources/zsh/history.d/$*" >> ~/.zsh_history
}

function add-test-command() {
  colorecho "Adding build pipeline test command: $*"
  echo "$*" >> "/.exegol/build_pipeline_tests/all_commands.txt"
}

function add-to-list() {
  echo $1 >> "/.exegol/installed_tools"
}

function fapt() {
  colorecho "Installing apt package(s): $*"
  apt-get install -y --no-install-recommends "$@" || exit
}

function fapt-noexit() {
  # This function tries the same thing as fapt but doesn't exit in case something's wrong.
  # Example: a package exists in amd64 but not arm64. I didn't find a way of knowing that beforehand.
  colorecho "Installing (no-exit) apt package(s): $*"
  apt-get install -y --no-install-recommends "$*" || echo -e "${RED}[EXEGOL ERROR] Package(s) $* probably doesn't exist for architecture $(uname -m), or no installation candidate was found, or some other error...${NOCOLOR}" 2>&1
}

### Setup, and special tool install functions

function post_install_clean() {
  # Function used to clean up post-install files
  colorecho "Cleaning..."
  updatedb
  rm -rfv /tmp/*
  echo "# -=-=-=-=-=-=-=- YOUR COMMANDS BELOW -=-=-=-=-=-=-=- #" >> ~/.zsh_history
}

function update() {
  colorecho "Updating, upgrading, cleaning"
  echo 'debconf debconf/frontend select Noninteractive' | debconf-set-selections
  apt-get -y update && apt-get -y install apt-utils dialog && apt-get -y upgrade && apt-get -y autoremove && apt-get clean
}

function filesystem() {
  colorecho "Preparing filesystem"
  mkdir -p /opt/tools/
  mkdir -p /opt/tools/bin/
  mkdir -p /data/
  mkdir -p /var/log/exegol
  mkdir -p /.exegol/build_pipeline_tests/
  touch /.exegol/build_pipeline_tests/all_commands.txt
}

function set_go_env(){
  colorecho "Setting environment variables for installation"
  export GO111MODULE=on
  export PATH=$PATH:/usr/local/go/bin:/root/.local/bin
}

function deploy_exegol() {
  colorecho "Installing Exegol things"
  # Moving exegol files to /
  mv /root/sources/exegol /.exegol
  # Moving supported custom configurations in /opt
  mv /.exegol/skel/supported_setups.md /opt/
  mkdir /var/log/exegol
  # Setup perms
  chown -R root:root /.exegol
  chmod 500 /.exegol/*.sh
  find /.exegol/skel/ -type f -exec chmod 660 {} \;
}

function install_openvpn() {
  fapt openvpn                    # Instal OpenVPN
  fapt openresolv                 # Dependency for DNS resolv.conf update with OpenVPN connection (using script)

  # Fixing openresolv to update /etc/resolv.conf without resolvectl daemon (with a fallback if no DNS server are supplied)
  line=$(($(grep -n 'up)' /etc/openvpn/update-resolv-conf | cut -d ':' -f1) +1))
  sed -i ${line}'i cp /etc/resolv.conf /etc/resolv.conf.backup' /etc/openvpn/update-resolv-conf

  line=$(($(grep -n 'resolvconf -a' /etc/openvpn/update-resolv-conf | cut -d ':' -f1) +1))
  sed -i ${line}'i [ "$(resolvconf -l "tun*" | grep -vE "^(\s*|#.*)$")" ] && /sbin/resolvconf -u || cp /etc/resolv.conf.backup /etc/resolv.conf' /etc/openvpn/update-resolv-conf
  line=$(($line + 1))
  sed -i ${line}'i rm /etc/resolv.conf.backup' /etc/openvpn/update-resolv-conf
  add-test-command "openvpn --version"
}

function install_exegol-history() {
  colorecho "Installing Exegol-history"
#  git -C /opt/tools/ clone https://github.com/ThePorgs/Exegol-history
# todo : below is something basic. A nice tool being created for faster and smoother worflow
  mkdir /opt/tools/Exegol-history
  echo "#export INTERFACE='eth0'" >> /opt/tools/Exegol-history/profile.sh
  echo "#export DOMAIN='DOMAIN.LOCAL'" >> /opt/tools/Exegol-history/profile.sh
  echo "#export DOMAIN_SID='S-1-5-11-39129514-1145628974-103568174'" >> /opt/tools/Exegol-history/profile.sh
  echo "#export USER='someuser'" >> /opt/tools/Exegol-history/profile.sh
  echo "#export PASSWORD='somepassword'" >> /opt/tools/Exegol-history/profile.sh
  echo "#export NT_HASH='c1c635aa12ae60b7fe39e28456a7bac6'" >> /opt/tools/Exegol-history/profile.sh
  echo "#export DC_IP='192.168.56.101'" >> /opt/tools/Exegol-history/profile.sh
  echo "#export DC_HOST='DC01.DOMAIN.LOCAL'" >> /opt/tools/Exegol-history/profile.sh
  echo "#export TARGET='192.168.56.69'" >> /opt/tools/Exegol-history/profile.sh
  echo "#export ATTACKER_IP='192.168.56.1'" >> /opt/tools/Exegol-history/profile.sh
}

function install_logrotate() {
  colorecho "Installing logrotate"
  fapt logrotate
  mv /root/sources/logrotate/* /etc/logrotate.d/
  chmod 644 /etc/logrotate.d/*
}

### Tool installation functions

function install_python-pip() {
  colorecho "Installing python-pip (for Python2.7)"
  curl --insecure https://bootstrap.pypa.io/pip/2.7/get-pip.py -o get-pip.py
  python get-pip.py
  rm get-pip.py
  add-test-command "pip --version"
}

function install_ohmyzsh() {
  colorecho "Installing oh-my-zsh, config, history, aliases"
  sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)"
  cp -v /root/sources/zsh/history ~/.zsh_history
  cp -v /root/sources/zsh/aliases /opt/.exegol_aliases
  cp -v /root/sources/zsh/zshrc ~/.zshrc
  git -C ~/.oh-my-zsh/custom/plugins/ clone https://github.com/zsh-users/zsh-autosuggestions
  git -C ~/.oh-my-zsh/custom/plugins/ clone https://github.com/zsh-users/zsh-syntax-highlighting
  git -C ~/.oh-my-zsh/custom/plugins/ clone https://github.com/zsh-users/zsh-completions
  git -C ~/.oh-my-zsh/custom/plugins/ clone https://github.com/agkozak/zsh-z
  git -C ~/.oh-my-zsh/custom/plugins/ clone https://github.com/lukechilds/zsh-nvm
  zsh -c "source ~/.oh-my-zsh/custom/plugins/zsh-nvm/zsh-nvm.plugin.zsh" # this is needed to start an instance of zsh to have the plugin set up
}

function install_locales() {
  colorecho "Configuring locales"
  apt-get -y install locales
  sed -i -e 's/# en_US.UTF-8 UTF-8/en_US.UTF-8 UTF-8/' /etc/locale.gen
  locale-gen
}

function install_tmux() {
  colorecho "Installing tmux"
  fapt tmux
  cp -v /root/sources/tmux/tmux.conf ~/.tmux.conf
  touch ~/.hushlogin
  add-to-list "tmux,https://github.com/tmux/tmux,a terminal multiplexer for Unix-like operating systems."
}

function install_gowitness() {
  colorecho "Installing gowitness"
  go install -v github.com/sensepost/gowitness@latest
  add-history gowitness
  add-test-command "gowitness --help"
  add-test-command "gowitness single https://exegol.readthedocs.io" # check the chromium dependency
  add-to-list "gowitness,https://github.com/sensepost/gowitness,A website screenshot utility written in Golang."
}

function install_goshs(){
  colorecho "Installing goshs"
  go install -v github.com/patrickhener/goshs@latest
  add-history goshs
  add-test-command "goshs -v"
  add-to-list "goshs,https://github.com/patrickhener/goshs,Goshs is a replacement for Python's SimpleHTTPServer. It allows uploading and downloading via HTTP/S with either self-signed certificate or user provided certificate and you can use HTTP basic auth."
}

function install_sslyze(){
  colorecho "Installing sslyze"
  if [[ $(uname -m) = 'x86_64' ]]
  then
    python3 -m pipx install sslyze
  else
    # https://github.com/nabla-c0d3/nassl/issues/86
    # FIXME we need some tinkering here to make it work on aarch64 (and move back add-history / add-test-command)
    criticalecho-noexit "This installation function (sslyze) doesn't support architecture $(uname -m)" && return
  fi
  add-history sslyze
  add-test-command "sslyze --help"
  add-to-list "sslyze,https://github.com/nabla-c0d3/sslyze,a Python tool for analyzing SSL/TLS configurations of servers."
}

function install_weevely() {
  colorecho "Installing weevely"
  fapt weevely
  add-test-command "weevely --help"
  add-to-list "weevely,https://github.com/epinna/weevely3,a webshell designed for post-exploitation purposes that can be extended over the network at runtime."
}

function install_responder() {
  colorecho "Installing Responder"
  git -C /opt/tools/ clone https://github.com/lgandx/Responder
  sed -i 's/ Random/ 1122334455667788/g' /opt/tools/Responder/Responder.conf
  sed -i 's/files\/AccessDenied.html/\/opt\/tools\/Responder\/files\/AccessDenied.html/g' /opt/tools/Responder/Responder.conf
  sed -i 's/files\/BindShell.exe/\/opt\/tools\/Responder\/files\/BindShell.exe/g' /opt/tools/Responder/Responder.conf
  sed -i 's/certs\/responder.crt/\/opt\/tools\/Responder\/certs\/responder.crt/g' /opt/tools/Responder/Responder.conf
  sed -i 's/certs\/responder.key/\/opt\/tools\/Responder\/certs\/responder.key/g' /opt/tools/Responder/Responder.conf
  fapt gcc-mingw-w64-x86-64 python3-netifaces
  x86_64-w64-mingw32-gcc /opt/tools/Responder/tools/MultiRelay/bin/Runas.c -o /opt/tools/Responder/tools/MultiRelay/bin/Runas.exe -municode -lwtsapi32 -luserenv
  x86_64-w64-mingw32-gcc /opt/tools/Responder/tools/MultiRelay/bin/Syssvc.c -o /opt/tools/Responder/tools/MultiRelay/bin/Syssvc.exe -municode
  cd /opt/tools/Responder || exit
  /opt/tools/Responder/certs/gen-self-signed-cert.sh
  add-aliases responder
  add-history responder
  add-test-command "responder --version"
  add-to-list "responder,https://github.com/lgandx/Responder,a LLMNR, NBT-NS and MDNS poisoner."
}

function install_sublist3r() {
  colorecho "Installing Sublist3r"
  python3 -m pipx install git+https://github.com/aboul3la/Sublist3r
  add-history sublist3r
  add-test-command "sublist3r --help"
  add-to-list "sublist3r,https://github.com/aboul3la/Sublist3r,a Python tool designed to enumerate subdomains of websites."
}

function install_php_filter_chain_generator() {
  colorecho "Installing PHP_Filter_Chain_Generator"
  git -C /opt/tools/ clone https://github.com/synacktiv/php_filter_chain_generator.git
  add-aliases php_filter_chain_generator
  add-test-command "php_filter_chain_generator --help"
  add-to-list "PHP filter chain generator,https://github.com/synacktiv/php_filter_chain_generator,TODO"
}

function install_kraken() {
  colorecho "Installing Kraken"
  git -C /opt/tools clone --recurse-submodules https://github.com/kraken-ng/Kraken.git
  cd /opt/tools/Kraken || exit
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

function install_recondog() {
  colorecho "Installing ReconDog"
  git -C /opt/tools/ clone https://github.com/s0md3v/ReconDog
  python3 -m pip install -r /opt/tools/ReconDog/requirements.txt
  add-aliases recondog
  add-test-command "recondog --help"
  add-to-list "recondog,https://github.com/s0md3v/ReconDog,a reconnaissance tool for performing information gathering on a target."
}

function install_githubemail() {
  colorecho "Installing github-email"
  npm install --global github-email
  add-history github-email
  add-test-command "github-email whatever"
  add-to-list "githubemail,https://github.com/paulirish/github-email,a command-line tool to retrieve a user's email from Github."
}

function install_photon() {
  colorecho "Installing photon"
  git -C /opt/tools/ clone https://github.com/s0md3v/photon
  python3 -m pip install -r /opt/tools/photon/requirements.txt
  add-aliases photon
  add-test-command "photon.py --help"
  add-to-list "photon,https://github.com/s0md3v/Photon,a fast web crawler which extracts URLs, files, intel & endpoints from a target."
}

function install_osrframework() {
  colorecho "Installing OSRFramework"
#  python3 -m pipx install # https://github.com/i3visio/osrframework/issues/382
  add-to-list "osrframework,https://github.com/i3visio/osrframework,a modular exploitation framework designed for reconnaissance and penetration testing."
}

function install_cloudfail() {
  colorecho "Installing CloudFail"
  git -C /opt/tools/ clone https://github.com/m0rtem/CloudFail
  python3 -m pip install -r /opt/tools/CloudFail/requirements.txt
  add-aliases cloudfail
  add-history cloudfail
  add-test-command "cloudfail.py --help"
  add-to-list "cloudfail,https://github.com/m0rtem/CloudFail,a reconnaissance tool for identifying misconfigured CloudFront domains."
}

function install_oneforall() {
  colorecho "Installing OneForAll"
  git -C /opt/tools/ clone https://github.com/shmilylty/OneForAll.git
  python3 -m pip install -r /opt/tools/OneForAll/requirements.txt
  add-aliases oneforall
  add-test-command "(setsid oneforall --help) </dev/null |& cat"
  add-to-list "oneforall,https://github.com/shmilylty/OneForAll,a powerful subdomain collection tool."
}

function install_eyewitness() {
  colorecho "Installing EyeWitness"
  git -C /opt/tools/ clone https://github.com/FortyNorthSecurity/EyeWitness
  cd /opt/tools/EyeWitness/Python/setup || exit
  ./setup.sh
  add-aliases eyewitness
  add-test-command "eyewitness --help"
  add-to-list "eyewitness,https://github.com/FortyNorthSecurity/EyeWitness,a tool to take screenshots of websites, provide some server header info, and identify default credentials if possible."
}

function install_wafw00f() {
  colorecho "Installing wafw00f"
  python3 -m pipx install wafw00F
  add-test-command "wafw00f --help"
  add-to-list "wafw00f,https://github.com/EnableSecurity/wafw00f,a Python tool that helps to identify and fingerprint web application firewall (WAF) products."
}

function install_linkfinder() {
  colorecho "Installing LinkFinder"
  git -C /opt/tools/ clone https://github.com/GerbenJavado/LinkFinder.git
  cd /opt/tools/LinkFinder || exit
  python3 -m pip install -r requirements.txt
  python3 setup.py install
  add-aliases linkfinder
  add-test-command "linkfinder --help"
  add-to-list "linkfinder,https://github.com/GerbenJavado/LinkFinder,a Python script that finds endpoints and their parameters in JavaScript files."
}

function install_ssrfmap() {
  colorecho "Installing SSRFmap"
  git -C /opt/tools/ clone https://github.com/swisskyrepo/SSRFmap
  cd /opt/tools/SSRFmap || exit
  python3 -m pip install -r requirements.txt
  add-aliases ssrfmap
  add-test-command "ssrfmap --help"
  add-to-list "ssrfmap,https://github.com/swisskyrepo/SSRFmap,a tool for testing SSRF vulnerabilities."
}

function install_nosqlmap() {
  colorecho "Installing NoSQLMap"
  git -C /opt/tools clone https://github.com/codingo/NoSQLMap.git
  cd /opt/tools/NoSQLMap || exit
  python setup.py install
  add-aliases nosqlmap
  add-test-command "nosqlmap --help"
  add-to-list "nosqlmap,https://github.com/codingo/NoSQLMap,a Python tool for testing NoSQL databases for security vulnerabilities."
}

function install_odat() {
  colorecho "Installing odat"
  odat_latest="$(curl -L -s https://github.com/quentinhardy/odat/releases/latest | grep tar.gz | cut -d '"' -f 2 | head -1)"
  wget "https://github.com/$odat_latest" -O /tmp/odat_latest.tar.gz
  mkdir -p /opt/tools/odat
  tar xvf /tmp/odat_latest.tar.gz -C /opt/tools/odat --strip=2
  mv /opt/tools/odat/odat* /opt/tools/odat/odat
  echo -e '#!/bin/sh\n(cd /opt/tools/odat/ && ./odat $@)' > /usr/local/bin/odat
  chmod +x /usr/local/bin/odat
  add-to-list "odat,https://github.com/quentinhardy/odat,a tool to perform Oracle Database enumeration and exploitation."
}

function install_fuxploider() {
  colorecho "Installing fuxploider"
  git -C /opt/tools/ clone https://github.com/almandin/fuxploider.git
  cd /opt/tools/fuxploider || exit
  python3 -m pip install -r requirements.txt
  add-aliases fuxploider
  add-test-command "fuxploider --help"
  add-to-list "fuxploider,https://github.com/almandin/fuxploider,a Python tool for finding and exploiting file upload forms/directories."
}

function install_corscanner() {
  colorecho "Installing CORScanner"
  git -C /opt/tools/ clone https://github.com/chenjj/CORScanner.git
  cd /opt/tools/CORScanner || exit
  python3 -m pip install -r requirements.txt
  add-aliases corscanner
  add-test-command "corscanner --help"
  add-to-list "corscanner,https://github.com/chenjj/CORScanner,a Python script for finding CORS misconfigurations."
}

function install_xsstrike() {
  colorecho "Installing XSStrike"
  git -C /opt/tools/ clone https://github.com/s0md3v/XSStrike.git
  python3 -m pipx install fuzzywuzzy
  add-aliases xsstrike
  add-test-command "XSStrike --help"
  add-to-list "xsstrike,https://github.com/s0md3v/XSStrike,a Python tool for detecting and exploiting XSS vulnerabilities."
}

function install_xspear() {
  colorecho "Installing XSpear"
  gem install XSpear
  add-test-command "XSpear --help"
  add-to-list "xspear,https://github.com/hahwul/XSpear,a powerful XSS scanning and exploitation tool."
}

function install_cupp() {
  colorecho "Installing cupp"
  fapt cupp
  add-test-command "cupp --help"
  add-to-list "cupp,https://github.com/Mebus/cupp,TODO"
}

function install_pass_station() {
  colorecho "Installing Pass Station"
  gem install pass-station
  add-history pass-station
  add-test-command "pass-station --help"
  add-to-list "pass,https://github.com/hashcat/hashcat,TODO"
}

function install_username-anarchy() {
  colorecho "Installing Username-Anarchy"
  git -C /opt/tools/ clone https://github.com/urbanadventurer/username-anarchy
  add-aliases username-anarchy
  add-test-command "username-anarchy --help"
  add-to-list "username-anarchy,https://github.com/urbanadventurer/username-anarchy,TODO"
}

function install_evilwinrm() {
  colorecho "Installing evil-winrm"
  gem install evil-winrm
  add-history evil-winrm
  add-test-command "evil-winrm --help"
  add-to-list "evilwinrm,https://github.com/Hackplayers/evil-winrm,Tool to connect to a remote Windows system with WinRM."
}

function install_bolt() {
  colorecho "Installing Bolt"
  git -C /opt/tools/ clone https://github.com/s0md3v/Bolt.git
  python3 -m pip install -r /opt/tools/Bolt/requirements.txt
  add-aliases bolt
  add-test-command "bolt --help"
  add-to-list "bolt,https://github.com/s0md3v/bolt,TODO"
}

function install_crackmapexec() {
  colorecho "Installing CrackMapExec"
  # Source bc cme needs cargo PATH (rustc) -> aardwolf dep
  # TODO: Optimize so that the PATH is always up to date
  source /root/.zshrc
  git -C /opt/tools/ clone https://github.com/Porchetta-Industries/CrackMapExec.git
  python3 -m pipx install /opt/tools/CrackMapExec/
  mkdir -p ~/.cme
  [ -f ~/.cme/cme.conf ] && mv ~/.cme/cme.conf ~/.cme/cme.conf.bak
  cp -v /root/sources/crackmapexec/cme.conf ~/.cme/cme.conf
  # below is for having the ability to check the source code when working with modules and so on
  # git -C /opt/tools/ clone https://github.com/byt3bl33d3r/CrackMapExec
  cp -v /root/sources/grc/conf.cme /usr/share/grc/conf.cme
  add-aliases crackmapexec
  add-history crackmapexec
  add-test-command "crackmapexec --help"
  add-to-list "crackmapexec,https://github.com/byt3bl33d3r/CrackMapExec,Network scanner."
}

function install_lsassy() {
  colorecho "Installing lsassy"
  python3 -m pipx install lsassy
  add-history lsassy
  add-test-command "lsassy --version"
  add-to-list "lsassy,https://github.com/Hackndo/lsassy,Windows secrets and passwords extraction tool."
}

function install_sprayhound() {
  colorecho "Installing sprayhound"
  apt-get -y install libsasl2-dev libldap2-dev
  python3 -m pipx install git+https://github.com/Hackndo/sprayhound
  add-history sprayhound
  add-test-command "sprayhound --help"
  add-to-list "sprayhound,https://github.com/Hackndo/Sprayhound,Active Directory password audit tool."
}

function install_impacket() {
  colorecho "Installing Impacket scripts"
  apt-get -y install libffi-dev
  git -C /opt/tools/ clone https://github.com/ThePorgs/impacket

  # See https://github.com/ThePorgs/impacket/blob/master/ChangeLog.md

  python3 -m pipx install /opt/tools/impacket/
  python3 -m pipx inject impacket chardet

  cp -v /root/sources/grc/conf.ntlmrelayx /usr/share/grc/conf.ntlmrelayx
  cp -v /root/sources/grc/conf.secretsdump /usr/share/grc/conf.secretsdump
  cp -v /root/sources/grc/conf.getgpppassword /usr/share/grc/conf.getgpppassword
  cp -v /root/sources/grc/conf.rbcd /usr/share/grc/conf.rbcd
  cp -v /root/sources/grc/conf.describeTicket /usr/share/grc/conf.describeTicket

  add-aliases impacket
  add-history impacket
  add-test-command "ntlmrelayx.py --help"
  add-test-command "secretsdump.py --help"
  add-test-command "Get-GPPPassword.py --help"
  add-test-command "getST.py --help && getST.py --help | grep 'u2u'"
  add-test-command "ticketer.py --help && ticketer.py --help | grep impersonate"
  add-test-command "ticketer.py --help && ticketer.py --help | grep hours"
  add-test-command "ticketer.py --help && ticketer.py --help | grep extra-pac"
  add-test-command "dacledit.py --help"
  add-test-command "describeTicket.py --help"
  add-to-list "impacket,https://github.com/ThePorgs/impacket,Set of tools for working with network protocols (ThePorgs version)."
}

function install_bloodhound-py() {
  colorecho "Installing and Python ingestor for BloodHound"
  git -C /opt/tools/ clone https://github.com/fox-it/BloodHound.py
  add-aliases bloodhound-py
  add-history bloodhound-py
  add-test-command "bloodhound.py --help"
  add-to-list "bloodhound-py,https://github.com/fox-it/BloodHound.py,Trust relationship analysis tool for Active Directory environments."
}

function install_neo4j() {
  colorecho "Installing neo4j"
  wget -O - https://debian.neo4j.com/neotechnology.gpg.key | apt-key add -
  # TODO: temporary fix => rollback to 4.4 stable until perf issue is fix on neo4j 5.x
  #echo 'deb https://debian.neo4j.com stable latest' | tee /etc/apt/sources.list.d/neo4j.list
  echo 'deb https://debian.neo4j.com stable 4.4' | tee /etc/apt/sources.list.d/neo4j.list
  apt-get update
  apt-get -y install --no-install-recommends gnupg libgtk2.0-bin libcanberra-gtk-module libx11-xcb1 libva-glx2 libgl1-mesa-glx libgl1-mesa-dri libgconf-2-4 libasound2 libxss1
  apt-get -y install neo4j
  # TODO: when temporary fix is not needed anymore --> neo4j-admin dbms set-initial-password exegol4thewin
  neo4j-admin set-initial-password exegol4thewin
  mkdir -p /usr/share/neo4j/logs/
  touch /usr/share/neo4j/logs/neo4j.log
  add-aliases neo4j
  add-history neo4j
  add-test-command "neo4j version"
  add-to-list "neo4j,https://github.com/neo4j/neo4j,Database."
}

function install_cyperoth() {
  colorecho "Installing cypheroth"
  git -C /opt/tools/ clone https://github.com/seajaysec/cypheroth/
  add-aliases cypheroth
  add-history cypheroth
  add-test-command "cypheroth --help; cypheroth -u neo4j -p exegol4thewin | grep 'Quitting Cypheroth'"
  add-to-list "cyperoth,https://github.com/seajaysec/cypheroth/,Automated, extensible toolset that runs cypher queries against Bloodhound's Neo4j backend and saves output to spreadsheets."
}

function install_mitm6_sources() {
  colorecho "Installing mitm6 from sources"
  git -C /opt/tools/ clone https://github.com/fox-it/mitm6
  cd /opt/tools/mitm6/ || exit
  python3 -m pip install -r requirements.txt
  python3 setup.py install
} #

function install_mitm6_pip() {
  colorecho "Installing mitm6 with pip"
  # commenting line below as I'm not sure what it's needed for
  # python3 -m pip install service_identity
  python3 -m pipx install mitm6
  # commenting lines below as they probably were temporary fixes to something.
  # if they need to be enabled again, architecture needs to be taken into account
  # cd /usr/lib/x86_64-linux-gnu/ || exit
  # ln -s -f libc.a liblibc.a
  add-history mitm6
  add-test-command "mitm6 --help"
  add-to-list "mitm6,https://github.com/fox-it/mitm6,Tool to conduct a man-in-the-middle attack against IPv6 protocols."
}

function install_aclpwn() {
  colorecho "Installing aclpwn with pip"
  python3 -m pipx install git+https://github.com/aas-n/aclpwn.py
  add-test-command "aclpwn -h"
  add-to-list "aclpwn,https://github.com/aas-n/aclpwn.py,Tool for testing the security of Active Directory access controls."
}

function install_routersploit() {
  colorecho "Installing RouterSploit"
  git -C /opt/tools/ clone https://www.github.com/threat9/routersploit
  cd /opt/tools/routersploit || exit
  python3 -m pip install -r requirements.txt
  add-aliases routersploit
  add-test-command "rsf --help"
  add-to-list "routersploit,https://github.com/threat9/routersploit,Security audit tool for routers."
}

function install_empire() {
  colorecho "Installing Empire"

  # Installing apt requirements
  DEBIAN_FRONTEND=noninteractive apt-get install -y wget sudo git python3-dev python3-pip xclip apt-transport-https \
  autoconf g++ git zlib1g-dev libxml2-dev libssl1.1 libssl-dev default-jdk curl git gcc nim

  # Installing xar (as per https://github.com/BC-SECURITY/Empire/blob/master/setup/install.sh)
  wget https://github.com/BC-SECURITY/xar/archive/xar-1.6.1-patch.tar.gz
  rm -rf xar-1.6.1
  rm -rf xar-1.6.1-patch/xar
  rm -rf xar-xar-1.6.1-patch
  tar -xvf xar-1.6.1-patch.tar.gz && mv xar-xar-1.6.1-patch/xar/ xar-1.6.1/
  if [[ $(uname -m) = 'x86_64' ]]
  then
    (cd xar-1.6.1 && ./autogen.sh --build=x86_64-unknown-linux-gnu)
    (cd xar-1.6.1 && ./configure --build=x86_64-unknown-linux-gnu)
  elif [[ $(uname -m) = 'aarch64' ]]
  then
    (cd xar-1.6.1 && ./autogen.sh --build=aarch64-unknown-linux-gnu)
    (cd xar-1.6.1 && ./configure --build=aarch64-unknown-linux-gnu)
  else
    criticalecho-noexit "This installation function (xar) doesn't support architecture $(uname -m)" && return
  fi
  (cd xar-1.6.1 && make)
  (cd xar-1.6.1 && make install)
  rm -rf xar-1.6.1
  rm -rf xar-1.6.1-patch/xar
  rm -rf xar-xar-1.6.1-patch

  # Installing bomutils (as per https://github.com/BC-SECURITY/Empire/blob/master/setup/install.sh)
  rm -rf bomutils
  git clone https://github.com/BC-SECURITY/bomutils.git
  (cd bomutils && make)
  (cd bomutils && make install)
  chmod 755 bomutils/build/bin/mkbom && sudo cp bomutils/build/bin/mkbom /usr/local/bin/.
  rm -rf bomutils

  # Installing powershell
  install_powershell

  # Installing dotnet sdk 6.0
  curl -L -o /tmp/dotnet-install.sh https://dot.net/v1/dotnet-install.sh
  chmod +x /tmp/dotnet-install.sh
  /tmp/dotnet-install.sh --channel 6.0
  rm /tmp/dotnet-install.sh

  git -C /opt/tools/ clone --recursive https://github.com/BC-SECURITY/Empire
  cd /opt/tools/Empire/ || exit

  python3 -m pip install poetry
  poetry install # FIXME doesn't work

  # Changing password
  sed -i 's/password123/exegol4thewin/' /opt/tools/Empire/empire/server/config.yaml
  add-aliases empire
  # TODO add-test-command
  add-to-list "empire,https://github.com/BC-SECURITY/Empire,Tool for Windows post-exploitation."
}

function install_starkiller() {
  colorecho "Installing Starkiller"
  apt-get -y install libfuse2
  version="$(curl -s https://github.com/BC-SECURITY/Starkiller/tags|grep /releases/tag/v -m1 |grep -Eo 'v[0-9]+\.[0-9]+\.[0-9]+'|cut -d 'v' -f2|head -n 1)"
  mkdir /opt/tools/starkiller
  wget -O /opt/tools/starkiller/starkiller.AppImage "https://github.com/BC-SECURITY/Starkiller/releases/download/v$version/starkiller-$version.AppImage"
  chmod +x /opt/tools/starkiller/starkiller.AppImage
  add-aliases starkiller
  add-to-list "starkiller,https://github.com/BC-SECURITY/Starkiller,Tool for Windows post-exploitation."
}

function install_assetfinder() {
  colorecho "Installing assetfinder"
  go install -v github.com/tomnomnom/assetfinder@latest
  add-history assetfinder
  add-test-command "assetfinder thehacker.recipes"
  add-to-list "assetfinder,https://github.com/tomnomnom/assetfinder,Tool to find subdomains and IP addresses associated with a domain."
}

function install_subfinder() {
  colorecho "Installing subfinder"
  go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
  add-history subfinder
  add-test-command "subfinder -version"
  add-to-list "subfinder,https://github.com/projectdiscovery/subfinder,Tool to find subdomains associated with a domain."
}

function install_gf() {
  # A wrapper around grep, to help you grep for things
  go install -v github.com/tomnomnom/gf@latest
  # Enable autocompletion
  echo 'source $GOPATH/pkg/mod/github.com/tomnomnom/gf@*/gf-completion.zsh' >> ~/.zshrc
  cp -r /root/go/pkg/mod/github.com/tomnomnom/gf@*/examples ~/.gf
  # Add patterns from 1ndianl33t
  git -C /opt/tools/ clone https://github.com/1ndianl33t/Gf-Patterns
  cp -r /opt/tools/Gf-Patterns/*.json ~/.gf
  # Remove repo to save space
  rm -r /opt/tools/Gf-Patterns
  add-test-command "gf --list"
  add-test-command "ls ~/.gf | grep 'redirect.json'"
  add-to-list "gf,https://github.com/tomnomnom/gf,Tool to find code injection points."
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
  git -C /opt/tools/ clone https://github.com/assetnote/kiterunner.git
  cd /opt/tools/kiterunner || exit
  wget https://wordlists-cdn.assetnote.io/data/kiterunner/routes-large.kite.tar.gz
  wget https://wordlists-cdn.assetnote.io/data/kiterunner/routes-small.kite.tar.gz
  make build
  ln -s "$(pwd)/dist/kr" /opt/tools/bin/kr
  add-history kitrunner
  add-test-command "kr --help"
  add-to-list "kiterunner,https://github.com/assetnote/kiterunner,Tool for operating Active Directory environments."
}

function install_dirsearch() {
  colorecho "Installing dirsearch"
  python3 -m pipx install git+https://github.com/maurosoria/dirsearch
  add-history dirsearch
  add-test-command "dirsearch --help"
  add-to-list "dirsearch,https://github.com/maurosoria/dirsearch,Tool for searching files and directories on a web site."
}

function install_cmsmap() {
  colorecho "Installing CMSmap"
  python3 -m pipx install git+https://github.com/Dionach/CMSmap.git
  cmsmap -U PC
  add-history cmsmap
  add-test-command "cmsmap --help; cmsmap --help |& grep 'Post Exploitation'"
  add-to-list "cmsmap,https://github.com/Dionach/CMSmap,Tool for security audit of web content management systems."
}

function install_tomcatwardeployer() {
  colorecho "Installing tomcatWarDeployer"
  git -C /opt/tools/ clone https://github.com/mgeeky/tomcatWarDeployer.git
  cd /opt/tools/tomcatWarDeployer/ || exit
  python3 -m pip install -r requirements.txt
  add-aliases tomcatwardeployer
  add-test-command "tomcatWarDeployer --help"
  add-to-list "tomcatwardeployer,https://github.com/mgeeky/tomcatwardeployer,Script to deploy war file in Tomcat."
}

function install_clusterd() {
  colorecho "Installing clusterd"
  git -C /opt/tools/ clone https://github.com/hatRiot/clusterd.git
  cd /opt/tools/clusterd/ || exit
  python -m pip install -r requirements.txt
  echo -e '#!/bin/sh\n(cd /opt/tools/clusterd/ && python clusterd.py $@)' > /usr/local/bin/clusterd
  chmod +x /usr/local/bin/clusterd
  add-history clusterd
  add-test-command "clusterd --help"
  add-to-list "clusterd,https://github.com/hatRiot/clusterd,A tool to distribute and remotely manage Hacking Team's RCS agents."
}

function install_moodlescan() {
  colorecho "Installing moodlescan"
  git -C /opt/tools/ clone https://github.com/inc0d3/moodlescan.git
  cd /opt/tools/moodlescan/ || exit
  python3 -m pip install -r requirements.txt
  /opt/tools/moodlescan/moodlescan.py -a
  add-aliases moodlescan
  add-history moodlescan
  add-test-command "moodlescan --help"
  add-to-list "moodlescan,https://github.com/inc0d3/moodlescan,Scan Moodle sites for information and vulnerabilities."
}

function install_arjun() {
  colorecho "Installing arjun"
  python3 -m pipx install arjun
  add-test-command "arjun --help"
  add-to-list "arjun,https://github.com/s0md3v/Arjun,HTTP parameter discovery suite."
}

function install_ffuf() {
  colorecho "Installing ffuf"
  go install -v github.com/ffuf/ffuf@latest
  add-history ffuf
  add-test-command "ffuf --help"
  add-to-list "ffuf,https://github.com/ffuf/ffuf,Fast web fuzzer written in Go."
}

function install_waybackurls() {
  colorecho "Installing waybackurls"
  go install -v github.com/tomnomnom/waybackurls@latest
  add-history waybackurls
  add-test-command "waybackurls -h"
  add-to-list "waybackurls,https://github.com/tomnomnom/waybackurls,Fetch all the URLs that the Wayback Machine knows about for a domain."
}

function install_gitrob(){
  colorecho "Installing gitrob"
  go install -v github.com/michenriksen/gitrob@latest
  add-to-list "gitrob,https://github.com/michenriksen/gitrob,Reconnaissance tool for GitHub organizations."
}

function install_gron() {
  colorecho "Installing gron"
  go install -v github.com/tomnomnom/gron@latest
  add-test-command "gron --help"
  add-to-list "gron,https://github.com/tomnomnom/gron,Make JSON greppable!"
}

function install_timing_attack() {
  colorecho "Installing timing_attack"
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

function install_findomain() {
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
  add-test-command "findomain --version"
  add-to-list "findomain,https://github.com/findomain/findomain,The fastest and cross-platform subdomain enumerator."
}

function install_proxychains() {
  colorecho "Installing proxychains"
  git -C /opt/tools/ clone https://github.com/rofl0r/proxychains-ng
  cd /opt/tools/proxychains-ng/ || exit
  ./configure --prefix=/usr --sysconfdir=/etc
  make
  make install
  # Add proxyresolv to PATH (needed with 'proxy_dns_old' config)
  ln -s /opt/tools/proxychains-ng/src/proxyresolv /usr/bin/proxyresolv
  make install-config
  cp -v /root/sources/proxychains/proxychains.conf /etc/proxychains.conf
  add-aliases proxychains
  add-test-command "proxychains4 echo test"
  add-test-command "proxyresolv"
  add-to-list "proxychains,https://github.com/rofl0r/proxychains,Proxy chains - redirect connections through proxy servers."
}

function install_grc() {
  colorecho "Installing and configuring grc"
  apt-get -y install grc
  cp -v /root/sources/grc/grc.conf /etc/grc.conf
  add-aliases grc
  add-to-list "grc,https://github.com/garabik/grc,Colorize logfiles and command output."
}

function install_nvm() {
  colorecho "Installing nvm (in zsh context)"
  zsh -c "source ~/.zshrc && nvm install node"
  add-to-list "nvm,https://github.com/nvm-sh/nvm,Node Version Manager - Simple bash script to manage multiple active node.js versions."
}

function install_pykek() {
  colorecho "Installing Python Kernel Exploit Kit (pykek) for MS14-068"
  git -C /opt/tools/ clone https://github.com/preempt/pykek
  add-aliases pykek
  add-test-command "ms14-068.py |& grep '<clearPassword>'"
  add-to-list "pykek,https://github.com/preempt/pykek,PyKEK (Python Kerberos Exploitation Kit), a python library to manipulate KRB5-related data."
}

function install_autorecon() {
  colorecho "Installing autorecon"
  apt-get -y install wkhtmltopdf python3-venv
  python3 -m pipx install git+https://github.com/Tib3rius/AutoRecon
  add-history autorecon
  # test below cannot work because test runner cannot have a valid display
  # add-test-command "autorecon --version"
  add-test-command "which autorecon"
  add-to-list "autorecon,https://github.com/Tib3rius/AutoRecon,Multi-threaded network reconnaissance tool which performs automated enumeration of services."
}

function install_tcpdump() {
  colorecho "Installing tcpdump"
  fapt tcpdump
  add-test-command "tcpdump --version"
  add-to-list "tcpdump,https://github.com/the-tcpdump-group/tcpdump,a powerful command-line packet analyzer for Unix-like systems"
}

function install_simplyemail() {
  colorecho "Installing SimplyEmail"
  git -C /opt/tools/ clone https://github.com/SimplySecurity/SimplyEmail.git
  cd /opt/tools/SimplyEmail/ || exit
  bash setup/setup.sh #TODO update install process ?
  add-aliases simplyemail
  add-history simplyemail
  add-test-command "SimplyEmail -l"
  add-to-list "simplyemail,https://github.com/SimplySecurity/SimplyEmail,a scriptable command line tool for sending emails"
}

function install_privexchange() {
  colorecho "Installing privexchange"
  git -C /opt/tools/ clone https://github.com/dirkjanm/PrivExchange
  add-aliases privexchange
  add-history privexchange
  add-test-command "python3 /opt/tools/PrivExchange/privexchange.py --help"
  add-to-list "privexchange,https://github.com/dirkjanm/PrivExchange,a tool to perform attacks against Microsoft Exchange server using NTLM relay techniques"
}

function install_lnkup() {
  colorecho "Installing LNKUp"
  git -C /opt/tools/ clone https://github.com/Plazmaz/LNKUp
  cd /opt/tools/LNKUp || exit
  python -m pip install -r requirements.txt
  add-aliases lnkup
  add-history lnkup
  add-test-command "lnk-generate.py --help"
  add-to-list "lnkup,https://github.com/Plazmaz/lnkUp,This tool will allow you to generate LNK payloads. Upon rendering or being run, they will exfiltrate data."
}

function install_samdump2() {
  colorecho "Installing samdump2"
  fapt samdump2
  add-test-command "samdump2 -h; samdump2 -h |& grep 'enable debugging'"
  add-to-list "samdump2,https://github.com/azan121468/SAMdump2,A tool to dump Windows NT/2k/XP/Vista password hashes from SAM files"
}

function install_pwntools() {
  colorecho "Installing pwntools"
  python -m pip install pwntools
  python -m pip install pathlib2
  python3 -m pip install pwntools
  add-test-command "python -c 'import pwn'"
  add-test-command "python3 -c 'import pwn'"
  add-to-list "pwntools,https://github.com/Gallopsled/pwntools,a CTF framework and exploit development library"
}

function install_angr() {
  colorecho "Installing angr"
  fapt python3-dev libffi-dev build-essential virtualenvwrapper
  python3 -m pip install virtualenv virtualenvwrapper
  mkvirtualenv --python="$(which python3)" angr
  python3 -m pip install angr
  add-test-command "python3 -c 'import angr'"
  add-to-list "angr,https://github.com/angr/angr,a platform-agnostic binary analysis framework"
}

function install_pwndbg() {
  colorecho "Installing pwndbg"
  #apt -y install python3.8 python3.8-dev
  git -C /opt/tools/ clone https://github.com/pwndbg/pwndbg
  cd /opt/tools/pwndbg || exit
  ./setup.sh
  echo 'set disassembly-flavor intel' >> ~/.gdbinit
  add-aliases gdb
  add-test-command "gdb --help"
  add-to-list "pwndbg,https://github.com/pwndbg/pwndbg,a GDB plugin that makes debugging with GDB suck less"
}

function install_darkarmour() {
  colorecho "Installing darkarmour"
  git -C /opt/tools/ clone https://github.com/bats3c/darkarmour
  cd /opt/tools/darkarmour || exit
  apt-get -y install mingw-w64-tools mingw-w64-common g++-mingw-w64 gcc-mingw-w64 upx-ucl osslsigncode
  add-aliases darkarmour
  add-history darkarmour
  add-test-command "darkarmour --help"
  add-to-list "darkarmour,https://github.com/bats3c/darkarmour,a tool to detect and evade common antivirus products"
}

function install_powershell() {
  colorecho "Installing powershell"
  if [[ $(uname -m) = 'x86_64' ]]
  then
    curl -L -o /tmp/powershell.tar.gz https://github.com/PowerShell/PowerShell/releases/download/v7.3.0/powershell-7.3.0-linux-x64.tar.gz
  elif [[ $(uname -m) = 'aarch64' ]]
  then
    curl -L -o /tmp/powershell.tar.gz https://github.com/PowerShell/PowerShell/releases/download/v7.3.0/powershell-7.3.0-linux-arm64.tar.gz
  elif [[ $(uname -m) = 'armv7l' ]]
  then
    curl -L -o /tmp/powershell.tar.gz https://github.com/PowerShell/PowerShell/releases/download/v7.3.0/powershell-7.3.0-linux-arm32.tar.gz
  else
    criticalecho-noexit "This installation function doesn't support architecture $(uname -m)" && return
  fi
  mkdir -v -p /opt/tools/powershell/7
  tar xvfz /tmp/powershell.tar.gz -C /opt/tools/powershell/7
  chmod -v +x /opt/tools/powershell/7/pwsh
  ln -v -s /opt/tools/powershell/7/pwsh /opt/tools/bin/pwsh
  ln -v -s /opt/tools/bin/pwsh /opt/tools/bin/powershell
  rm -v /tmp/powershell.tar.gz
  add-test-command "powershell -Version"
  add-to-list "powershell,https://github.com/PowerShell/PowerShell,a command-line shell and scripting language designed for system administration and automation"
}

function install_fzf() {
  colorecho "Installing fzf"
  git -C /opt/tools/ clone --depth 1 https://github.com/junegunn/fzf.git
  cd /opt/tools/fzf || exit
  ./install --all
  add-aliases fzf
  add-test-command "fzf --version"
  add-to-list "fzf,https://github.com/junegunn/fzf,a command-line fuzzy finder"
}

function install_shellerator() {
  colorecho "Installing shellerator"
  python3 -m pipx install git+https://github.com/ShutdownRepo/shellerator
  add-history shellerator
  add-test-command "shellerator --help"
  add-to-list "shellerator,https://github.com/ShutdownRepo/Shellerator,a simple command-line tool for generating shellcode"
}

function install_uberfile() {
  colorecho "Installing uberfile"
  python3 -m pipx install git+https://github.com/ShutdownRepo/uberfile
  add-test-command "uberfile --help"
  add-to-list "uberfile,https://github.com/ShutdownRepo/Uberfile,Uberfile is a simple command-line tool aimed to help pentesters quickly generate file downloader one-liners in multiple contexts (wget, curl, powershell, certutil...). This project code is based on my other similar project for one-liner reverseshell generation Shellerator."
}

function install_kadimus() {
  colorecho "Installing kadimus"
  apt-get -y install libcurl4-openssl-dev libpcre3-dev libssh-dev
  git -C /opt/tools/ clone https://github.com/P0cL4bs/Kadimus
  cd /opt/tools/Kadimus || exit
  make
  add-aliases kadimus
  add-history kadimus
  add-test-command "kadimus --help"
  add-to-list "kadimus,https://github.com/P0cL4bs/Kadimus,a tool for detecting and exploiting file upload vulnerabilities"
}

function install_testssl() {
  colorecho "Installing testssl"
  apt-get -y install bsdmainutils
  git -C /opt/tools/ clone --depth 1 https://github.com/drwetter/testssl.sh.git
  add-aliases testssl
  add-test-command "testssl --help"
  add-to-list "testssl,https://github.com/drwetter/testssl.sh,a tool for testing SSL/TLS encryption on servers"
}

function install_sslscan() {
  colorecho "Installing sslscan"
  fapt sslscan
  add-test-command "sslscan --version"
  add-to-list "sslscan,https://github.com/rbsec/sslscan,a tool for testing SSL/TLS encryption on servers"
}

function install_tls-scanner() {
  colorecho "Installing TLS-Scanner"
  fapt maven
  git -C /opt/tools/ clone https://github.com/tls-attacker/TLS-Scanner
  cd /opt/tools/TLS-Scanner || exit
  git submodule update --init --recursive
  mvn clean package -DskipTests=true
  add-aliases tls-scanner
  add-history tls-scanner
  add-test-command "tls-scanner --help"
  add-to-list "tls-scanner,https://github.com/tls-attacker/tls-scanner,a simple script to check the security of a remote TLS/SSL web server"
}

function install_bat() {
  colorecho "Installing bat"
  version="$(curl -s https://api.github.com/repos/sharkdp/bat/releases/latest | grep 'tag_name' | cut -d 'v' -f2 | cut -d '"' -f1)"
  if [[ $(uname -m) = 'x86_64' ]]
  then
    wget -O /tmp/bat.deb "https://github.com/sharkdp/bat/releases/download/v"$version"/bat_"$version"_amd64.deb"
  elif [[ $(uname -m) = 'aarch64' ]]
  then
    wget -O /tmp/bat.deb "https://github.com/sharkdp/bat/releases/download/v"$version"/bat_"$version"_arm64.deb"
  elif [[ $(uname -m) = 'armv7l' ]]
  then
    wget -O /tmp/bat.deb "https://github.com/sharkdp/bat/releases/download/v"$version"/bat_"$version"_armhf.deb"
  else
    criticalecho-noexit "This installation function doesn't support architecture $(uname -m)" && return
  fi
  apt-get install -f /tmp/bat.deb
  rm /tmp/bat.deb
  add-test-command "bat --version"
  add-to-list "bat,https://github.com/sharkdp/bat,a command-line tool for displaying file contents with syntax highlighting"
}

function install_mdcat() {
  colorecho "Installing mdcat"
  fapt pkg-config
  cargo install mdcat
  source "$HOME/.cargo/env"
  add-test-command "mdcat --version"
  add-to-list "mdcat,https://github.com/lunaryorn/mdcat,a command-line tool for rendering markdown documents"
}

function install_xsrfprobe() {
  colorecho "Installing XSRFProbe"
  git -C /opt/tools/ clone https://github.com/0xInfection/XSRFProbe
  cd /opt/tools/XSRFProbe || exit
  python3 setup.py install
  add-test-command "xsrfprobe --help"
  add-to-list "xsrfprobe,https://github.com/0xInfection/XSRFProbe,a tool for detecting and exploiting Cross-Site Request Forgery (CSRF) vulnerabilities"
}

function install_krbrelayx() {
  colorecho "Installing krbrelayx"
  python3 -m pip install dnspython ldap3
  #python -m pip install dnstool==1.15.0
  git -C /opt/tools/ clone https://github.com/dirkjanm/krbrelayx
  cd /opt/tools/krbrelayx/ || exit
  cp -v /root/sources/grc/conf.krbrelayx /usr/share/grc/conf.krbrelayx
  add-aliases krbrelayx
  add-history krbrelayx
  add-test-command "krbrelayx.py --help"
  add-test-command "addspn.py --help"
  add-test-command "addspn.py --help"
  add-test-command "printerbug.py --help"
  add-to-list "krbrelayx,https://github.com/dirkjanm/krbrelayx,a tool for performing Kerberos relay attacks"
}

function install_hakrawler() {
  colorecho "Installing hakrawler"
  go install -v github.com/hakluke/hakrawler@latest
  add-history hakrawler
  add-test-command "hakrawler --help"
  add-to-list "hakrawler,https://github.com/hakluke/hakrawler,a fast web crawler for gathering URLs and other information from websites"
}

function install_jwt_tool() {
  colorecho "Installing JWT tool"
  git -C /opt/tools/ clone https://github.com/ticarpi/jwt_tool
  python3 -m pip install pycryptodomex
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

function install_pypykatz() {
  colorecho "Installing pypykatz"
  python3 -m pipx install pypykatz
  add-history pypykatz
  add-test-command "pypykatz version"
  add-to-list "pypykatz,https://github.com/skelsec/pypykatz,a Python library for mimikatz-like functionality"
}

function install_enyx() {
  colorecho "Installing enyx"
  git -C /opt/tools/ clone https://github.com/trickster0/Enyx
  add-aliases enyx
  add-history enyx
  add-test-command "enyx"
  add-to-list "enyx,https://github.com/trickster0/enyx,Framework for building offensive security tools."
}

function install_enum4linux-ng() {
  colorecho "Installing enum4linux-ng"
  python3 -m pipx install git+https://github.com/cddmp/enum4linux-ng
  add-history enum4linux-ng
  add-test-command "enum4linux-ng --help"
  add-to-list "enum4linux-ng,https://github.com/cddmp/enum4linux-ng,Tool for enumerating information from Windows and Samba systems."
}

function install_git-dumper() {
  colorecho "Installing git-dumper"
  git -C /opt/tools/ clone https://github.com/arthaud/git-dumper
  cd /opt/tools/git-dumper || exit
  python3 -m pip install -r requirements.txt
  add-aliases git-dumper
  add-test-command "git-dumper --help"
  add-to-list "git-dumper,https://github.com/arthaud/git-dumper,Small script to dump a Git repository from a website."
}

function install_gittools() {
  colorecho "Installing GitTools"
  git -C /opt/tools/ clone https://github.com/internetwache/GitTools.git
  add-aliases gittools
  add-test-command "gitdumper --help; gitdumper --help |& grep 'USAGE: http://target.tld/.git/'"
  add-to-list "gittools,https://github.com/internetwache/GitTools,A collection of Git tools including a powerful Dumper for dumping Git repositories."
}

function install_gopherus() {
  colorecho "Installing gopherus"
  git -C /opt/tools/ clone https://github.com/tarunkant/Gopherus
  cd /opt/tools/Gopherus || exit
  ./install.sh
  add-aliases install_gopherus
  add-test-command "gopherus --help"
  add-to-list "gopherus,https://github.com/tarunkant/Gopherus,Gopherus is a simple command line tool for exploiting vulnerable Gopher servers."
}

function install_ysoserial() {
  colorecho "Installing ysoserial"
  mkdir /opt/tools/ysoserial/
  wget -O /opt/tools/ysoserial/ysoserial.jar "https://jitpack.io/com/github/frohoff/ysoserial/master-SNAPSHOT/ysoserial-master-SNAPSHOT.jar"
  add-aliases ysoserial
  add-test-command "ysoserial --help; ysoserial --help |& grep 'spring-core:4.1.4.RELEASE'"
  add-to-list "ysoserial,https://github.com/frohoff/ysoserial,A proof-of-concept tool for generating payloads that exploit unsafe Java object deserialization."
}

function install_whatweb() {
  colorecho "Installing whatweb"
  fapt whatweb
  add-test-command "whatweb --version"
  add-to-list "whatweb,https://github.com/urbanadventurer/WhatWeb,Next generation web scanner that identifies what websites are running."
}

function install_phpggc(){
  colorecho "Installing phpggc"
  git -C /opt/tools clone https://github.com/ambionics/phpggc.git
  add-aliases phpggc
  add-test-command "phpggc --help"
  add-to-list "phpggc,https://github.com/ambionics/phpggc,Exploit generation tool for the PHP platform."
}

function install_symfony-exploits(){
  colorecho "Installing symfony-exploits"
  git -C /opt/tools clone https://github.com/ambionics/symfony-exploits
  add-aliases symfony-exploits
  add-test-command "secret_fragment_exploit.py --help"
  add-to-list "symfony-exploits,https://github.com/ambionics/symfony-exploits,Collection of Symfony exploits and PoCs."
}

function install_john() {
  colorecho "Installing john the ripper"
  #fapt qtbase5-dev
  git -C /opt/tools/ clone --depth 1 https://github.com/openwall/john
  cd /opt/tools/john/src || exit
  ./configure --disable-native-tests && make
  add-aliases john-the-ripper
  add-history john-the-ripper
  add-test-command "john --help"
  add-to-list "john,https://github.com/openwall/john,John the Ripper password cracker."
}

function install_fcrackzip() {
  colorecho "Installing fcrackzip"
  fapt fcrackzip
  add-history fcrackzip
  add-test-command fcrackzip --help
  add-to-list "fcrackzip,https://github.com/hyc/fcrackzip,Password cracker for zip archives."
}

function install_name-that-hash() {
  colorecho "Installing Name-That-Hash"
  python3 -m pipx install name-that-hash
  add-history name-that-hash
  add-test-command "nth --help"
  add-to-list "name-that-hash,https://github.com/HashPals/Name-That-Hash,Online tool for identifying hashes."
}

function install_zerologon() {
  colorecho "Pulling CVE-2020-1472 exploit and scan scripts"
  git -C /opt/tools/ clone https://github.com/SecuraBV/CVE-2020-1472
  mv /opt/tools/CVE-2020-1472 /opt/tools/zerologon-scan
  git -C /opt/tools/ clone https://github.com/dirkjanm/CVE-2020-1472
  mv /opt/tools/CVE-2020-1472 /opt/tools/zerologon-exploit
  add-aliases zerologon
  add-history zerologon
  add-test-command "zerologon-scan; zerologon-scan | grep Usage"
  add-to-list "zerologon,https://github.com/SecuraBV/CVE-2020-1472,Exploit for the Zerologon vulnerability (CVE-2020-1472)."
}

function install_proxmark3() {
  colorecho "Installing proxmark3 client"
  colorecho "Compiling proxmark client for generic usage with PLATFORM=PM3OTHER (read https://github.com/RfidResearchGroup/proxmark3/blob/master/doc/md/Use_of_Proxmark/4_Advanced-compilation-parameters.md#platform)"
  colorecho "It can be compiled again for RDV4.0 with 'make clean && make all && make install' from /opt/tools/proxmak3/"
  apt-get -y install --no-install-recommends git ca-certificates build-essential pkg-config libreadline-dev gcc-arm-none-eabi libnewlib-dev qtbase5-dev libbz2-dev libbluetooth-dev
  git -C /opt/tools/ clone https://github.com/RfidResearchGroup/proxmark3.git
  cd /opt/tools/proxmark3 || exit
  make clean
  make all PLATFORM=PM3OTHER
  make install PLATFORM=PM3OTHER
  add-aliases proxmark3
  add-history proxmark3
  add-test-command "proxmark3 --version"
  add-to-list "proxmark3,https://github.com/Proxmark/proxmark3,Open source RFID research toolkit."
}

function install_checksec-py() {
  colorecho "Installing checksec.py"
  python3 -m pipx install checksec.py
  add-test-command "checksec --help"
  add-to-list "checksec-py,https://github.com/Wenzel/checksec.py,Python wrapper script for checksec.sh from paX."
}

function install_arsenal() {
  echo "Installing Arsenal"
  python3 -m pipx install git+https://github.com/Orange-Cyberdefense/arsenal
  add-aliases arsenal
  add-test-command "arsenal --version"
  add-to-list "arsenal,https://github.com/Orange-Cyberdefense/arsenal,Powerful weapons for penetration testing."
}

function install_tldr() {
  colorecho "Installing tldr"
  fapt tldr
  mkdir -p ~/.local/share/tldr
  tldr -u
  add-to-list "tldr,https://github.com/tldr-pages/tldr,Collection of simplified and community-driven man pages."
}

function install_bloodhound() {
  colorecho "Installing BloodHound from sources"
  git -C /opt/tools/ clone https://github.com/BloodHoundAD/BloodHound/
  mv /opt/tools/BloodHound /opt/tools/BloodHound4
  zsh -c "source ~/.zshrc && cd /opt/tools/BloodHound4 && nvm install 16.13.0 && nvm use 16.13.0 && npm install -g electron-packager && npm install && npm run build:linux"
  if [[ $(uname -m) = 'x86_64' ]]
  then
    ln -s /opt/tools/BloodHound4/BloodHound-linux-x64/BloodHound /opt/tools/BloodHound4/BloodHound
  elif [[ $(uname -m) = 'aarch64' ]]
  then
    fapt libgbm1
    ln -s /opt/tools/BloodHound4/BloodHound-linux-arm64/BloodHound /opt/tools/BloodHound4/BloodHound
  elif [[ $(uname -m) = 'armv7l' ]]
  then
    fapt libgbm1
    ln -s /opt/tools/BloodHound4/BloodHound-linux-armv7l/BloodHound /opt/tools/BloodHound4/BloodHound
  else
    criticalecho-noexit "This installation function doesn't support architecture $(uname -m)" && return
  fi
  mkdir -p ~/.config/bloodhound
  cp -v /root/sources/bloodhound/config.json ~/.config/bloodhound/config.json
  cp -v /root/sources/bloodhound/customqueries.json ~/.config/bloodhound/customqueries.json
  add-aliases bloodhound
  # TODO add-test-command
  add-to-list "bloodhound,https://github.com/BloodHoundAD/BloodHound,Active Directory security tool for reconnaissance and attacking AD environments."
}

function install_bloodhound_old_v3() {
  colorecho "Installing Bloodhound v3 (just-in-case)"
  fapt libxss1
  wget -P /tmp/ "https://github.com/BloodHoundAD/BloodHound/releases/download/3.0.5/BloodHound-linux-x64.zip"
  unzip /tmp/BloodHound-linux-x64.zip -d /opt/tools/
  mv /opt/tools/BloodHound-linux-x64 /opt/tools/BloodHound3
  rm /tmp/BloodHound-linux-x64.zip
} #

function install_bloodhound_old_v2() {
  colorecho "Installing BloodHound v2 (for older databases/collections)"
  wget -P /tmp/ https://github.com/BloodHoundAD/BloodHound/releases/download/2.2.1/BloodHound-linux-x64.zip
  unzip /tmp/BloodHound-linux-x64.zip -d /opt/tools/
  mv /opt/tools/BloodHound-linux-x64 /opt/tools/BloodHound2
  rm /tmp/BloodHound-linux-x64.zip
} #

function install_bettercap() {
  colorecho "Installing Bettercap"
  apt-get -y install libpcap-dev libusb-1.0-0-dev libnetfilter-queue-dev
  go install -v github.com/bettercap/bettercap@latest
  /root/go/bin/bettercap -eval "caplets.update; ui.update; q"
  sed -i 's/set api.rest.username user/set api.rest.username bettercap/g' /usr/local/share/bettercap/caplets/http-ui.cap
  sed -i 's/set api.rest.password pass/set api.rest.password exegol4thewin/g' /usr/local/share/bettercap/caplets/http-ui.cap
  sed -i 's/set api.rest.username user/set api.rest.username bettercap/g' /usr/local/share/bettercap/caplets/https-ui.cap
  sed -i 's/set api.rest.password pass/set api.rest.password exegol4thewin/g' /usr/local/share/bettercap/caplets/https-ui.cap
  add-aliases bettercap
  add-test-command "bettercap --version"
  add-to-list "bettercap,https://github.com/bettercap/bettercap,The Swiss Army knife for 802.11, BLE, and Ethernet networks reconnaissance and MITM attacks."
}

function install_hcxtools() {
  colorecho "Installing hcxtools"
  fapt libcurl4 libcurl4-openssl-dev libssl-dev openssl pkg-config
  git -C /opt/tools/ clone https://github.com/ZerBea/hcxtools
  cd /opt/tools/hcxtools/ || exit
  # Checking out to specific commit is a temporary fix to the project no compiling anymore.
  # FIXME whenever possible to stay up to date with project (https://github.com/ZerBea/hcxtools/issues/233)
  git checkout 5937d2ad9d021f3b5e2edd55d79439b8485d3222
  make
  make install
  add-history hcxtools
  add-test-command "hcxpcapngtool --version"
  add-test-command "hcxhashtool --version"
  add-to-list "hcxtools,https://github.com/ZerBea/hcxtools,Tools for capturing and analyzing packets from WLAN devices."
}

function install_hcxdumptool() {
  colorecho "Installing hcxdumptool"
  apt-get -y install libcurl4-openssl-dev libssl-dev
  git -C /opt/tools/ clone https://github.com/ZerBea/hcxdumptool
  cd /opt/tools/hcxdumptool || exit
  # Checking out to specific commit is a temporary fix to the project no compiling anymore.
  # FIXME whenever possible to stay up to date with project (https://github.com/ZerBea/hcxdumptool/issues/232)
  git checkout 56d078de4d6f5cef07b378707ab478fde03168c0
  make
  make install
  ln -s /usr/local/bin/hcxpcapngtool /usr/local/bin/hcxpcaptool
  add-history hcxdumptool
  add-test-command "hcxdumptool --version"
  add-to-list "hcxdumptool,https://github.com/ZerBea/hcxdumptool,Small tool to capture packets from wlan devices."
}

function install_pyrit() {
  colorecho "Installing pyrit"
  git -C /opt/tools clone https://github.com/JPaulMora/Pyrit
  cd /opt/tools/Pyrit || exit
  fapt python2.7 python2.7-dev libssl-dev libpcap-dev
  python2.7 -m pip install psycopg2-binary scapy
  #https://github.com/JPaulMora/Pyrit/issues/591
  cp -v /root/sources/patches/undefined-symbol-aesni-key.patch undefined-symbol-aesni-key.patch
  git apply --verbose undefined-symbol-aesni-key.patch
  python2.7 setup.py clean
  python2.7 setup.py build
  python2.7 setup.py install
  add-test-command "pyrit help"
  add-to-list "pyrit,https://github.com/JPaulMora/Pyrit,Python-based WPA/WPA2-PSK attack tool."
}

function install_wifite2() {
  colorecho "Installing wifite2"
  git -C /opt/tools/ clone https://github.com/derv82/wifite2.git
  cd /opt/tools/wifite2/ || exit
  python3 setup.py install
  add-test-command "wifite --help"
  add-to-list "wifite2,https://github.com/derv82/wifite2,Script for auditing wireless networks."
}

function install_wireshark_sources() {
  colorecho "Installing tshark, wireshark"
  apt-get -y install cmake libgcrypt20-dev libglib2.0-dev libpcap-dev qtbase5-dev libssh-dev libsystemd-dev qtmultimedia5-dev libqt5svg5-dev qttools5-dev libc-ares-dev flex bison byacc
  wget -O /tmp/wireshark.tar.xz https://www.wireshark.org/download/src/wireshark-latest.tar.xz
  cd /tmp/ || exit
  tar -xvf /tmp/wireshark.tar.xz
  cd "$(find . -maxdepth 1 -type d -name 'wireshark*')" || exit
  cmake .
  make
  make install
  cd /tmp/ || exit
  rm -r "$(find . -maxdepth 1 -type d -name 'wireshark*')"
  wireshark.tar.xz
} #

function install_infoga() {
  colorecho "Installing infoga"
  git -C /opt/tools/ clone https://github.com/m4ll0k/Infoga
  find /opt/tools/Infoga/ -type f -print0 | xargs -0 dos2unix
  cd /opt/tools/Infoga || exit
  python3 -m pip install .
  add-aliases infoga
  add-history infoga
  add-test-command "infoga.py --help"
  add-to-list "infoga,https://github.com/m4ll0k/Infoga,Information gathering tool for hacking."
}

function install_buster() {
  colorecho "Installing buster"
  python3 -m pipx install git+https://github.com/sham00n/buster
  add-history buster
  add-test-command "buster --help"
  add-to-list "buster,https://github.com/sham00n/Buster,Advanced OSINT tool"
}

function install_pwnedornot() {
  colorecho "Installing pwnedornot"
  git -C /opt/tools/ clone https://github.com/thewhiteh4t/pwnedOrNot
  python3 -m pip install requests html2text
  mkdir -p "$HOME/.config/pwnedornot"
  cp config.json "$HOME/.config/pwnedornot/config.json"
  add-aliases pwnedornot
  add-test-command "pwnedornot.py --help"
  add-to-list "pwnedornot,https://github.com/thewhiteh4t/pwnedOrNot,Check if a password has been leaked in a data breach."
}

function install_chromium() {
  fapt chromium
  add-test-command "chromium --version"
  add-to-list "chromium,https://github.com/chromium/chromium,Open-source web browser project from Google."
}

# FIXME
function install_ghunt() {
  colorecho "Installing ghunt"
  apt-get update
  apt-get install -y curl unzip gnupg
  git -C /opt/tools/ clone https://github.com/mxrch/GHunt
  cd /opt/tools/GHunt || exit
  python3 -m pip install -r requirements.txt
  add-aliases ghunt
  # TODO add-test-command
  add-to-list "ghunt,https://github.com/mxrch/ghunt,Hunt down GitHub users and repositories leakage."
}

function install_oaburl() {
  colorecho "Downloading oaburl.py"
  mkdir /opt/tools/OABUrl
  wget -O /opt/tools/OABUrl/oaburl.py "https://gist.githubusercontent.com/snovvcrash/4e76aaf2a8750922f546eed81aa51438/raw/96ec2f68a905eed4d519d9734e62edba96fd15ff/oaburl.py"
  chmod +x /opt/tools/OABUrl/oaburl.py
  add-aliases oaburl
  add-history oaburl
  add-test-command "oaburl.py --help"
  add-to-list "oaburl,https://gist.githubusercontent.com/snovvcrash/4e76aaf2a8750922f546eed81aa51438/raw/96ec2f68a905eed4d519d9734e62edba96fd15ff/oaburl.py,Find Open redirects and other vulnerabilities."
}

function install_libmspack() {
  colorecho "Installing libmspack"
  git -C /opt/tools/ clone https://github.com/kyz/libmspack.git
  cd /opt/tools/libmspack/libmspack || exit
  ./rebuild.sh
  ./configure
  make
  add-aliases libmspack
  add-test-command "oabextract"
  add-to-list "libmspack,https://github.com/kyz/libmspack,C library for Microsoft compression formats."
}

function install_ruler() {
  colorecho "Downloading ruler and form templates"
  git -C /opt/tools clone https://github.com/sensepost/ruler/
  cd /opt/tools/ruler || exit
  if [[ $(uname -m) = 'x86_64' ]]
  then
    GOOS=linux GOARCH=amd64 go build -o ruler
  elif [[ $(uname -m) = 'aarch64' ]]
  then
    GOOS=linux GOARCH=arm64 go build -o ruler
  else
    criticalecho-noexit "This installation function doesn't support architecture $(uname -m)" && return
  fi
  ln -s /opt/tools/ruler/ruler /opt/tools/bin/ruler
  add-history ruler
  add-test-command "ruler --version"
  add-to-list "ruler,https://github.com/sensepost/ruler,Outlook Rules exploitation framework."
}

function install_ghidra() {
  colorecho "Installing Ghidra"
  wget -P /tmp/ "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_10.1.2_build/ghidra_10.1.2_PUBLIC_20220125.zip"
  unzip /tmp/ghidra_10.1.2_PUBLIC_20220125.zip -d /opt/tools
  rm /tmp/ghidra_10.1.2_PUBLIC_20220125.zip
  add-aliases ghidra
  # TODO add-test-command GUI app
  add-to-list "ghidra,https://github.com/NationalSecurityAgency/ghidra,Software reverse engineering suite of tools."
}

function install_ida() {
  colorecho "Installing IDA"
  if [[ $(uname -m) = 'x86_64' ]]
  then
    wget -P /tmp/ "https://out7.hex-rays.com/files/idafree77_linux.run"
    chmod +x /tmp/idafree77_linux.run
    /tmp/idafree77_linux.run --mode unattended --prefix /opt/tools/idafree-7.7
    rm /tmp/idafree77_linux.run
  else
    criticalecho-noexit "This installation function doesn't support architecture $(uname -m), IDA Free only supports x86/x64" && return
  fi
  add-aliases ida
  # TODO add-test-command GUI app
  add-to-list "ida,https://www.hex-rays.com/products/ida/,Interactive disassembler for software analysis."
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

function install_linkedin2username() {
  colorecho "Installing linkedin2username"
  git -C /opt/tools/ clone https://github.com/initstring/linkedin2username
  cd /opt/tools/linkedin2username || exit
  python3 -m python -m pip install -r requirements.txt
  add-aliases linkedin2username
  add-history linkedin2username
  add-test-command "linkedin2username.py --help"
  add-to-list "linkedin2username,https://github.com/initstring/linkedin2username,Generate a list of LinkedIn usernames from a company name."
}

function install_toutatis() {
  colorecho "Installing toutatis"
  git -C /opt/tools/ clone https://github.com/megadose/toutatis
  cd /opt/tools/toutatis || exit
  python3 setup.py install
  add-aliases toutatis
  add-history toutatis
  add-test-command "toutatis --help"
  add-to-list "toutatis,https://github.com/megadose/Toutatis,Toutatis is a tool that allows you to extract information from instagrams accounts such as e-mails, phone numbers and more."
}

function install_carbon14() {
  colorecho "Installing Carbon14"
  git -C /opt/tools/ clone https://github.com/Lazza/Carbon14
  cd /opt/tools/Carbon14 || exit
  python3 -m pip install -r requirements.txt
  add-aliases carbon14
  add-history carbon14
  add-test-command "carbon14.py --help"
  add-to-list "carbon14,https://github.com/Lazza/carbon14,OSINT tool for estimating when a web page was written."
}

function install_youtubedl() {
  colorecho "Installing youtube-dl"
  python3 -m pipx install youtube-dl
  add-test-command "youtube-dl --version"
  add-to-list "youtubedl,https://github.com/ytdl-org/youtube-dl,Download videos from YouTube and other sites."
}

function install_ipinfo() {
  colorecho "Installing ipinfo"
  sudo npm install ipinfo-cli --global
  add-history ipinfo
  add-test-command "ipinfo 127.0.0.1"
  add-to-list "ipinfo,https://github.com/ipinfo/cli,Get information about an IP address or hostname."
}

function install_constellation() {
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
  add-to-list "constellation,https://github.com/constellation-app/Constellation,Find and exploit vulnerabilities in mobile applications."
}

function install_holehe() {
  colorecho "Installing holehe"
  python3 -m pipx install holehe
  add-history holehe
  add-test-command "holehe --help"
  add-to-list "holehe,https://github.com/megadose/holehe,Exploit a vulnerable Samba service to gain root access."
}

function install_twint() {
  colorecho "Installing twint"
  python3 -m pipx install twint
  add-history twint
  add-to-list "twint,https://github.com/twintproject/twint,Twitter intelligence tool."
}

function install_h8mail() {
  colorecho "Installing h8mail"
  python3 -m pipx install h8mail
  add-history h8mail
  add-test-command "h8mail --help"
  add-to-list "h8mail,https://github.com/khast3x/h8mail,Email OSINT and breach hunting."
}

function install_phoneinfoga() {
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

function install_windapsearch-go() {
  colorecho "Installing Go windapsearch"
  if [[ $(uname -m) = 'x86_64' ]]
  then
    wget -O /opt/tools/bin/windapsearch "https://github.com/ropnop/go-windapsearch/releases/latest/download/windapsearch-linux-amd64"
  else
    criticalecho-noexit "This installation function doesn't support architecture $(uname -m)" && return
  fi
  chmod +x /opt/tools/bin/windapsearch
  add-history windapsearch
  add-test-command "windapsearch --help"
  add-to-list "windapsearch-go,https://github.com/ropnop/go-windapsearch/,Active Directory enumeration tool."
}

function install_trilium() {
  colorecho "Installing Trilium (building from sources)"
  apt-get -y install libpng16-16 libpng-dev pkg-config autoconf libtool build-essential nasm libx11-dev libxkbfile-dev
  git -C /opt/tools/ clone -b stable https://github.com/zadam/trilium.git
  cd /opt/tools/trilium || exit
  # the npm install needs to be executed in the zsh context where nvm is used to set the Node version to be used.
  zsh -c "source ~/.zshrc && cd /opt/tools/trilium && nvm install 16 && nvm use 16 && npm install && npm rebuild"
  mkdir -p /root/.local/share/trilium-data
  cp -v /root/sources/trilium/* /root/.local/share/trilium-data
  add-aliases trilium
  # Start the trilium, sleep for 3 sec, attempt to stop it
  # Stop command will fail if trilium isn't running
  add-test-command "trilium-start;sleep 20;trilium-stop"
  add-to-list "trilium,https://github.com/zadam/trilium,Personal knowledge management system."
}

function install_ntlmv1-multi() {
  colorecho "Installing ntlmv1 multi tool"
  git -C /opt/tools clone https://github.com/evilmog/ntlmv1-multi
  add-aliases ntlmv1-multi
  add-history ntlmv1-multi
  add-test-command "ntlmv1-multi --ntlmv1 a::a:a:a:a"
  add-to-list "ntlmv1-multi,https://github.com/evilmog/ntlmv1-multi,Exploit a vulnerability in Microsoft Windows to gain system-level access."
}

function install_droopescan() {
  colorecho "Installing droopescan"
  git -C /opt/tools clone https://github.com/droope/droopescan.git
  cd /opt/tools/droopescan || exit
  python3 -m pip install -r requirements.txt
  python3 setup.py install
  add-test-command "droopescan --help"
  add-to-list "droopescan,https://github.com/droope/droopescan,Scan Drupal websites for vulnerabilities."
}

function install_drupwn() {
  colorecho "Installing drupwn"
  python3 -m pipx install git+https://github.com/immunIT/drupwn
  add-test-command "drupwn --help"
  add-to-list "drupwn,https://github.com/immunIT/drupwn,Drupal security scanner."
}

function install_kubectl(){
  colorecho "Installing kubectl"
  mkdir -p /opt/tools/kubectl
  cd /opt/tools/kubectl || exit
  if [[ $(uname -m) = 'x86_64' ]]
  then
    curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
  elif [[ $(uname -m) = 'aarch64' ]]
  then
    curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/arm64/kubectl"
  elif [[ $(uname -m) = 'armv7l' ]]
  then
    curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/arm/kubectl"
  else
    criticalecho-noexit "This installation function doesn't support architecture $(uname -m)" && return
  fi
  install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl
  add-test-command "kubectl --help"
  add-to-list "kubectl,https://kubernetes.io/docs/reference/kubectl/overview/,Command-line interface for managing Kubernetes clusters."
}

function install_awscli(){
  colorecho "Installing aws cli"
  cd /tmp || exit
  if [[ $(uname -m) = 'x86_64' ]]
  then
    curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
  elif [[ $(uname -m) = 'aarch64' ]]
  then
    curl "https://awscli.amazonaws.com/awscli-exe-linux-aarch64.zip" -o "awscliv2.zip"
  else
    criticalecho-noexit "This installation function doesn't support architecture $(uname -m)" && return
  fi
  unzip awscliv2.zip
  ./aws/install -i /opt/tools/aws-cli -b /usr/local/bin
  rm -rf aws
  rm awscliv2.zip
  add-test-command "aws --version"
  add-to-list "awscli,https://aws.amazon.com/cli/,Command-line interface for Amazon Web Services."
}

function install_scout() {
  colorecho "Installing ScoutSuite"
  python3 -m pipx install scoutsuite
  add-test-command "scout --help"
  add-to-list "scout,TODO,TODO"
}

function install_jdwp_shellifier(){
  colorecho "Installing jdwp_shellifier"
  git -C /opt/tools/ clone https://github.com/IOActive/jdwp-shellifier
  add-aliases jdwp-shellifier
  add-test-command "jdwp-shellifier.py --help"
  add-to-list "jdwp,https://github.com/IOActive/jdwp-shellifier,This exploitation script is meant to be used by pentesters against active JDWP service, in order to gain Remote Code Execution."
}

function install_maigret() {
  colorecho "Installing maigret"
  python3 -m pipx install git+https://github.com/soxoj/maigret.git
  add-history maigret
  add-test-command "maigret --help"
  add-to-list "maigret,https://github.com/soxoj/maigret,Collects information about a target email (or domain) from Google and Bing search results"
}

function install_amber() {
  colorecho "Installing amber"
  # Installing keystone requirement
  git -C /opt/tools/ clone https://github.com/EgeBalci/keystone
  cd /opt/tools/keystone/ || exit
  mkdir build
  cd build || exit
  ../make-lib.sh
  cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF -DLLVM_TARGETS_TO_BUILD="AArch64;X86" -G "Unix Makefiles" ..
  make -j8
  make install && ldconfig
  # Installing amber
  go install -v github.com/EgeBalci/amber@latest
  add-history amber
  add-test-command "amber --help"
  add-to-list "amber,https://github.com/EgeBalci/amber,Forensic tool to recover browser history, cookies, and credentials"
}

function install_hashonymize() {
  colorecho "Installing hashonymizer"
  python3 -m pipx install git+https://github.com/ShutdownRepo/hashonymize
  add-test-command "hashonymize --help"
  add-to-list "hashonymize,https://github.com/ShutdownRepo/hashonymize,This small tool is aimed at anonymizing hashes files for offline but online cracking like Google Collab for instance (see https://github.com/ShutdownRepo/google-colab-hashcat)."
}

function install_theharvester() {
  colorecho "Installing theHarvester"
  git -C /opt/tools/ clone https://github.com/laramies/theHarvester
  python3 -m pip install -r theHarvester/requirements.txt
  add-aliases theharvester
  add-history theharvester
  add-to-list "theharvester,https://github.com/laramies/theHarvester,Tool for gathering e-mail accounts, subdomain names, virtual hosts, open ports/ banners, and employee names from different public sources"
}

function install_libusb-dev() {
  colorecho "Installing libusb-dev"
  fapt libusb-dev
  add-test-command "dpkg -l libusb-dev | grep 'libusb-dev'"

  add-to-list "libusb-dev,https://github.com/libusb/libusb,Library for USB device access"
}

function install_autoconf() {
  colorecho "Installing autoconf"
  fapt autoconf
  add-test-command "autoconf --version"
  add-to-list "autoconf,https://www.gnu.org/software/autoconf/autoconf.html,Tool for producing shell scripts to configure source code packages"
}

function install_nfct() {
  colorecho "Installing nfct"
  fapt nfct
  add-test-command "nfct --help |& grep 'nfct command'"
  add-to-list "nfct,https://github.com/grundid/nfctools,Tool for Near Field Communication (NFC) devices"
}

function install_pcsc() {
  colorecho "Installing tools for PC/SC (smartcard)"
  apt-get install -y pcsc-tools pcscd libpcsclite-dev libpcsclite1
  add-test-command "pcsc_scan -V"
  add-to-list "pcsc,https://pcsclite.apdu.fr/,Middleware for smart card readers"
}

function install_libnfc() {
  colorecho "Installing libnfc"
  apt-get install -y libnfc-dev libnfc-bin
  # FIXME
  #cd /opt/tools/
  #wget http://dl.bintray.com/nfc-tools/sources/libnfc-1.7.1.tar.bz2 #broken link
  #tar xjf libnfc-1.7.1.tar.bz2
  #cd libnfc-1.7.1
  #./configure --with-drivers=all
  #make
  #make install
  #ldconfig
  #cd ../
  #rm libnfc-1.7.1.tar.bz2
  add-history libnfc
  add-test-command "nfc-scan-device -h"
  add-to-list "libnfc,https://github.com/grundid/nfctools,Library for Near Field Communication (NFC) devices"
}

function install_mfoc() {
  colorecho "Installing mfoc"
  git -C /opt/tools/ clone https://github.com/nfc-tools/mfoc
  cd /opt/tools/mfoc || exit
  autoreconf -vis
  ./configure
  make
  make install
  add-history mfoc
  add-test-command "mfoc -h"
  add-to-list "mfoc,https://github.com/nfc-tools/mfoc,Implementation of 'offline nested' attack by Nethemba"
}

function install_mfcuk() {
  colorecho "Installing mfcuk"
  fapt mfcuk
  add-test-command "mfcuk -i whatever"
  add-to-list "mfcuk,https://github.com/nfc-tools/mfcuk,Implementation of an attack on Mifare Classic and Plus RFID cards"
}

function install_libnfc-crypto1-crack() {
  colorecho "Installing libnfc-crypto1-crack"
  git -C /opt/tools/ clone https://github.com/aczid/crypto1_bs
  cd /opt/tools/crypto1_bs || exit
  wget https://github.com/droidnewbie2/acr122uNFC/raw/master/crapto1-v3.3.tar.xz
  wget https://github.com/droidnewbie2/acr122uNFC/raw/master/craptev1-v1.1.tar.xz
  xz -d craptev1-v1.1.tar.xz crapto1-v3.3.tar.xz
  tar xvf craptev1-v1.1.tar
  tar xvf crapto1-v3.3.tar --one-top-level
  make CFLAGS=-"-std=gnu99 -O3 -march=native -Wl,--allow-multiple-definition"
  cp libnfc_crypto1_crack /opt/tools/bin
  add-aliases libnfc-crypto1-crack
  add-history libnfc-crypto1-crack
  add-test-command "libnfc_crypto1_crack --help |& grep 'libnfc.buses'"
  add-to-list "libnfc-crypto1-crack,https://github.com/droidnewbie2/acr122uNFC,Implementation of cryptographic attack on Mifare Classic RFID cards"
}

function install_mfdread() {
  colorecho "Installing mfdread"
  pip3 install bitstring
  git -C /opt/tools/ clone https://github.com/zhovner/mfdread
  add-aliases mfdread
  add-history mfdread
  add-test-command "mfdread /opt/tools/mfdread/dump.mfd"
  add-to-list "mfdread,https://github.com/zhovner/mfdread,Tool for reading/writing Mifare RFID tags"
}

function install_mousejack() {
  colorecho "Installing mousejack"
  apt-get -y install sdcc binutils python git
  python-pip
  git -C /opt/tools/ clone https://github.com/BastilleResearch/mousejack
  cd /opt/tools/mousejack || exit
  git submodule init
  git submodule update
  cd nrf-research-firmware || exit
  make
  add-aliases mousejack
  add-history mousejack
  add-test-command "nrf24-scanner.py --help"
  add-test-command "nrf24-sniffer.py --help"
  add-test-command "nrf24-network-mapper.py --help"
  add-to-list "mousejack,https://github.com/BastilleResearch/mousejack,Exploit to take over a wireless mouse and keyboard"
}

function install_jackit() {
  colorecho "Installing jackit"
  git -C /opt/tools/ clone https://github.com/insecurityofthings/jackit
  cd /opt/tools/jackit || exit
  python -m pip install .
  add-history jackit
  add-test-command "jackit --help"
  add-to-list "jackit,https://github.com/insecurityofthings/jackit,Exploit to take over a wireless mouse and keyboard"
}

function install_gosecretsdump() {
  colorecho "Installing gosecretsdump"
  git -C /opt/tools/ clone https://github.com/c-sto/gosecretsdump
  go install -v github.com/C-Sto/gosecretsdump@latest
  add-history gosecretsdump
  add-test-command "gosecretsdump -version"
  add-to-list "gosecretsdump,https://github.com/c-sto/gosecretsdump,Implements NTLMSSP network authentication protocol in Go"
}

function install_hackrf() {
  colorecho "Installing HackRF tools"
  apt-get -y install hackrf
  add-test-command "hackrf_debug --help"
  add-to-list "hackrf,https://github.com/mossmann/hackrf,Low cost software defined radio platform"
}

function install_gqrx() {
  colorecho "Installing gqrx"
  apt-get -y install gqrx-sdr
  # test below cannot work because test runner cannot have a valid display
  # add-test-command "gqrx --help"
  add-test-command "which gqrx"
  add-to-list "gqrx,https://github.com/csete/gqrx,Software defined radio receiver powered by GNU Radio and Qt"
}

function install_rtl-433() {
  colorecho "Installing rtl-433"
  fapt rtl-433
  add-test-command "dpkg -l rtl-433 | grep 'rtl-433'"
  add-to-list "rtl-433,https://github.com/merbanan/rtl_433,Tool for decoding various wireless protocols/ signals such as those used by weather stations"
}

function install_sipvicious() {
  colorecho "Installing SIPVicious"
  git -C /opt/tools/ clone https://github.com/enablesecurity/sipvicious.git
  cd /opt/tools/sipvicious/ || exit
  python3 setup.py install
  add-test-command "sipvicious_svcrack --version"
  add-to-list "sipvicious,https://github.com/enablesecurity/sipvicious,Enumeration and MITM tool for SIP devices"
}

function install_httpmethods() {
  colorecho "Installing httpmethods"
  git -C /opt/tools/ clone https://github.com/ShutdownRepo/httpmethods
  cd /opt/tools/httpmethods || exit
  python3 setup.py install
  add-history httpmethods
  add-test-command "httpmethods --help"
  add-to-list "httpmethods,https://github.com/ShutdownRepo/httpmethods,Tool for exploiting HTTP methods (e.g. PUT, DELETE, etc.)"
}

function install_adidnsdump() {
  colorecho "Installing adidnsdump"
  python3 -m pipx install git+https://github.com/dirkjanm/adidnsdump
  add-history adidnsdump
  add-test-command "adidnsdump --help"
  add-to-list "adidnsdump,https://github.com/dirkjanm/adidnsdump,Active Directory Integrated DNS dump utility"
}

function install_dnschef() {
  colorecho "Installing DNSChef"
  git -C /opt/tools/ clone https://github.com/iphelix/dnschef
  python3 -m pip install -r /opt/tools/dnschef/requirements.txt
  add-aliases dnschef
  add-test-command "dnschef --help"
  add-to-list "dnschef,https://github.com/iphelix/dnschef,Tool for DNS MITM attacks"
}

function install_h2csmuggler() {
  colorecho "Installing h2csmuggler"
  git -C /opt/tools/ clone https://github.com/BishopFox/h2csmuggler
  python3 -m pip install h2
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

function install_pipx() {
  colorecho "Installing pipx"
  python3 -m pip install pipx
  pipx ensurepath
  add-test-command "pipx --version"
  add-to-list "pipx,https://github.com/pipxproject/pipx,Execute binaries from Python packages in isolated environments"
}

function install_peepdf() {
  colorecho "Installing peepdf"
  fapt libjpeg-dev
  python2.7 -m pip install peepdf
  add-to-list "peepdf,https://github.com/jesparza/peepdf,Powerful Python tool to analyze and investigate PDF files"
}

function install_volatility2() {
  colorecho "Installing volatility"
  apt-get -y install pcregrep libpcre++-dev python2-dev yara
  git -C /opt/tools/ clone https://github.com/volatilityfoundation/volatility
  cd /opt/tools/volatility || exit
  python -m pip install pycrypto distorm3 pillow openpyxl ujson
  python setup.py install
  # https://github.com/volatilityfoundation/volatility/issues/535#issuecomment-407571161
  ln -s /usr/local/lib/python2.7/dist-packages/usr/lib/libyara.so /usr/lib/libyara.so
  add-aliases volatility2
  add-test-command "volatility2 --help"
  add-to-list "volatility2,https://github.com/volatilityfoundation/volatility,Volatile memory extraction utility framework"
}

function install_volatility3() {
  colorecho "Installing volatility3"
  python3 -m pipx install git+https://github.com/volatilityfoundation/volatility3
  add-aliases volatility3
  add-history volatility3
  add-test-command "volatility3 --help"
  add-to-list "volatility3,https://github.com/volatilityfoundation/volatility3,Advanced memory forensics framework"
}

function install_testdisk() {
  colorecho "Installing testdisk"
  fapt testdisk
  add-history testdisk
  add-test-command "testdisk --help"
  add-to-list "testdisk,https://github.com/cgsecurity/testdisk,Partition recovery and file undelete utility"
}

function install_jadx() {
  colorecho "Installing jadx"
  git -C /opt/tools/ clone https://github.com/skylot/jadx.git
  cd /opt/tools/jadx
  ./gradlew dist
  ln -v -s /opt/tools/jadx/build/jadx/bin/jadx /opt/tools/bin/jadx
  ln -v -s /opt/tools/jadx/build/jadx/bin/jadx-gui /opt/tools/bin/jadx-gui
  add-history jadx
  add-test-command "jadx --help"
  add-to-list "jadx,https://github.com/skylot/jadx,Java decompiler"
}

function install_fdisk() {
  colorecho "Installing fdisk"
  fapt fdisk
  add-history fdisk
  add-test-command "fdisk --help"
  add-to-list "fdisk,https://github.com/karelzak/util-linux,Collection of basic system utilities, including fdisk partitioning tool"
}

function install_sleuthkit() {
  colorecho "Installing sleuthkit"
  fapt sleuthkit
  add-test-command "blkcalc -V"
  add-to-list "sleuthkit,https://github.com/sleuthkit/sleuthkit,Forensic toolkit to analyze volume and file system data"
}

function install_zsteg() {
  colorecho "Installing zsteg"
  gem install zsteg
  add-test-command "zsteg --help"
  add-to-list "zsteg,https://github.com/zed-0xff/zsteg,Detect steganography hidden in PNG and BMP images"
}

function install_exif() {
  colorecho "Installing exif"
  fapt exif
  add-history exif
  add-test-command "exif --help"
  add-to-list "exif,https://exiftool.org/,Utility to read, write and edit metadata in image, audio and video files"
}

function install_exiv2() {
  colorecho "Installing exiv2"
  fapt exiv2
  add-history exiv2
  add-test-command "exiv2 --help"
  add-to-list "exiv2,https://github.com/Exiv2/exiv2,Image metadata library and toolset"
}

function install_hexedit() {
  colorecho "Installing hexedit"
  fapt hexedit
  add-history hexedit
  add-test-command "hexedit --help|& grep 'usage: hexedit'"
  add-to-list "hexedit,https://github.com/pixel/hexedit,View and edit binary files"
}

function install_stegolsb() {
  colorecho "Installing stegolsb"
  python3 -m pipx install stego-lsb
  add-test-command "stegolsb --version"
  add-to-list "stegolsb,https://github.com/KyTn/STEGOLSB,Steganography tool to hide data in BMP images using least significant bit algorithm"
}

function install_whatportis() {
  colorecho "Installing whatportis"
  python3 -m pipx install whatportis
  echo y | whatportis --update
  add-history whatportis
  add-test-command "whatportis --version"
  add-to-list "whatportis,https://github.com/ncrocfer/whatportis,Command-line tool to lookup port information"
}

function install_ultimate_vimrc() {
  colorecho "Installing The Ultimate vimrc"
  git clone --depth=1 https://github.com/amix/vimrc.git ~/.vim_runtime
  sh ~/.vim_runtime/install_awesome_vimrc.sh
  add-to-list "ultimate,https://github.com/amix/vimrc.git,Vim in steroids."
}

function install_ngrok() {
  colorecho "Installing ngrok"
  if [[ $(uname -m) = 'x86_64' ]]
  then
    wget -O /tmp/ngrok.zip https://bin.equinox.io/c/4VmDzA7iaHb/ngrok-stable-linux-amd64.zip
  elif [[ $(uname -m) = 'aarch64' ]]
  then
    wget -O /tmp/ngrok.zip https://bin.equinox.io/c/4VmDzA7iaHb/ngrok-stable-linux-arm64.zip
  elif [[ $(uname -m) = 'armv7l' ]]
  then
    wget -O /tmp/ngrok.zip https://bin.equinox.io/c/4VmDzA7iaHb/ngrok-stable-linux-arm.zip
  else
    criticalecho-noexit "This installation function doesn't support architecture $(uname -m)" && return
  fi
  unzip -d /opt/tools/bin/ /tmp/ngrok.zip
  add-history ngrok
  add-test-command "ngrok version"
  add-to-list "ngrok,https://github.com/inconshreveable/ngrok,Expose a local server behind a NAT or firewall to the internet"
}

function install_chisel() {
  colorecho "Installing chisel"
  go install -v github.com/jpillora/chisel@latest
  # TODO: add windows pre-compiled binaries in /opt/ressources/windows?
  add-test-command "chisel --help"
  add-to-list "chisel,https://github.com/jpillora/chisel,Go based TCP tunnel, with authentication and encryption support"
}

function install_sshuttle() {
  colorecho "Installing sshtuttle"
  git -C /opt/tools/ clone https://github.com/sshuttle/sshuttle.git
  cd /opt/tools/sshuttle || exit
  python3 setup.py install
  add-test-command "sshuttle --version"
  add-to-list "sshuttle,https://github.com/sshuttle/sshuttle,Transparent proxy server that tunnels traffic through an SSH server"
}

function install_pygpoabuse() {
  colorecho "Installing pyGPOabuse"
  git -C /opt/tools/ clone https://github.com/Hackndo/pyGPOAbuse
  python3 -m pip install -r /opt/tools/pyGPOAbuse/requirements.txt
  add-aliases pygpoabuse
  add-test-command "pygpoabuse --help"
  add-to-list "pygpoabuse,https://github.com/Hackndo/pyGPOAbuse,A tool for abusing GPO permissions to escalate privileges"
}

function install_rsactftool() {
  colorecho "Installing RsaCtfTool"
  git -C /opt/tools/ clone https://github.com/Ganapati/RsaCtfTool
  cd /opt/tools/RsaCtfTool || exit
  apt-get -y install libgmp3-dev libmpc-dev
  python3 -m pip install -r requirements.txt
  add-aliases rsactftool
  add-to-list "rsactftool,https://github.com/Ganapati/RsaCtfTool,Tool for performing RSA attack and decrypting encrypted RSA message"
}

function install_feroxbuster() {
  colorecho "Installing feroxbuster"
  mkdir /opt/tools/feroxbuster
  cd /opt/tools/feroxbuster || exit
  curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/master/install-nix.sh | bash
  # Adding a symbolic link in order for autorecon to be able to find the Feroxbuster binary
  ln -s /opt/tools/feroxbuster/feroxbuster /opt/tools/bin/feroxbuster
  add-aliases feroxbuster
  add-history feroxbuster
  add-test-command "feroxbuster --help"
  add-to-list "feroxbuster,https://github.com/epi052/feroxbuster,Simple, fast and recursive content discovery tool"
}

function install_bloodhound-import() {
  colorecho "Installing bloodhound-import"
  python3 -m pipx install bloodhound-import
  add-history bloodhound-import
  add-test-command "bloodhound-import --help"
  add-to-list "bloodhound-import,https://github.com/fox-it/BloodHound.py,Import data into BloodHound for analyzing active directory trust relationships"
}

function install_bloodhound-quickwin() {
  colorecho "Installing bloodhound-quickwin"
  python3 -m pip install py2neo pandas prettytable
  git -C /opt/tools/ clone https://github.com/kaluche/bloodhound-quickwin
  add-aliases bloodhound-quickwin
  add-history bloodhound-quickwin
  add-test-command "bloodhound-quickwin --help"
  add-to-list "bloodhound-quickwin,https://github.com/kaluche/bloodhound-quickwin,A tool for BloodHounding on Windows machines without .NET or Powershell installed"
}

function install_ldapsearch() {
  colorecho "Installing ldapsearch"
  fapt ldap-utils
  add-history ldapsearch
  add-test-command "ldapsearch --help; ldapsearch --help |& grep 'Search options'"
}

function install_ldapsearch-ad() {
  colorecho "Installing ldapsearch-ad"
  git -C /opt/tools/ clone https://github.com/yaap7/ldapsearch-ad
  cd /opt/tools/ldapsearch-ad/ || exit
  python3 -m pip install -r requirements.txt
  add-aliases ldapsearch-ad
  add-history ldapsearch-ad
  add-test-command "ldapsearch-ad --version"
  add-to-list "ldapsearch-ad,https://github.com/yaap7/ldapsearch-ad,LDAP search utility with AD support"
}

function install_rustscan() {
  colorecho "Installing RustScan"
  source "$HOME/.cargo/env"
  cargo install rustscan
  add-to-list "rustscan,https://github.com/RustScan/RustScan,Fast port scanner"
}

function install_divideandscan() {
  colorecho "Installing DivideAndScan"
  python3 -m pipx install git+https://github.com/snovvcrash/DivideAndScan
  add-history divideandscan
  add-test-command "divideandscan --help"
  add-to-list "divideandscan,https://github.com/snovvcrash/divideandscan,Advanced subdomain scanner"
}

function install_iptables() {
  colorecho "Installing iptables"
  fapt iptables
  add-test-command "iptables --version"
  add-to-list "iptables,https://linux.die.net/man/8/iptables,Userspace command line tool for configuring kernel firewall"
}

function install_trid() {
  colorecho "Installing trid"
  mkdir /opt/tools/trid/
  cd /opt/tools/trid || exit
  wget https://mark0.net/download/tridupdate.zip
  wget https://mark0.net/download/triddefs.zip
  wget https://mark0.net/download/trid_linux_64.zip
  unzip trid_linux_64.zip
  unzip triddefs.zip
  unzip tridupdate.zip
  rm tridupdate.zip triddefs.zip trid_linux_64.zip
  chmod +x trid
  python3 tridupdate.py
  add-aliases trid
  add-test-command "trid '-?'; trid | grep 'This help'"
  add-to-list "trid,https://mark0.net/soft-trid-e.html,File identifier"
}

function install_pcredz() {
  colorecho "Installing PCredz"
  python3 -m pip install Cython
  fapt libpcap-dev
  python3 -m pip install Cython python-libpcap
  git -C /opt/tools/ clone https://github.com/lgandx/PCredz
  add-aliases pcredz
  add-test-command "PCredz --help"
  add-to-list "pcredz,https://github.com/lgandx/PCredz,PowerShell credential dumper"
}

function install_smartbrute() {
  colorecho "Installing smartbrute"
  python3 -m pipx install git+https://github.com/ShutdownRepo/smartbrute
  add-history smartbrute
  add-test-command "smartbrute --help"
  add-to-list "smartbrute,https://github.com/ShutdownRepo/SmartBrute,The smart password spraying and bruteforcing tool for Active Directory Domain Services."
}

function install_frida() {
  colorecho "Installing frida"
  python3 -m pipx install frida-tools
  add-test-command "frida --version"
  add-to-list "frida,https://github.com/frida/frida,Dynamic instrumentation toolkit"
}

function install_objection() {
  colorecho "Installing objection"
  python3 -m pipx install git+https://github.com/sensepost/objection
  add-history objection
  add-test-command "objection --help"
  add-to-list "objection,https://github.com/sensepost/objection,Runtime mobile exploration"
}

function install_androguard() {
  colorecho "Installing androguard"
  python3 -m pipx install androguard
  add-test-command "androguard --version"
  add-to-list "androguard,https://github.com/androguard/androguard,Reverse engineering and analysis of Android applications"
}

function install_petitpotam() {
  colorecho "Installing PetitPotam"
  git -C /opt/tools/ clone https://github.com/ly4k/PetitPotam
  mv /opt/tools/PetitPotam /opt/tools/PetitPotam_alt
  git -C /opt/tools/ clone https://github.com/topotam/PetitPotam
  add-aliases petitpotam
  add-history petitpotam
  add-test-command "petitpotam.py --help"
  add-to-list "petitpotam,https://github.com/topotam/PetitPotam,Windows machine account manipulation"
}

function install_dfscoerce() {
  colorecho "Installing DfsCoerce"
  git -C /opt/tools/ clone https://github.com/Wh04m1001/DFSCoerce.git
  add-aliases dfscoerce
  add-history dfscoerce
  add-test-command "dfscoerce.py --help"
  add-to-list "dfscoerce,https://github.com/Wh04m1001/dfscoerce,DFS-R target coercion tool"
}

function install_coercer() {
  colorecho "Installing Coercer"
  python3 -m pipx install git+https://github.com/p0dalirius/Coercer
  add-history coercer
  add-test-command "coercer --help"
  add-to-list "coercer,https://github.com/p0dalirius/coercer,DFS-R target coercion tool"
}

function install_pkinittools() {
  colorecho "Installing PKINITtools"
  git -C /opt/tools/ clone https://github.com/dirkjanm/PKINITtools
  add-aliases pkinittools
  add-history pkinittools
  add-test-command "gettgtpkinit.py --help"
  add-to-list "pkinittools,https://github.com/dirkjanm/PKINITtools,Pkinit support tools"
}

function install_pywhisker() {
  colorecho "Installing pyWhisker"
  git -C /opt/tools/ clone https://github.com/ShutdownRepo/pywhisker
  cd /opt/tools/pywhisker || exit
  python3 -m pip install -r requirements.txt
  add-aliases pywhisker
  add-history pywhisker
  add-test-command "pywhisker.py --help"
  add-to-list "pywhisker,https://github.com/ShutdownRepo/pywhisker,PyWhisker is a Python equivalent of the original Whisker made by Elad Shamir and written in C#. This tool allows users to manipulate the msDS-KeyCredentialLink attribute of a target user/computer to obtain full control over that object. It's based on Impacket and on a Python equivalent of Michael Grafnetter's DSInternals called PyDSInternals made by podalirius."
}

function install_targetedKerberoast() {
  colorecho "Installing targetedKerberoast"
  git -C /opt/tools/ clone https://github.com/ShutdownRepo/targetedKerberoast
  cd /opt/tools/targetedKerberoast || exit
  python3 -m pip install -r requirements.txt
  add-aliases targetedkerberoast
  add-history targetedkerberoast
  add-test-command "targetedKerberoast.py --help"
  add-to-list "targetedKerberoast,https://github.com/ShutdownRepo/targetedKerberoast,Kerberoasting against specific accounts"
}

function install_manspider() {
  colorecho "Installing MANSPIDER"
  python3 -m pipx install git+https://github.com/blacklanternsecurity/MANSPIDER
  add-history manspider
  add-test-command "manspider --help"
  add-to-list "manspider,https://github.com/blacklanternsecurity/manspider,Crawl SMB shares for juicy information. File content searching."
}

function install_pywsus() {
  colorecho "Installing pywsus"
  git -C /opt/tools/ clone https://github.com/GoSecure/pywsus
  cd /opt/tools/pywsus || exit
  #virtualenv -p /usr/bin/python3 ./venv
  #source ./venv/bin/activate
  python3 -m pip install -r ./requirements.txt
  add-aliases pywsus
  add-history pywsus
  add-test-command "pywsus.py --help"
  add-to-list "pywsus,https://github.com/GoSecure/pywsus,Python implementation of a WSUS client"
}

function install_ignorant() {
  colorecho "Installing ignorant"
  python3 -m pipx install git+https://github.com/megadose/ignorant
  add-to-list "ignorant,https://github.com/megadose/ignorant,Ignorant allows you to check if a phone number is used on different sites like snapchat, instagram."
}

function install_donpapi() {
  colorecho "Installing DonPAPI"
  git -C /opt/tools/ clone https://github.com/login-securite/DonPAPI.git
  python3 -m pip install -r /opt/tools/DonPAPI/requirements.txt
  add-aliases donpapi
  add-history donpapi
  add-test-command "DonPAPI.py --help"
  add-to-list "donpapi,https://github.com/login-securite/DonPAPI,Python network and web application scanner"
}

function install_gau() {
  colorecho "Installing gau"
  GO111MODULE=on go install -v github.com/lc/gau@latest
  add-test-command "gau --help"
  add-to-list "gau,https://github.com/lc/gau,Fast tool for fetching URLs"
}

function install_webclientservicescanner() {
  colorecho "Installing webclientservicescanner"
  python3 -m pipx install git+https://github.com/Hackndo/WebclientServiceScanner
  add-history webclientservicescanner
  add-test-command "webclientservicescanner --help"
  add-to-list "webclientservicescanner,https://github.com/Hackndo/webclientservicescanner,Scans for web service endpoints"
}

function install_certipy() {
  colorecho "Installing Certipy"
  python3 -m pipx install git+https://github.com/ly4k/Certipy
  add-history certipy
  add-test-command "certipy --version"
  add-to-list "certipy,https://github.com/ly4k/Certipy,Python tool to create and sign certificates"
}

function install_eaphammer() {
  # Debian port : working ?
  colorecho "Installing EPA hammer"
  git -C /opt/tools/ clone https://github.com/s0lst1c3/eaphammer
  cd /opt/tools/eaphammer || exit
  echo y | ./kali-setup
  add-aliases eaphammer
  add-test-command "eaphammer --help"
  add-to-list "eaphammer,https://github.com/s0lst1c3/eaphammer,Targeted evil twin attacks against WPA2-Enterprise networks"
}

function install_vulny-code-static-analysis() {
  colorecho "Installing Vulny Code Static Analysis"
  git -C /opt/tools/ clone https://github.com/swisskyrepo/Vulny-Code-Static-Analysis
  add-aliases vulny-code-static-analysis
  add-test-command "vulny-code-static-analysis --help"
  add-to-list "vulny-code-static-analysis,https://github.com/swisskyrepo/Vulny-Code-Static-Analysis,Static analysis tool for C code"
}

function install_brakeman() {
  colorecho "Installing Brakeman"
  gem install brakeman
  add-history brakeman
  add-test-command "brakeman --help"
  add-to-list "brakeman,https://github.com/presidentbeef/brakeman,Static analysis tool for Ruby on Rails applications"
}

function install_semgrep() {
  colorecho "Installing semgrep"
  python3 -m pipx install semgrep
  add-history semgrep
  add-test-command "semgrep --help"
  add-to-list "semgrep,https://github.com/returntocorp/semgrep/,Static analysis tool that supports multiple languages and can find a variety of vulnerabilities and coding errors."
}

function install_nuclei() {
  # Vulnerability scanner
  colorecho "Installing Nuclei"
  go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
  nuclei -update-templates
  add-history nuclei
  add-test-command "nuclei --version"
  add-to-list "nuclei,https://github.com/projectdiscovery/nuclei,A fast and customizable vulnerability scanner that can detect a wide range of issues, including XSS, SQL injection, and misconfigured servers."
}

function install_prips() {
  # Print the IP addresses in a given range
  colorecho "Installing Prips"
  fapt prips
  add-history prips
  add-test-command "prips --help"
  add-to-list "prips,https://manpages.ubuntu.com/manpages/focal/man1/prips.1.html,A utility for quickly generating IP ranges or enumerating hosts within a specified range."
}

function install_hakrevdns() {
  # Reverse DNS lookups
  colorecho "Installing Hakrevdns"
  go install -v github.com/hakluke/hakrevdns@latest
  add-history hakrevdns
  add-test-command "hakrevdns --help; hakrevdns --help |& grep 'Protocol to use for lookups'"
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

function install_dnsx() {
  colorecho "Installing dnsx"
  go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
  add-history dnsx
  add-test-command "dnsx --help"
  add-to-list "dnsx,https://github.com/projectdiscovery/dnsx,A tool for DNS reconnaissance that can help identify subdomains and other related domains."
}

function install_shuffledns() {
  colorecho "Installing shuffledns"
  go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest
  add-history shuffledns
  add-test-command "shuffledns --help"
  add-to-list "shuffledns,https://github.com/projectdiscovery/shuffledns,A fast and customizable DNS resolver that can be used for subdomain enumeration and other tasks."
}

function install_tailscale() {
  curl -fsSL https://pkgs.tailscale.com/stable/ubuntu/focal.gpg | sudo apt-key add -
  curl -fsSL https://pkgs.tailscale.com/stable/ubuntu/focal.list | sudo tee /etc/apt/sources.list.d/tailscale.list
  apt-get update
  fapt tailscale
  add-aliases tailscale
  add-history tailscale
  add-test-command "tailscale --help"
  add-to-list "tailscale,https://github.com/tailscale/tailscale,A secure and easy-to-use VPN alternative that is designed for teams and businesses."
}

function install_ligolo-ng() {
  colorecho "Installing ligolo-ng"
  git -C /opt/tools/ clone https://github.com/nicocha30/ligolo-ng.git
  cd /opt/tools/ligolo-ng
  go build -o agent cmd/agent/main.go
  go build -o proxy cmd/proxy/main.go
  GOOS=windows go build -o agent.exe cmd/agent/main.go
  GOOS=windows go build -o proxy.exe cmd/proxy/main.go
  ln -v -s /opt/tools/ligolo-ng/agent /opt/tools/bin/ligolo-agent
  ln -v -s /opt/tools/ligolo-ng/proxy /opt/tools/bin/ligolo-proxy
  add-test-command "ligolo-agent --help"
  add-test-command "ligolo-proxy --help"
  add-to-list "ligolo-ng,https://github.com/nicocha30/ligolo-ng,An advanced subdomain scanner that supports multiple sources and can detect a wide range of issues, including expired domains and misconfigured servers."
}

function install_anew() {
  colorecho "Installing anew"
  go install -v github.com/tomnomnom/anew@latest
  add-test-command "anew --help"
  add-to-list "anew,https://github.com/tomnomnom/anew,A simple tool for filtering and manipulating text data, such as log files and other outputs."
}

function install_naabu() {
  colorecho "Installing naabu"
  apt-get install -y libpcap-dev
  go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
  add-test-command "naabu --help"
  add-to-list "naabu,https://github.com/projectdiscovery/naabu,A fast and reliable port scanner that can detect open ports and services."
}

function install_tor() {
  colorecho "Installing tor"
  fapt tor
  echo 'SOCKSPort 127.0.0.1:9050' >> /etc/tor/torrc
  add-test-command "service tor start"
  add-to-list "tor,https://github.com/torproject/tor,Anonymity tool that can help protect your privacy and online identity by routing your traffic through a network of servers."
}

function install_torbrowser() {
  colorecho "Installing torbrowser"
  # TODO : also need to find out how to install for ARM
  # TODO add-test-command
  # add-to-list "torbrowser,https://github.com/torproject/torbrowser-releases/releases,Web browser that is designed to work with the Tor network and provide anonymous browsing."
}

function install_pwndb() {
  colorecho "Installing pwndb"
  git -C /opt/tools/ clone https://github.com/davidtavarez/pwndb.git
  cd /opt/tools/pwndb || exit
  chmod +x pwndb.py
  add-aliases pwndb
  add-history pwndb
  add-test-command "pwndb --help"
  add-to-list "pwndb,https://github.com/davidtavarez/pwndb,A command-line tool for searching the pwndb database of compromised credentials."
}

function install_robotstester() {
  # This Python script can enumerate all URLs present in robots.txt files, and test whether they can be accessed or not.
  # https://github.com/p0dalirius/robotstester
  colorecho "Installing Robotstester"
  python3 -m pipx install git+https://github.com/p0dalirius/robotstester
  add-history robotstester
  add-test-command "robotstester --help"
  add-to-list "robotstester,https://github.com/p0dalirius/robotstester,Utility for testing whether a website's robots.txt file is correctly configured."
}

function install_finduncommonshares() {
  colorecho "Installing FindUncommonShares"
  git -C /opt/tools/ clone https://github.com/p0dalirius/FindUncommonShares
  cd /opt/tools/FindUncommonShares/ || exit
  python3 -m pip install -r requirements.txt
  add-aliases finduncommonshares
  add-history finduncommonshares
  add-test-command "FindUncommonShares.py --help"
  add-to-list "finduncommonshares,https://github.com/p0dalirius/FindUncommonShares,Script that can help identify shares that are not commonly found on a Windows system."
}

function install_shadowcoerce() {
  colorecho "Installing ShadowCoerce PoC"
  git -C /opt/tools/ clone https://github.com/ShutdownRepo/ShadowCoerce
  add-aliases shadowcoerce
  add-history shadowcoerce
  add-test-command "shadowcoerce.py --help"
  add-to-list "shadowcoerce,https://github.com/ShutdownRepo/shadowcoerce,Utility for bypassing the Windows Defender antivirus by hiding a process within a legitimate process."
}

function install_pwncat() {
  colorecho "Installing pwncat"
  python3 -m pipx install pwncat-cs
  add-test-command "pwncat-cs --version"
  add-to-list "pwncat,https://github.com/calebstewart/pwncat,A lightweight and versatile netcat alternative that includes various additional features."
}

function install_gmsadumper() {
  colorecho "Installing gMSADumper"
  git -C /opt/tools/ clone https://github.com/micahvandeusen/gMSADumper
  add-aliases gmsadumper
  add-history gmsadumper
  add-test-command "gMSADumper.py --help"
  add-to-list "gmsadumper,https://github.com/micahvandeusen/gMSADumper,A tool for extracting credentials and other information from a Microsoft Active Directory domain."
}

function install_pylaps() {
  colorecho "Installing pyLAPS"
  git -C /opt/tools/ clone https://github.com/p0dalirius/pyLAPS
  add-aliases pylaps
  add-history pylaps
  add-test-command "pyLAPS.py --help"
  add-to-list "pylaps,https://github.com/p0dalirius/pylaps,Utility for enumerating and querying LDAP servers."
}

function install_ldaprelayscan() {
  colorecho "Installing LdapRelayScan"
  git -C /opt/tools/ clone https://github.com/zyn3rgy/LdapRelayScan
  cd /opt/tools/LdapRelayScan || exit
  python3 -m pip install -r requirements.txt
  add-aliases ldaprelayscan
  add-history ldaprelayscan
  add-test-command "LdapRelayScan.py --help"
  add-to-list "ldaprelayscan,TODO,TODO"
}

function install_goldencopy() {
  colorecho "Installing GoldenCopy"
  python3 -m pipx install goldencopy
  add-history goldencopy
  add-test-command "goldencopy --help"
  add-to-list "goldencopy,https://github.com/0x09AL/golden_copy.git,A tool to copy data from Golden Ticket and Silver Ticket"
}

function install_crackhound() {
  colorecho "Installing CrackHound"
  git -C /opt/tools/ clone https://github.com/trustedsec/CrackHound
  cd /opt/tools/CrackHound
  prs="6"
  for pr in $prs; do git fetch origin pull/$pr/head:pull/$pr && git merge --strategy-option theirs --no-edit pull/$pr; done
  python3 -m pip install -r /opt/tools/CrackHound/requirements.txt
  add-aliases crackhound
  add-history crackhound
  add-test-command "crackhound.py --help"
  add-to-list "crackhound,https://github.com/trustedsec/crackhound.git,A fast WPA/WPA2/WPA3 WiFi Handshake capture, password recovery and analysis tool"
}

function install_kerbrute() {
  colorecho "Installing Kerbrute"
  go install github.com/ropnop/kerbrute@latest
  add-history kerbrute
  add-test-command "kerbrute --help"
  # FIXME ARM platforms install ?
  add-to-list "kerbrute,https://github.com/ropnop/kerbrute,A tool to perform Kerberos pre-auth bruteforcing"
}

function install_searchsploit() {
  colorecho "Installing Searchsploit"
  git -C /opt/tools/ clone https://gitlab.com/exploit-database/exploitdb
  ln -sf /opt/tools/exploitdb/searchsploit /opt/tools/bin/searchsploit
  cp -n /opt/tools/exploitdb/.searchsploit_rc ~/
  sed -i 's/\(.*[pP]aper.*\)/#\1/' ~/.searchsploit_rc
  sed -i 's/opt\/exploitdb/opt\/tools\/exploitdb/' ~/.searchsploit_rc
  searchsploit -u
  add-test-command "searchsploit --help; searchsploit --help |& grep 'You can use any number of search terms'"
  add-to-list "searchsploit,https://gitlab.com/exploit-database/exploitdb,A command line search tool for Exploit-DB"
}

function install_crunch() {
  colorecho "Installing crunch"
  fapt crunch
  add-test-command "crunch --help"
  add-to-list "crunch,https://github.com/crunchsec/crunch,A wordlist generator where you can specify a standard character set or a character set you specify."
}

function install_seclists(){
  colorecho "Installing Seclists"
  git -C /usr/share/ clone https://github.com/danielmiessler/SecLists.git seclists
  cd /usr/share/seclists || exit
  rm -r LICENSE .git* CONTRIBUT* .bin
  add-test-command "[ -d '/usr/share/seclists/Discovery/' ]"
  add-to-list "seclists,https://github.com/danielmiessler/SecLists,A collection of multiple types of lists used during security assessments"
}

function install_rockyou(){
  colorecho "Installing rockyou"
  mkdir /usr/share/wordlists
  tar -xvf /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt.tar.gz -C /usr/share/wordlists/
  ln -s /usr/share/seclists/ /usr/share/wordlists/seclists
  add-test-command "[ -f '/usr/share/wordlists/rockyou.txt' ]"
  add-to-list "rockyou,https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt,A password dictionary used by most hackers"
}

function install_amass(){
  colorecho "Installing Amass"
  set_go_env
  go install -v github.com/owasp-amass/amass/v3/...@master
  add-test-command "amass -version"
  add-to-list "amass,https://github.com/OWASP/Amass,A DNS enumeration, attack surface mapping & external assets discovery tool"
}

function install_maltego(){
  colorecho "Installing Maltego"
  wget https://maltego-downloads.s3.us-east-2.amazonaws.com/linux/Maltego.v4.3.0.deb -O /tmp/maltegov4.3_package.deb
  dpkg -i /tmp/maltegov4.3_package.deb
  # TODO add-test-command
  add-to-list "maltego,https://www.paterva.com/web7/downloads.php,A tool used for open-source intelligence and forensics"
}

function install_spiderfoot(){
  colorecho "Installing Spiderfoot"
  git -C /opt/tools/ clone https://github.com/smicallef/spiderfoot.git # depends on alias declaration in order to work
  python3 -m pip install -r /opt/tools/spiderfoot/requirements.txt
  add-aliases spiderfoot
  add-history spiderfoot
  add-test-command "spiderfoot --help"
  add-test-command "spiderfoot-cli --help"
  add-to-list "spiderfoot,https://github.com/smicallef/spiderfoot,A reconnaissance tool that automatically queries over 100 public data sources"
}

function install_finalrecon(){
  colorecho "Installing FinalRecon"
  git -C /opt/tools/ clone https://github.com/thewhiteh4t/FinalRecon
  cd /opt/tools/FinalRecon || exit
  python3 -m pip install -r requirements.txt
  add-aliases finalrecon
  add-test-command "finalrecon.py --help"
  add-to-list "finalrecon,https://github.com/thewhiteh4t/FinalRecon,A web reconnaissance tool that gathers information about web pages"
}

function install_xsser(){
  colorecho "Installing xsser"
  pip3 install pycurl bs4 pygeoip gobject cairocffi selenium
  add-to-list "xsser,https://github.com/epsylon/xsser,A tool to test for XSS vulnerability"
}

function install_joomscan(){
  colorecho "Installing joomscan"
  git -C /opt/tools/ clone https://github.com/rezasp/joomscan.git
  fapt libc6-dev gcc libcrypt-ssleay-perl openssl libssl-dev libz-dev
  cpanm Bundle::LWP
  cpanm LWP::Protocol::https
  add-aliases joomscan
  add-test-command "joomscan --version"
  add-to-list "joomscan,https://github.com/rezasp/joomscan,A tool to enumerate Joomla-based websites"
}

function install_wpscan(){
  colorecho "Installing wpscan"
  apt-get install -y procps ruby-dev
  apt-get install -y apt-transport-https ca-certificates gnupg2 curl
  curl -sSL https://rvm.io/pkuczynski.asc | gpg2 --import -
  curl -sSL https://get.rvm.io | bash -s stable --ruby
  gem install nokogiri -v 1.11.4 # use this version to resolve the conflict with cewl
  gem install wpscan
  add-history wpscan
  add-test-command "wpscan --help"
  add-to-list "wpscan,https://github.com/wpscanteam/wpscan,A tool to enumerate WordPress-based websites"
}

function install_go(){
  colorecho "Installing go (Golang)"
  cd /tmp/ || exit
  if [[ $(uname -m) = 'x86_64' ]]
  then
    wget -O /tmp/go.tar.gz https://go.dev/dl/go1.20.linux-amd64.tar.gz
  elif [[ $(uname -m) = 'aarch64' ]]
  then
    wget -O /tmp/go.tar.gz https://go.dev/dl/go1.20.linux-arm64.tar.gz
  elif [[ $(uname -m) = 'armv7l' ]]
  then
    wget -O /tmp/go.tar.gz https://go.dev/dl/go1.20.linux-armv6l.tar.gz
  else
    criticalecho-noexit "This installation function doesn't support architecture $(uname -m)" && return
  fi
  rm -rf /usr/local/go
  tar -C /usr/local -xzf /tmp/go.tar.gz
  export PATH=$PATH:/usr/local/go/bin
  add-test-command "go version"
  add-to-list "go,https://golang.org/doc/install,A programming language often used to create command line tools"
}

function install_metasploit(){
  colorecho "Installing Metasploit"
  #apt-get clean
  #zsh -c 'rm -rvf /var/lib/apt/lists/*'
  #apt-get update
  mkdir /tmp/metasploit_install
  cd /tmp/metasploit_install || exit
  curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && chmod 755 msfinstall && ./msfinstall
  cd /opt/tools || exit
  rm -rf /tmp/metasploit_install
  add-test-command "msfconsole --version"
  add-to-list "metasploit,https://github.com/rapid7/metasploit-framework,A popular penetration testing framework that includes many exploits and payloads"
}

function install_smbmap(){
  colorecho "Installing smbmap"
  git -C /opt/tools/ clone -v https://github.com/ShawnDEvans/smbmap
  cd /opt/tools/smbmap || exit
  # installing requirements manually to skip impacket overwrite
  # wish we could install smbmap in virtual environment :'(
  python3 -m pip install pyasn1 pycrypto configparser termcolor impacket
  add-aliases smbmap
  add-history smbmap
  add-test-command "smbmap --help"
  add-to-list "smbmap,https://github.com/ShawnDEvans/smbmap,A tool to enumerate SMB shares and check for null sessions"
}

function install_pth-tools(){
  colorecho "Installing pth-tools"
  git -C /opt/tools clone -v https://github.com/byt3bl33d3r/pth-toolkit
  cd /opt/tools/pth-toolkit || exit
  if [[ $(uname -m) = 'x86_64' ]]
  then
    wget -O /tmp/libreadline6_6.3-8+b3.deb http://ftp.debian.org/debian/pool/main/r/readline6/libreadline6_6.3-8+b3_amd64.deb
    wget -O /tmp/multiarch-support_2.19-18+deb8u10.deb http://ftp.debian.org/debian/pool/main/g/glibc/multiarch-support_2.19-18+deb8u10_amd64.deb
  elif [[ $(uname -m) = 'aarch64' ]]
  then
    criticalecho-noexit "This installation function doesn't support architecture $(uname -m)" && return
    # FIXME
    #16 428.9  libreadline6:armhf : Depends: libc6:armhf (>= 2.15) but it is not installable
    #16 428.9                       Depends: libtinfo5:armhf but it is not installable
    #16 428.9  multiarch-support:armhf : Depends: libc6:armhf (>= 2.13-5) but it is not installable
    wget -O /tmp/libreadline6_6.3-8+b3.deb http://ftp.debian.org/debian/pool/main/r/readline6/libreadline6_6.3-8+b3_armhf.deb
    wget -O /tmp/multiarch-support_2.19-18+deb8u10.deb http://ftp.debian.org/debian/pool/main/g/glibc/multiarch-support_2.19-18+deb8u10_armhf.deb
  elif [[ $(uname -m) = 'armv7l' ]]
  then
    criticalecho-noexit "This installation function doesn't support architecture $(uname -m)" && return
    # FIXME ?
    wget -O /tmp/libreadline6_6.3-8+b3.deb http://ftp.debian.org/debian/pool/main/r/readline6/libreadline6_6.3-8+b3_armel.deb
    wget -O /tmp/multiarch-support_2.19-18+deb8u10.deb http://ftp.debian.org/debian/pool/main/g/glibc/multiarch-support_2.19-18+deb8u10_armel.deb
  else
    criticalecho-noexit "This installation function doesn't support architecture $(uname -m)" && return
  fi
  dpkg -i /tmp/libreadline6_6.3-8+b3.deb
  dpkg -i /tmp/multiarch-support_2.19-18+deb8u10.deb
  apt-get --fix-broken install
  add-aliases pth-tools
  add-history pth-tools
  # TODO add-test-command
  add-to-list "pth-tools,https://github.com/byt3bl33d3r/pth-toolkit,A toolkit to perform pass-the-hash attacks"
}

function install_smtp-user-enum(){
  colorecho "Installing smtp-user-enum"
  python3 -m pipx install smtp-user-enum
  add-history smtp-user-enum
  add-test-command "smtp-user-enum --help"
  add-to-list "smtp-user-enum,https://github.com/pentestmonkey/smtp-user-enum,A tool to enumerate email addresses via SMTP"
}

function install_gpp-decrypt(){
  colorecho "Installing gpp-decrypt"
  python3 -m pip install pycrypto colorama
  git -C /opt/tools/ clone -v https://github.com/t0thkr1s/gpp-decrypt
  add-aliases gpp-decrypt
  add-test-command "gpp-decrypt.py -f /opt/tools/gpp-decrypt/groups.xml"
  add-to-list "gpp-decrypt,https://github.com/t0thkr1s/gpp-decrypt,A tool to decrypt Group Policy Preferences passwords"
}

function install_android-tools-adb() {
  colorecho "Installing android-tools-adb"
  fapt android-tools-adb
  add-test-command "adb --help"
  add-to-list "android-tools-adb,https://developer.android.com/studio/command-line/adb,A collection of tools for debugging Android applications"
}

function install_smali(){
  colorecho "Installing smali"
  apt-get install default-jre wget
  mkdir /opt/tools/smali/
  wget https://bitbucket.org/JesusFreke/smali/downloads/smali-2.5.2.jar -O /opt/tools/smali/smali-2.5.2.jar
  add-aliases smali
  add-test-command "smali --version"
  add-to-list "smali,https://github.com/JesusFreke/smali,A tool to disassemble and assemble Android's dex files"
}

function install_tesseract-ocr(){
  colorecho "Installing tesseract-ocr"
  apt-get install -y tesseract-ocr
  add-to-list "tesseract-ocr,https://github.com/tesseract-ocr/tesseract,A text recognition engine that can be used for OCR tasks"
}

function install_dex2jar(){
  colorecho "Installing dex2jar"
  wget https://github.com/pxb1988/dex2jar/releases/latest/download/dex2jar-2.1.zip -O /tmp/dex2jar.zip
  unzip /tmp/dex2jar.zip -d /opt/tools/
  mv /opt/tools/dex-tools-2.1/ /opt/tools/dex2jar
  find /opt/tools/dex2jar -type f -name "*.sh" -exec ln -s '{}' /opt/tools/bin ';'
  add-test-command "d2j-dex2jar.sh --help"
  add-to-list "dex2jar,https://github.com/pxb1988/dex2jar,A tool to convert Android's dex files to Java's jar files"
}

function install_zipalign() {
  colorecho "Installing zipalign"
  fapt zipalign
  add-test-command "zipalign --help |& grep 'verbose output'"
  add-to-list "zipalign,https://developer.android.com/studio/command-line/zipalign,arguably the most important step to optimize your APK file"
}

function install_apksigner() {
  colorecho "Installing apksigner"
  fapt apksigner
  add-test-command "apksigner --version"
  add-to-list "apksigner,https://source.android.com/security/apksigning,arguably the most important step to optimize your APK file"
}

function install_apktool() {
  colorecho "Installing apktool"
  fapt apktool
  add-test-command "apktool --version"
  add-to-list "apktools,TODO,TODO"
}

function install_hostapd-wpe(){
  colorecho "Installing hostapd-wpe"
  fapt libssl-dev libnl-3-dev
  mkdir -p /opt/tools/hostapd-wpe
  cd /opt/tools/hostapd-wpe || exit
  git clone https://github.com/OpenSecurityResearch/hostapd-wpe
  wget http://hostap.epitest.fi/releases/hostapd-2.6.tar.gz #fails, too old :D
  tar -zxf hostapd-2.6.tar.gz
  cd hostapd-2.6 || exit
  patch -p1 < ../hostapd-wpe/hostapd-wpe.patch
  cd hostapd || exit
  make
  cd ../../hostapd-wpe/certs || exit
  ./bootstrap
  cd ../../hostapd-2.6/hostapd || exit
  ./hostapd-wpe hostapd-wpe.conf
  add-to-list "hostapd-wpe,https://github.com/OpenSecurityResearch/hostapd-wpe,A version of hostapd with added support for wireless injection attacks"
}

function install_radare2(){
  colorecho "Installing radare2"
  git -C /opt/tools/ clone https://github.com/radareorg/radare2
  /opt/tools/radare2/sys/install.sh
  add-test-command "radare2 -h"
  add-to-list "radare2,https://github.com/radareorg/radare2,A complete framework for reverse-engineering and analyzing binaries"
}

function install_jd-gui(){
  colorecho "Installing jd-gui"
  mkdir -p /opt/tools/jd-gui && cd /opt/tools/jd-gui || exit
  wget https://github.com/java-decompiler/jd-gui/releases/download/v1.6.6/jd-gui-1.6.6.jar
  add-aliases jd-gui
  # TODO add-test-command GUI app
  add-to-list "jd-gui,https://github.com/java-decompiler/jd-gui,A standalone Java Decompiler GUI"
}

function install_rust_cargo() {
  colorecho "Installing rustc, cargo, rustup"
  curl https://sh.rustup.rs -sSf | sh -s -- -y
  source "$HOME/.cargo/env"
  add-test-command "cargo --version"
  add-to-list "rust,https://www.rust-lang.org,A systems programming language focused on safety, speed, and concurrency"
}

function install_fierce() {
  colorecho "Installing fierce"
  python3 -m pipx install git+https://github.com/mschwager/fierce
  add-history fierce
  add-test-command "fierce --help"
  add-to-list "fierce,https://github.com/mschwager/fierce,A DNS reconnaissance tool for locating non-contiguous IP space"
}

function install_yarn() {
  colorecho "Installing yarn"
  curl -sS https://dl.yarnpkg.com/debian/pubkey.gpg | apt-key add -
  echo "deb https://dl.yarnpkg.com/debian/ stable main" | tee /etc/apt/sources.list.d/yarn.list
  apt update
  apt install -y yarn
  add-to-list "yarn,https://yarnpkg.com,A package manager for JavaScript"
}

function install_aircrack-ng() {
  colorecho "Installing aircrack-ng"
  fapt aircrack-ng
  add-aliases aircrack-ng
  add-history aircrack-ng
  add-test-command "aircrack-ng --help"
  add-to-list "aircrack-ng,https://www.aircrack-ng.org,A suite of tools for wireless penetration testing"
}

function install_emacs-nox() {
  colorecho "Installing emacs-nox"
  fapt emacs-nox
  add-aliases emacs-nox
  add-to-list "emacs-nox,https://www.gnu.org/software/emacs/,An extensible, customizable, free/libre text editor"
}

function install_nmap() {
  colorecho "Installing nmap"
  echo 'deb http://deb.debian.org/debian bullseye-backports main' > /etc/apt/sources.list.d/backports.list
  apt-get update
  fapt nmap/bullseye-backports
  add-aliases nmap
  add-history nmap
  add-test-command "nmap --version"
  add-to-list "nmap,https://nmap.org,The Network Mapper - a powerful network discovery and security auditing tool"
}

function install_netdiscover() {
  colorecho "Installing netdiscover"
  fapt netdiscover
  add-history netdiscover
  add-test-command "netdiscover -h |& grep 'Usage: netdiscover'"
}

function install_php() {
  colorecho "Installing php"
  fapt php
  add-aliases php
  add-to-list "php,https://www.php.net,A popular general-purpose scripting language"
}

function install_python3-pyftpdlib() {
  colorecho "Installing python3-pyftpdlib"
  fapt python3-pyftpdlib
  add-aliases pyftpdlib
  add-history pyftpdlib
  add-to-list "python3-pyftpdlib,https://github.com/giampaolo/pyftpdlib,A Python FTP server library"
}

function install_python3() {
  colorecho "Installing python3"
  fapt python3
  add-aliases python3
  add-to-list "python3,https://www.python.org,A popular general-purpose programming language"
}

function install_libxml2-utils() {
  colorecho "Installing libxml2-utils"
  fapt libxml2-utils
  add-aliases xmllint
  add-to-list "libxml2-utils,http://xmlsoft.org/,A set of utilities for manipulating XML and HTML files"
}

function install_xsel() {
  colorecho "Installing xsel"
  fapt xsel
  add-aliases xsel
  add-to-list "xsel,http://www.kfish.org/software/xsel/,A command-line program for getting and setting the contents of the X selection"
}

function install_cewl() {
  colorecho "Installing cewl"
  fapt cewl
  add-history cewl
  add-test-command "cewl --help"
  add-to-list "cewl,https://digi.ninja/projects/cewl.php,Generates custom wordlists by spidering a target's website and parsing the results"
}

function install_curl() {
  colorecho "Installing curl"
  fapt curl
  add-history curl
  add-to-list "curl,https://curl.se/,A command-line tool for transferring data using various protocols"
}

function install_dirb() {
  colorecho "Installing dirb"
  fapt dirb
  add-history dirb
  add-test-command "dirb | grep '<username:password>'"
  add-to-list "dirb,https://github.com/v0re/dirb,Web Content Scanner"
}

function install_dnsutils() {
  colorecho "Installing dnsutils"
  fapt dnsutils
  add-history dnsutils
  add-to-list "dnsutils,https://manpages.debian.org/jessie/dnsutils/dig.1.en.html,Provides various tools for querying DNS servers"
}

function install_faketime() {
  colorecho "Installing faketime"
  fapt faketime
  add-history faketime
  add-to-list "faketime,https://github.com/wolfcw/libfaketime,Report a fake time to programs"
}

function install_pdfcrack() {
  colorecho "Installing pdfcrack"
  fapt pdfcrack
  add-test-command "pdfcrack --version"
  add-to-list "pdfcrack,https://github.com/robins/pdfcrack,A tool for cracking password-protected PDF files"
}

function install_bruteforce-luks() {
  colorecho "Installing bruteforce-luks"
  fapt bruteforce-luks
  add-test-command "bruteforce-luks -h |& grep 'Print progress info'"
  add-to-list "bruteforce-luks,https://github.com/glv2/bruteforce-luks,A tool to help recover encrypted LUKS2 containers"
}

function install_hashcat() {
  colorecho "Installing hashcat"
  fapt hashcat
  add-history hashcat
  add-test-command "hashcat --help"
  add-to-list "hashcat,https://hashcat.net/hashcat,A tool for advanced password recovery"
}

function install_ldapdomaindump() {
  colorecho "Installing ldapdomaindump"
  python3 -m pipx install git+https://github.com/dirkjanm/ldapdomaindump
  add-history ldapdomaindump
  add-test-command "ldapdomaindump --help"
  add-to-list "ldapdomaindump,https://github.com/dirkjanm/ldapdomaindump,A tool for dumping domain data from an LDAP service"
}

function install_hping3() {
  colorecho "Installing hping3"
  fapt hping3
  add-test-command "hping3 --version"
  add-to-list "hping3,https://github.com/antirez/hping,A network tool able to send custom TCP/IP packets"
}

function install_masscan() {
  colorecho "Installing masscan"
  fapt masscan
  add-history masscan
  add-test-command "masscan --help; masscan --version | grep 'Masscan version'"
  add-to-list "masscan,https://github.com/robertdavidgraham/masscan,Masscan is an Internet-scale port scanner"
}

function install_nbtscan() {
  colorecho "Installing nbtscan"
  fapt nbtscan
  add-history nbtscan
  add-test-command "nbtscan 127.0.0.1"
  add-to-list "nbtscan,https://github.com/charlesroelli/nbtscan,NBTscan is a program for scanning IP networks for NetBIOS name information."
}

function install_rpcbind() {
  colorecho "Installing rpcbind"
  fapt rpcbind
  add-test-command "rpcbind"
  add-to-list "rpcbind,https://github.com/teg/rpcbind,RPCbind is a server that converts RPC program numbers into universal addresses."
}

function install_ntpdate() {
  colorecho "Installing ntpdate"
  fapt ntpdate
  add-history ntpdate
  add-to-list "ntpdate,https://github.com/ntpsec/ntpsec,ntpdate is a command that sets the local date and time to the value received from a remote NTP server"
}

function install_onesixtyone() {
  colorecho "Installing onesixtyone"
  fapt onesixtyone
  add-history onesixtyone
  add-test-command "onesixtyone 127.0.0.1 public"
  add-to-list "onesixtyone,https://github.com/trailofbits/onesixtyone,onesixtyone is an SNMP scanner which utilizes a sweep technique to achieve very high performance."
}

function install_polenum() {
  colorecho "Installing polenum"
  git -C /opt/tools/ clone https://github.com/Wh1t3Fox/polenum
  python3 -m pip install impacket
  add-aliases polenum
  add-history polenum
  add-test-command "polenum.py --help"
  add-to-list "polenum,https://github.com/Wh1t3Fox/polenum,Polenum is a Python script which uses the Impacket library to extract user information through the SMB protocol."
}

function install_rlwrap() {
  colorecho "Installing rlwrap"
  fapt rlwrap
  add-history rlwrap
  add-test-command "rlwrap --version"
  add-to-list "rlwrap,https://github.com/hanslub42/rlwrap,rlwrap is a small utility that wraps input and output streams of executables, making it possible to edit and re-run input history"
}

function install_samba() {
  colorecho "Installing samba"
  fapt samba
  add-history samba
  add-to-list "samba,https://github.com/samba-team/samba,Samba is an open-source implementation of the SMB/CIFS networking protocol"
}

function install_smbclient() {
  colorecho "Installing smbclient"
  fapt smbclient
  add-history smbclient
  add-test-command "smbclient --help"
  add-to-list "smbclient,https://github.com/samba-team/samba,SMBclient is a command-line utility that allows you to access Windows shared resources"
}

function install_snmp() {
  colorecho "Installing snmp"
  fapt snmp
  add-history snmp
  add-to-list "snmp,https://doc.ubuntu-fr.org/snmp,SNMP is a protocol for network management"
}

function install_sqlmap() {
  colorecho "Installing sqlmap"
  fapt sqlmap
  add-history sqlmap
  add-test-command "sqlmap --version"
  add-to-list "sqlmap,https://github.com/sqlmapproject/sqlmap,Sqlmap is an open-source penetration testing tool that automates the process of detecting and exploiting SQL injection flaws"
}

function install_ssh() {
  colorecho "Installing ssh"
  fapt ssh
  add-history ssh
  add-to-list "ssh,https://github.com/openssh/openssh-portable,SSH (Secure Shell) is a cryptographic network protocol for secure data communication"
}

function install_wfuzz() {
  colorecho "Installing wfuzz"
  fapt wfuzz
  add-history wfuzz
  add-test-command "wfuzz --help"
  add-to-list "wfuzz,https://github.com/xmendez/wfuzz,WFuzz is a web application vulnerability scanner that allows you to find vulnerabilities using a wide range of attack payloads and fuzzing techniques"
}

function install_freerdp2-x11() {
  colorecho "Installing freerdp2-x11"
  fapt freerdp2-x11
  add-history xfreerdp
  # test below cannot work because test runner cannot have a valid display
  # add-test-command "xfreerdp /version"
  add-test-command "which xfreerdp"
  add-to-list "freerdp2-x11,https://github.com/FreeRDP/FreeRDP,FreeRDP is a free implementation of the Remote Desktop Protocol (RDP), released under the Apache license."
}

function install_patator() {
  colorecho "Installing patator"
  fapt patator # messes up with lib, it installs python3-impacket (0.9.22-2)
  add-to-list "patator,https://github.com/lanjelot/patator,Patator is a multi-purpose brute-forcer, with a modular design and a flexible usage."
}

function install_exiftool() {
  colorecho "Installing exiftool"
  fapt exiftool
  add-test-command "wget -O /tmp/duck.png https://play-lh.googleusercontent.com/A6y8kFPu6iiFg7RSkGxyNspjOBmeaD3oAOip5dqQvXASnZp-Vg65jigJJLHr5mOEOryx && exiftool /tmp/duck.png && rm /tmp/duck.png"
  add-to-list "exiftool,https://github.com/exiftool/exiftool,ExifTool is a Perl library and command-line tool for reading, writing and editing meta information in image, audio and video files."
}

function install_exifprobe() {
  colorecho "Installing exifprobe"
  fapt exifprobe
  add-test-command "exifprobe -V; exifprobe -V |& grep 'Hubert Figuiere'"
  add-to-list "exifprobe,https://github.com/hfiguiere/exifprobe,Exifprobe is a command-line tool to parse EXIF data from image files."
}

function install_dnsenum() {
  colorecho "Installing dnsenum"
  fapt dnsenum
  add-test-command "dnsenum --help; dnsenum --help |& grep 'Print this help message'"
  add-to-list "dnsenum,https://github.com/fwaeytens/dnsenum,dnsenum is a tool for enumerating DNS information about a domain."
}

function install_hydra() {
  colorecho "Installing hydra"
  fapt hydra
  add-test-command "hydra --help; hydra -help |& grep 'more command line options'"
  add-to-list "hydra,https://github.com/vanhauser-thc/thc-hydra,Hydra is a parallelized login cracker which supports numerous protocols to attack."
}

function install_imagemagick() {
  colorecho "Installing imagemagick"
  fapt imagemagick
  add-test-command "convert -version"
  add-to-list "imagemagick,https://github.com/ImageMagick/ImageMagick,ImageMagick is a free and open-source image manipulation tool used to create, edit, compose, or convert bitmap images."
}

function install_ascii() {
  colorecho "Installing ascii"
  fapt ascii
  add-test-command "ascii -v"
  add-to-list "ascii,https://github.com/moul/ascii,ASCII command-line tool to replace images with color-coded ASCII art."
}

function install_avrdude() {
  colorecho "Installing avrdude"
  fapt avrdude
  add-test-command "avrdude '-?'"
  add-to-list "avrdude,https://github.com/avrdudes/avrdude,AVRDUDE is a command-line program that allows you to download/upload/manipulate the ROM and EEPROM contents of AVR microcontrollers using the in-system programming technique (ISP)."
}

function install_minicom() {
  colorecho "Installing minicom"
  fapt minicom
  add-test-command "minicom --version; minicom --version |& grep 'This program is free software'"
  add-to-list "minicom,https://doc.ubuntu-fr.org/minicom,Minicom is a text-based serial communication program for Unix-like operating systems."
}

function install_nasm() {
  colorecho "Installing nasm"
  fapt nasm
  add-test-command "nasm --version"
  add-to-list "nasm,https://github.com/netwide-assembler/nasm,NASM is an 80x86 assembler designed for portability and modularity."
}

function install_wabt() {
  colorecho "Installing wabt"
  fapt wabt
  add-to-list "wabt,https://github.com/WebAssembly/wabt,The WebAssembly Binary Toolkit (WABT) is a suite of tools for WebAssembly (Wasm), including assembler and disassembler, a syntax checker, and a binary format validator."
}

function install_ltrace() {
  colorecho "Installing ltrace"
  fapt-noexit ltrace
  add-to-list "ltrace,https://github.com/dkogan/ltrace,ltrace is a debugging program for Linux and Unix that intercepts and records dynamic library calls that are called by an executed process."
}

function install_strace() {
  colorecho "Installing strace"
  fapt strace
  add-to-list "strace,https://github.com/strace/strace,strace is a debugging utility for Linux that allows you to monitor and diagnose system calls made by a process."
}

function install_stegosuite() {
  colorecho "Installing stegosuite"
  fapt stegosuite
  add-test-command "stegosuite --help"
  add-to-list "stegosuite,https://github.com/osde8info/stegosuite,Stegosuite is a free steganography tool that allows you to hide data in image and audio files."
}

function install_steghide() {
  colorecho "Installing steghide"
  fapt steghide
  add-test-command "steghide --version"
  add-to-list "steghide,https://github.com/StefanoDeVuono/steghide,steghide is a steganography program that is able to hide data in various kinds of image and audio files."
}

function install_binwalk() {
  colorecho "Installing binwalk"
  fapt binwalk
  add-test-command "binwalk --help"
  add-to-list "binwalk,https://github.com/ReFirmLabs/binwalk,Binwalk is a tool for analyzing, reverse engineering, and extracting firmware images."
}

function install_foremost() {
  colorecho "Installing foremost"
  fapt foremost
  add-test-command "foremost -V"
  add-to-list "foremost,https://doc.ubuntu-fr.org/foremost,Foremost is a forensic tool for recovering files based on their headers, footers, and internal data structures."
}

function install_pst-utils() {
  colorecho "Installing pst-utils"
  fapt pst-utils
  add-to-list "pst-utils,https://manpages.debian.org/jessie/pst-utils/readpst.1,pst-utils is a set of tools for working with Outlook PST files."
}

function install_reaver() {
  colorecho "Installing reaver"
  fapt reaver
  add-test-command "reaver --help; reaver --help |& grep 'Tactical Network Solutions'"
  add-to-list "reaver,https://github.com/t6x/reaver-wps-fork-t6x,reaver is a tool for brute-forcing WPS (Wireless Protected Setup) PINs."
}

function install_bully() {
  colorecho "Installing bully"
  fapt bully
  add-test-command "bully --version"
  add-to-list "bully,https://github.com/aanarchyy/bully,bully is a tool for brute-forcing WPS (Wireless Protected Setup) PINs."
}

function install_cowpatty() {
  colorecho "Installing cowpatty"
  fapt cowpatty
  add-test-command "cowpatty -V"
  add-to-list "cowpatty,https://github.com/joswr1ght/cowpatty,cowpatty is a tool for offline dictionary attacks against WPA-PSK (Pre-Shared Key) networks."
}

function install_redis-tools() {
  colorecho "Installing redis-tools"
  fapt redis-tools
  add-test-command "redis-cli --version"
  add-to-list "redis-tools,https://github.com/antirez/redis-tools,redis-tools is a collection of Redis client utilities, including redis-cli and redis-benchmark."
}

function install_mariadb-client() {
  colorecho "Installing mariadb-client"
  fapt mariadb-client
  add-test-command "mariadb --version"
  add-to-list "mariadb-client,https://github.com/MariaDB/server,MariaDB is a community-developed fork of the MySQL relational database management system. The mariadb-client package includes command-line utilities for interacting with a MariaDB server."
}

function install_ssh-audit() {
  colorecho "Installing ssh-audit"
  fapt ssh-audit
  add-test-command "ssh-audit --help; ssh-audit --help |& grep 'verbose output'"
  add-to-list "ssh-audit,https://github.com/arthepsy/ssh-audit,ssh-audit is a tool to test SSH server configuration for best practices."
}

function install_xtightvncviewer() {
  colorecho "Installing xtightvncviewer"
  fapt xtightvncviewer
  add-to-list "xtightvncviewer,https://www.commandlinux.com/man-page/man1/xtightvncviewer.1.html,xtightvncviewer is an open source VNC client software."
}

function install_rdesktop() {
  colorecho "Installing rdesktop"
  fapt rdesktop
  add-to-list "rdesktop,https://github.com/rdesktop/rdesktop,rdesktop is a client for Remote Desktop Protocol (RDP), used in a number of Microsoft products including Windows NT Terminal Server, Windows 2000 Server, Windows XP and Windows 2003 Server."
}

function install_dns2tcp() {
  colorecho "Installing dns2tcp"
  fapt dns2tcp
  add-to-list "dns2tcp,https://github.com/alex-sector/dns2tcp,dns2tcp is a tool for relaying TCP connections over DNS."
}

function install_traceroute() {
  colorecho "Installing traceroute"
  fapt traceroute
  add-to-list "traceroute,https://github.com/iputils/iputils,Traceroute is a command which can show you the path a packet of information takes from your computer to one you specify."
}

function install_wireshark() {
  colorecho "Installing Wireshark"
  DEBIAN_FRONTEND=noninteractive fapt wireshark
  #TODO add-test-command
  add-to-list "wireshark,https://github.com/wireshark/wireshark,Wireshark is a network protocol analyzer that lets you see what’s happening on your network at a microscopic level."
}

function install_tshark() {
  colorecho "Installing tshark"
  DEBIAN_FRONTEND=noninteractive fapt tshark
  add-test-command "tshark --version"
  add-to-list "tshark,https://github.com/wireshark/wireshark,TShark is a terminal version of Wireshark."
}

function install_smuggler() {
  colorecho "Installing smuggler.py"
  git -C /opt/tools/ clone https://github.com/defparam/smuggler.git
  add-aliases smuggler
  add-history smuggler
  add-test-command "smuggler.py --help"
  add-to-list "smuggler,https://github.com/defparam/smuggler,Smuggler is a tool that helps pentesters and red teamers to smuggle data into and out of the network even when there are multiple layers of security in place."
}

function install_ldeep() {
  colorecho "Installing ldeep"
  python3 -m pipx install ldeep
  add-test-command "ldeep --help"
  add-history ldeep
  add-to-list "ldeep,https://github.com/franc-pentest/ldeep,ldeep is a tool to discover hidden paths on Web servers."
}

function install_genusernames() {
  colorecho "Installing genusernames"
  mkdir -p /opt/tools/genusernames
  wget -O /opt/tools/genusernames/genusernames.function https://gitlab.com/-/snippets/2480505/raw/main/bash
  sed -i 's/genadname/genusernames/g' /opt/tools/genusernames/genusernames.function
  echo 'source /opt/tools/genusernames/genusernames.function' >> ~/.zshrc
  add-test-command "genusernames 'john doe'"
  add-to-list "genusernames,https://gitlab.com/-/snippets/2480505/raw/main/bash,GenUsername is a Python tool for generating a list of usernames based on a name or email address."
}

function install_rusthound() {
  colorecho "Installing RustHound"
  fapt gcc libclang-dev clang libclang-dev libgssapi-krb5-2 libkrb5-dev libsasl2-modules-gssapi-mit musl-tools gcc-mingw-w64-x86-64
  git -C /opt/tools/ clone https://github.com/OPENCYBER-FR/RustHound
  cd /opt/tools/RustHound
  # Sourcing rustup shell setup, so that rust binaries are found when installing cme
  source "$HOME/.cargo/env"
  cargo build --release
  ln -s /opt/tools/RustHound/target/release/rusthound /opt/tools/bin/rusthound
  add-history rusthound
  add-test-command "rusthound --help"
  add-to-list "rusthound,https://github.com/OPENCYBER-FR/RustHound,Rusthound is a tool for searching through git repositories for secrets and sensitive information."
}

function install_certsync() {
  colorecho "Installing certsync"
  python3 -m pipx install git+https://github.com/zblurx/certsync
  add-test-command ""
  add-to-list "certsync,https://github.com/zblurx/certsync,certsync is a tool that helps you synchronize certificates between two directories."
}

function install_KeePwn() {
  colorecho "Installing KeePwn"
  python3 -m pipx install git+https://github.com/Orange-Cyberdefense/KeePwn
  add-test-command ""
  add-to-list "KeePwn,https://github.com/Orange-Cyberdefense/KeePwn,KeePwn is a tool that extracts passwords from KeePass 1.x and 2.x databases."
}

function install_pre2k() {
  colorecho "Installing pre2k"
  python3 -m pipx install git+https://github.com/garrettfoster13/pre2k
  add-test-command "pre2k --help"
  add-to-list "pre2k,https://github.com/garrettfoster13/pre2k,pre2k is a tool to check if a Windows domain has any pre-2000 Windows 2000 logon names still in use."
}

function install_msprobe() {
  colorecho "Installing msprobe"
  python3 -m pipx install git+https://github.com/puzzlepeaches/msprobe
  add-test-command "msprobe --help"
  add-to-list "msprobe,https://github.com/puzzlepeaches/msprobe,msprobe is a tool to identify Microsoft Windows hosts and servers that are running certain services."
}

function install_masky() {
  colorecho "Installing masky"
  python3 -m pipx install git+https://github.com/Z4kSec/Masky
  add-test-command "masky --help"
  add-to-list "masky,https://github.com/Z4kSec/masky,masky is a tool to mask sensitive data, such as credit card numbers, in logs and other files."
}

function install_roastinthemiddle() {
  colorecho "Installing roastinthemiddle"
  python3 -m pipx install git+https://github.com/Tw1sm/RITM
  add-test-command "roastinthemiddle --help"
  add-to-list "roastinthemiddle,https://github.com/Tw1sm/RITM,RoastInTheMiddle is a tool to intercept and relay NTLM authentication requests."
}

function install_PassTheCert() {
  colorecho "Installing PassTheCert"
  git -C /opt/tools/ clone https://github.com/AlmondOffSec/PassTheCert
  add-aliases PassTheCert
  add-test-command "passthecert.py --help"
  add-to-list "PassTheCert,https://github.com/AlmondOffSec/PassTheCert,PassTheCert is a tool to extract Active Directory user password hashes from a domain controller's local certificate store."
}

function install_bqm() {
  colorecho "Installing BQM"
  gem install bqm --no-wrapper
  add-history bqm
  add-test-command "bqm --help"
}

function install_tls-map() {
  colorecho "Installing TLS map"
  gem install tls-map
  add-history tls-map
  add-test-command "tls-map --help"
}

function install_haiti() {
  colorecho "Installing haiti"
  gem install haiti-hash
  add-history haiti
  add-test-command "haiti --help"
}

function install_ctf-party() {
  colorecho "Installing ctf-party"
  gem install ctf-party
  add-history ctf-party
  add-test-command "ctf-party --help"
}

function install_notify() {
  colorecho "Installing Notify"
  go install -v github.com/projectdiscovery/notify/cmd/notify@latest
  add-history notify
  add-test-command "notify -h"
}

function install_firefox() {
  colorecho "Installing firefox"
  fapt firefox-esr
  mkdir /opt/tools/firefox
  mv /root/sources/firefox/* /opt/tools/firefox/
  python3 -m pip install -r /opt/tools/firefox/requirements.txt
  python3 /opt/tools/firefox/setup.py
  add-test-command "file /root/.mozilla/firefox/*.Exegol"
  add-test-command "firefox --version"
}

# Package dedicated to the basic things the env needs
function package_base() {
  update || exit
  deploy_exegol
  fapt software-properties-common
  add-apt-repository contrib
  add-apt-repository non-free
  apt-get update
  fapt man                        # Most important
  fapt git                        # Git client
  fapt lsb-release
  fapt pciutils
  fapt zip
  fapt unzip
  fapt kmod
  fapt sudo                       # Sudo
  install_curl                    # HTTP handler
  fapt wget                       # Wget
  fapt gnupg2                     # gnugpg
  install_python3-pyftpdlib       # FTP server python library
  install_php                     # Php language
  fapt python2                    # Python 2 language
  install_python3                 # Python 3 language
  fapt python2-dev                # Python 2 language (dev version)
  fapt python3-dev                # Python 3 language (dev version)
  fapt python3-venv
  fapt libffi-dev
  install_rust_cargo
  ln -s /usr/bin/python2.7 /usr/bin/python  # fix shit
  install_python-pip              # Pip
  fapt python3-pip                # Pip
  python3 pip install --upgrade pip
  filesystem
  install_go                      # Golang language
  set_go_env
  install_locales
  install_tmux                    # Tmux
  fapt zsh                        # Awesome shell
  fapt asciinema                  # shell recording
  install_ohmyzsh                 # Awesome shell
  install_tldr                    # TL;DR man
  fapt python-setuptools
  fapt python3-setuptools
  python3 -m pip install wheel
  python -m pip install wheel
  install_pipx
  install_fzf                     # File fuzzer
  install_grc
  fapt npm                        # Node Package Manager
  install_nvm
  install_yarn
  fapt gem                        # Install ruby packages
  fapt automake                   # Automake
  fapt autoconf                   # Autoconf
  fapt make
  fapt gcc
  fapt g++
  fapt file                       # Detect type of file with magic number
  fapt lsof                       # Linux utility
  fapt less                       # Linux utility
  fapt x11-apps                   # Linux utility
  fapt net-tools                  # Linux utility
  fapt vim                        # Text editor
  install_ultimate_vimrc          # Make vim usable OOFB
  fapt nano                       # Text editor (not the best)
  install_emacs-nox
  fapt jq                         # jq is a lightweight and flexible command-line JSON processor
  fapt iputils-ping               # Ping binary
  fapt iproute2                   # Firewall rules
  install_openvpn                 # install OpenVPN
  install_mdcat                   # cat markdown files
  install_bat                     # Beautiful cat
  fapt tidy
  fapt mlocate
  install_xsel
  fapt libtool
  install_dnsutils                # DNS utilities like dig and nslookup
  fapt dos2unix                   # Convert encoded dos script
  DEBIAN_FRONTEND=noninteractive fapt macchanger  # Macchanger
  install_samba                   # Samba
  fapt ftp                        # FTP client
  install_ssh                     # SSH client
  fapt sshpass                    # SSHpass (wrapper for using SSH with password on the CLI)
  fapt telnet                     # Telnet client
  fapt nfs-common                 # NFS client
  install_snmp
  fapt ncat                       # Socket manager
  fapt netcat-traditional         # Socket manager
  fapt socat                      # Socket manager
  install_gf                      # wrapper around grep
  fapt rdate                      # tool for querying the current time from a network server
  fapt putty                      # GUI-based SSH, Telnet and Rlogin client
  fapt screen                     # CLI-based PuTT-like
  fapt p7zip-full                 # 7zip
  fapt p7zip-rar                  # 7zip rar module
  fapt-noexit rar                 # rar
  fapt unrar                      # unrar
  fapt xz-utils                   # xz (de)compression
  fapt xsltproc                   # apply XSLT stylesheets to XML documents (Nmap reports)
  fapt parallel
  fapt tree
  install_faketime
  fapt ruby ruby-dev
  install_libxml2-utils
  fapt nim
  fapt perl
  install_exegol-history
  install_logrotate
  fapt openjdk-11-jre openjdk-11-jdk-headless
  fapt openjdk-17-jre openjdk-17-jdk-headless
  ln -s -v /usr/lib/jvm/java-11-openjdk-* /usr/lib/jvm/java-11-openjdk    # To avoid determining the correct path based on the architecture
  ln -s -v /usr/lib/jvm/java-17-openjdk-* /usr/lib/jvm/java-17-openjdk    # To avoid determining the correct path based on the architecture
  update-alternatives --set java /usr/lib/jvm/java-17-openjdk-*/bin/java  # Set the default openjdk version to 17
  install_chromium
  install_firefox
}

# Package dedicated to offensive miscellaneous tools
function package_misc() {
  set_go_env
  install_goshs                   # Web uploader/downloader page
  install_searchsploit            # Exploitdb local search engine
  install_rlwrap                  # Reverse shell utility
  install_shellerator             # Reverse shell generator
  install_uberfile                # file uploader/downloader commands generator
  install_arsenal                 # Cheatsheets tool
  install_trilium                 # notes taking tool
  install_exiftool                # Meta information reader/writer
  install_imagemagick             # Copy, modify, and distribute image
  install_ngrok                   # expose a local development server to the Internet
  install_whatportis              # Search default port number
  install_ascii                   # The ascii table in the shell
  install_ctf-party               # Enhance and speed up script/exploit writing
  install_notify                  # Notify is a Go-based assistance package that enables you to stream the output of several tools
}

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
  # install_theharvester          # Gather emails, subdomains, hosts, employee names, open ports and banners FIXME
  install_simplyemail             # Gather emails
  install_ffuf                    # Web fuzzer (little favorites)
  install_sqlmap                  # SQL injection scanner
  install_hydra                   # Login scanner
  # install_joomscan                # Joomla scanner FIXME (https://github.com/ThePorgs/Exegol-images/actions/runs/3557732633/jobs/5977150292)
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

# Package dedicated to the installation of wordlists and tools like wl generators
function package_wordlists() {
  set_go_env
  install_crunch                  # Wordlist generator
  install_seclists                # Awesome wordlists
  install_rockyou                 # Basically installs rockyou (~same as Kali)
  install_cewl                    # Wordlist generator
  install_cupp                    # User password profiler
  install_pass_station            # Default credentials database
  install_username-anarchy        # Generate possible usernames based on heuristics
  install_genusernames
}

# Package dedicated to offline cracking/bruteforcing tools
function package_cracking() {
  set_go_env
  install_hashcat                 # Password cracker
  install_john                    # Password cracker
  install_fcrackzip               # Zip cracker
  install_pdfcrack                # PDF cracker
  install_bruteforce-luks         # Find the password of a LUKS encrypted volume
  install_name-that-hash          # Name-That-Hash, hash identifier tool
  install_haiti                   # haiti, hash type identifier
}

# Package dedicated to osint, recon and passive tools
function package_osint() {
  set_go_env
  install_youtubedl               # Command-line program to download videos from YouTube.com and other video sites
  install_exiftool                # For read exif information
  install_exifprobe               # Probe and report structure and metadata content of camera image files
  install_sublist3r               # Fast subdomains enumeration tool
  install_assetfinder             # Find domains and subdomains potentially related to a given domain
  install_subfinder               # Subfinder is a subdomain discovery tool that discovers valid subdomains for websites
  install_amass                   # OWASP Amass tool suite is used to build a network map of the target
  install_findomain               # Findomain Monitoring Service use OWASP Amass, Sublist3r, Assetfinder and Subfinder
  install_dnsenum                 # DNSEnum is a command-line tool that automatically identifies basic DNS records
  install_holehe                  # Check if the mail is used on different sites
  install_simplyemail             # Gather emails
  # install_theharvester          # Gather emails, subdomains, hosts, employee names, open ports and banners FIXME
  install_h8mail                  # Email OSINT & Password breach hunting tool
  install_infoga                  # Gathering email accounts informations
  # install_buster                  # An advanced tool for email reconnaissance FIXME /root/.local/pipx/shared/lib/python3.9/site-packages/setuptools/installer.py:27: SetuptoolsDeprecationWarning: setuptools.installer is deprecated. Requirements should be satisfied by a PEP 517 installer.
  install_pwnedornot              # OSINT Tool for Finding Passwords of Compromised Email Addresses
  # install_ghunt                 # Investigate Google Accounts with emails FIXME
  install_phoneinfoga             # Advanced information gathering & OSINT framework for phone numbers
  install_maigret                 # Search pseudos and information about users on many platforms
  install_linkedin2username       # Generate username lists for companies on LinkedIn
  install_toutatis                # Toutatis is a tool that allows you to extract information from instagrams accounts
  install_waybackurls             # Website history
  install_carbon14                # OSINT tool for estimating when a web page was written
  install_photon                  # Incredibly fast crawler designed for OSINT.
  install_cloudfail               # Utilize misconfigured DNS and old database records to find hidden IP's behind the CloudFlare network
  install_ipinfo                  # Get information about an IP address using command line with ipinfo.io
  install_constellation           # A graph-focused data visualisation and interactive analysis application.
  install_maltego                 # Maltego is a software used for open-source intelligence and forensics
  # install_spiderfoot            # SpiderFoot automates OSINT collection # FIXME, requirements.txt creates dependancies conflicts and there's no setup.py file that would allow for pipx install
  install_finalrecon              # A fast and simple python script for web reconnaissance
  # fapt recon-ng                 # External recon tool FIXME
  # install_osrframework          # OSRFramework, the Open Sources Research Framework FIXME
  install_tor					            # Tor proxy
  # install_torbrowser            # Tor browser FIXME
  install_pwndb					          # No need to say more, no ? Be responsible with this tool please !
  install_githubemail             # Retrieve a GitHub user's email even if it's not public
  # fapt whois                    # See information about a specific domain name or IP address FIXME
  install_recondog                # Informations gathering tool
  install_gron                    # JSON parser
  # install_ignorant              # holehe but for phone numbers
}

# Package dedicated to applicative and active web pentest tools
function package_web() {
  set_go_env
  install_gobuster                # Web fuzzer (pretty good for several extensions)
  install_kiterunner              # Web fuzzer (fast and pretty good for api bruteforce)
  install_amass                   # Web fuzzer
  install_ffuf                    # Web fuzzer (little favorites)
  install_dirb                    # Web fuzzer
  install_wfuzz                   # Web fuzzer (second favorites) FIXME Pycurl is not compiled against Openssl
  install_dirsearch               # Web fuzzer
  install_sqlmap                  # SQL injection scanner
  install_ssrfmap                 # SSRF scanner
  install_gopherus                # SSRF helper
  install_nosqlmap                # NoSQL scanner
  install_xsstrike                # XSS scanner
  install_xspear                  # XSS scanner
  # install_xsser                 # XSS scanner FIXME missing install
  install_xsrfprobe               # CSRF scanner
  install_bolt                    # CSRF scanner
  install_kadimus                 # LFI scanner
  install_fuxploider              # File upload scanner
  # install_patator               # Login scanner # FIXME
  # install_joomscan                # Joomla scanner FIXME (https://github.com/ThePorgs/Exegol-images/actions/runs/3557732633/jobs/5977150292)
  install_wpscan                  # Wordpress scanner
  install_droopescan              # Drupal scanner
  install_drupwn                  # Drupal scanner
  install_cmsmap                  # CMS scanner (Joomla, Wordpress, Drupal)
  install_moodlescan              # Moodle scanner
  install_testssl                 # SSL/TLS scanner
  install_sslscan                 # SSL/TLS scanner
  install_tls-scanner             # SSL/TLS scanner
  # install_sslyze                  # SSL/TLS scanner FIXME
  install_weevely                 # Awesome secure and light PHP webshell
  install_cloudfail               # Cloudflare misconfiguration detector
  install_eyewitness              # Website screenshoter
  install_oneforall
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
  install_whatweb                 # Recognises web technologies including content management
  # install_phpggc                  # php deserialization payloads FIXME https://github.com/ambionics/phpggc/issues/142
  install_symfony-exploits        #  symfony secret fragments exploit
  install_jdwp_shellifier         # exploit java debug
  install_httpmethods             # Tool for HTTP methods enum & verb tampering
  install_h2csmuggler             # Tool for HTTP2 smuggling
  install_byp4xx                  # Tool to automate 40x errors bypass attempts
  install_feroxbuster             # ffuf but with multithreaded recursion
  install_tomcatwardeployer       # Apache Tomcat auto WAR deployment & pwning tool
  install_clusterd                # Axis2/JBoss/ColdFusion/Glassfish/Weblogic/Railo scanner
  install_arjun                   # HTTP Parameter Discovery
  install_nuclei                  # Needed for gau install
  install_gau                     # fetches known URLs from AlienVault's Open Threat Exchange, the Wayback Machine, Common Crawl, and URLScan
  install_prips                   # Print the IP addresses in a given range
  install_hakrevdns               # Reverse DNS lookups
  install_httprobe                # Probe http
  install_httpx                   # Probe http
  install_anew                    # A tool for adding new lines to files, skipping duplicates
  install_robotstester            # Robots.txt scanner
  install_naabu                   # Fast port scanner
  # install_gitrob                # Senstive files reconnaissance in github
  install_burpsuite
  install_smuggler                # HTTP Request Smuggling scanner
  fapt swaks                      # Featureful, flexible, scriptable, transaction-oriented SMTP test tool
  install_php_filter_chain_generator # A CLI to generate PHP filters chain and get your RCE
  install_kraken                  # Kraken is a modular multi-language webshell.
  install_soapui                  # SoapUI is an open-source web service testing application for SOAP and REST
}

# Package dedicated to command & control frameworks
function package_c2() {
  set_go_env
  # install_empire                # Exploit framework FIXME
  # install_starkiller            # GUI for Empire, commenting while Empire install is not fixed
  install_metasploit              # Offensive framework
  install_routersploit            # Exploitation Framework for Embedded Devices
  install_pwncat                  # netcat and rlwrap on steroids to handle revshells, automates a few things too
}

# Package dedicated to internal Active Directory tools
function package_ad() {
  set_go_env
  install_responder               # LLMNR, NBT-NS and MDNS poisoner
  install_ldapdomaindump
  install_crackmapexec            # Network scanner
  install_sprayhound              # Password spraying tool
  install_smartbrute              # Password spraying tool
  install_bloodhound-py           # AD cartographer
  install_neo4j                   # Bloodhound dependency
  install_bloodhound
  # install_bloodhound_old_v3
  # install_bloodhound_old_v2
  install_cyperoth                # Bloodhound dependency
  # install_mitm6_sources         # Install mitm6 from sources
  install_mitm6_pip               # DNS server misconfiguration exploiter
  install_aclpwn                  # ACL exploiter
  install_impacket                # Network protocols scripts
  install_pykek                   # AD vulnerability exploiter
  install_lsassy                  # Credentials extracter
  install_privexchange            # Exchange exploiter
  install_ruler                   # Exchange exploiter
  install_darkarmour              # Windows AV evasion
  install_amber                   # AV evasion
  install_powershell              # Windows Powershell for Linux
  install_krbrelayx               # Kerberos unconstrained delegation abuse toolkit
  install_evilwinrm               # WinRM shell
  install_pypykatz                # Mimikatz implementation in pure Python
  install_enyx                    # Hosts discovery
  install_enum4linux-ng           # Hosts enumeration
  install_zerologon               # Exploit for zerologon cve-2020-1472
  install_libmspack               # Library for some loosely related Microsoft compression format
  install_windapsearch-go         # Active Directory Domain enumeration through LDAP queries
  install_oaburl                  # Send request to the MS Exchange Autodiscover service
  install_lnkup
  install_samdump2                # Dumps Windows 2k/NT/XP/Vista password hashes
  install_smbclient               # Small dynamic library that allows iOS apps to access SMB/CIFS file servers
  install_polenum
  install_smbmap                  # Allows users to enumerate samba share drives across an entire domain
  install_pth-tools               # Pass the hash attack
  install_smtp-user-enum          # SMTP user enumeration via VRFY, EXPN and RCPT
  install_onesixtyone             # SNMP scanning
  install_nbtscan                 # NetBIOS scanning tool
  install_rpcbind                 # RPC scanning
  install_gpp-decrypt             # Decrypt a given GPP encrypted string
  install_ntlmv1-multi            # NTLMv1 multi tools: modifies NTLMv1/NTLMv1-ESS/MSCHAPv2
  install_hashonymize             # Anonymize NTDS, ASREProast, Kerberoast hashes for remote cracking
  install_gosecretsdump           # secretsdump in Go for heavy files
  install_adidnsdump              # enumerate DNS records in Domain or Forest DNS zones
  install_pygpoabuse
  install_bloodhound-import       # Python script to import BH data to a neo4j db
  install_bloodhound-quickwin     # Python script to find quickwins from BH data in a neo4j db
  install_ldapsearch              # LDAP enumeration utils
  install_ldapsearch-ad           # Python script to find quickwins from basic ldap enum
  install_petitpotam              # Python script to coerce auth through MS-EFSR abuse
  install_dfscoerce               # Python script to coerce auth through NetrDfsRemoveStdRoot and NetrDfsAddStdRoot abuse
  install_coercer                 # Python script to coerce auth through multiple methods
  install_pkinittools             # Python scripts to use kerberos PKINIT to obtain TGT
  install_pywhisker               # Python script to manipulate msDS-KeyCredentialLink
  #install_manspider              # Snaffler-like in Python # FIXME : https://github.com/blacklanternsecurity/MANSPIDER/issues/18
  install_targetedKerberoast
  install_pcredz
  install_pywsus
  install_donpapi
  install_webclientservicescanner
  install_certipy
  install_shadowcoerce
  install_gmsadumper
  install_pylaps
  install_finduncommonshares
  install_ldaprelayscan
  install_goldencopy
  install_crackhound
  install_kerbrute                # Tool to enumerate and bruteforce AD accounts through kerberos pre-authentication
  install_ldeep
  install_rusthound
  install_certsync
  install_KeePwn
  install_pre2k
  install_msprobe
  install_masky
  install_roastinthemiddle
  install_PassTheCert
  install_bqm                     # Deduplicate custom BloudHound queries from different datasets and merge them in one customqueries.json file.
}

# Package dedicated to mobile apps pentest tools
function package_mobile() {
  set_go_env
  install_android-tools-adb
  install_smali
  install_dex2jar
  install_zipalign
  install_apksigner
  install_apktool
  install_frida
  install_objection               # Runtime mobile exploration toolkit
  install_androguard              # Reverse engineering and analysis of Android applications
}

# Package dedicated to VOIP/SIP pentest tools
function package_voip() {
  set_go_env
  install_sipvicious              # Set of tools for auditing SIP based VOIP systems
}

# Package dedicated to RFID/NCF pentest tools
function package_rfid() {
  set_go_env
  install_libusb-dev
  install_autoconf
  install_nfct
  install_pcsc
  install_libnfc                  # NFC library
  install_mfoc                    # Tool for nested attack on Mifare Classic
  install_mfcuk                   # Tool for Darkside attack on Mifare Classic
  install_libnfc-crypto1-crack    # tool for hardnested attack on Mifare Classic
  install_mfdread                 # Tool to pretty print Mifare 1k/4k dumps
  install_proxmark3               # Proxmark3 scripts
}

# Package dedicated to IoT tools
function package_iot() {
  install_avrdude
  install_minicom
}

# Package dedicated to SDR
function package_sdr() {
  install_mousejack               # tools for mousejacking
  install_jackit                  # tools for mousejacking
  install_hackrf                  # tools for hackrf
  install_gqrx                    # spectrum analyzer for SDR
  install_rtl-433                 # decode radio transmissions from devices on the ISM bands
}

# Package dedicated to network pentest tools
function package_network() {
  export PATH=$PATH:/usr/local/go/bin
  install_proxychains             # Network tool
  install_wireshark               # Wireshark packet sniffer
  install_tshark                  # Tshark packet sniffer
  # install_wireshark_sources     # Install Wireshark from sources
  install_hping3                  # Discovery tool
  install_masscan                 # Port scanner
  install_nmap                    # Port scanner
  install_netdiscover             # Active/passive address reconnaissance tool
  install_autorecon               # External recon tool
  install_tcpdump                 # Capture TCP traffic
  install_dnschef                 # Python DNS server
  install_divideandscan           # Python project to automate port scanning routine
  install_iptables                # iptables for the win
  install_traceroute              # ping ping
  install_chisel                  # Fast TCP/UDP tunnel over HTTP
  install_sshuttle                # Transparent proxy over SSH
  install_dns2tcp                 # TCP tunnel over DNS
  # install_eaphammer             # FIXME
  install_freerdp2-x11
  install_rdesktop
  install_xtightvncviewer
  install_fierce
  install_ssh-audit               # SSH server audit
  install_hydra                   # Login scanner
  install_mariadb-client          # Mariadb client
  install_redis-tools             # Redis protocol
  # install_odat                  # Oracle Database Attacking Tool, FIXME
  install_dnsx                    # Fast and multi-purpose DNS toolkit
  install_shuffledns              # Wrapper around massdns to enumerate valid subdomains
  install_tailscale               # Zero config VPN for building secure networks
  #install_ligolo-ng              # Tunneling tool that uses a TUN interface, FIXME: https://github.com/nicocha30/ligolo-ng/issues/32
}

# Package dedicated to wifi pentest tools
function package_wifi() {
  set_go_env
  install_pyrit                   # Databases of pre-computed WPA/WPA2-PSK authentication phase
  install_wifite2                 # Retrieving password of a wireless access point (router)
  install_aircrack-ng             # WiFi security auditing tools suite
  # install_hostapd-wpe           # Modified hostapd to facilitate AP impersonation attacks, FIXME broken install, need official release of hostapd-2.6.tar.gz
  install_reaver                  # Brute force attack against Wifi Protected Setup
  install_bully                   # WPS brute force attack
  install_cowpatty                # WPA2-PSK Cracking
  install_bettercap               # MiTM tool
  install_hcxtools                # Tools for PMKID and other wifi attacks
  install_hcxdumptool             # Small tool to capture packets from wlan devices
}

# Package dedicated to forensic tools
function package_forensic() {
  install_pst-utils               # Reads a PST and prints the tree structure to the console
  install_binwalk                 # Tool to find embedded files
  install_foremost                # Alternative to binwalk
  install_volatility2             # Memory analysis tool
  install_volatility3             # Memory analysis tool v2
  install_trid                    # filetype detection tool
  # install_peepdf                # PDF analysis FIXME
  install_testdisk                # Recover lost partitions
  install_jadx                    # Dex to Java decompiler
  install_fdisk                   # Creating and manipulating disk partition table
  install_sleuthkit               # Collection of command line tools that allow you to investigate disk images
}

# Package dedicated to steganography tools
function package_steganography() {
  install_zsteg                   # Detect stegano-hidden data in PNG & BMP
  install_stegosuite
  install_steghide
  install_stegolsb                # (including wavsteg)
  install_exif                    # Show and change EXIF information in JPEG files
  install_exiv2                   # Utility to read, write, delete and modify Exif, IPTC, XMP and ICC image metadata
  install_hexedit                 # View and edit files in hexadecimal or in ASCII
}

# Package dedicated to cloud tools
function package_cloud() {
  install_kubectl
  install_awscli
  install_scout                   # Multi-Cloud Security Auditing Tool
}

# Package dedicated to reverse engineering tools
function package_reverse() {
  install_pwntools                # CTF framework and exploit development library
  install_pwndbg                  # Advanced Gnu Debugger
  install_angr                    # Binary analysis
  install_checksec-py             # Check security on binaries
  install_nasm                    # Netwide Assembler
  install_radare2                 # Awesome debugger
  install_wabt                    # The WebAssembly Binary Toolkit
  install_ltrace
  install_strace
  install_ghidra
  install_ida
  install_jd-gui                  # Java decompiler
}

# Package dedicated to attack crypto
function package_crypto() {
  # install_rsactftool            # attack rsa FIXME
  install_tls-map                 # CLI & library for mapping TLS cipher algorithm names: IANA, OpenSSL, GnuTLS, NSS
}

# Package dedicated to SAST and DAST tools
function package_code_analysis() {
  install_vulny-code-static-analysis
  install_brakeman		            # Checks Ruby on Rails applications for security vulnerabilities
  install_semgrep                 # Static analysis engine for finding bugs and vulnerabilities
}

# Entry point for the installation
if [[ $EUID -ne 0 ]]; then
  criticalecho "You must be a root user"
else
  if declare -f "$1" > /dev/null
  then
    if [[ -f '/.dockerenv' ]]; then
      echo -e "${GREEN}"
      echo "This script is running in docker, as it should :)"
      echo "If you see things in red, don't panic, it's usually not errors, just badly handled colors"
      echo -e "${NOCOLOR}"
      "$@"
    else
      echo -e "${RED}"
      echo "[!] Careful : this script is supposed to be run inside a docker/VM, do not run this on your host unless you know what you are doing and have done backups. You are warned :)"
      echo -e "${NOCOLOR}"
      "$@"
    fi
  else
    echo "'$1' is not a known function name" >&2
    exit 1
  fi
fi
