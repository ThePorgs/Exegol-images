#!/bin/bash
# Author: The Exegol Project

# TODO add add-test-command in all tools

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
  cat "/root/sources/zsh/aliases.d/$*" | sed '/^$/d' | perl -pe 'chomp if eof' && echo '' >> /opt/.exegol_aliases
}

function add-history() {
  colorecho "Adding history commands for: $*"
  cat "/root/sources/zsh/history.d/$*" | sed '/^$/d' | perl -pe 'chomp if eof' && echo '' >> /opt/.zsh_history
}

function add-test-command() {
  colorecho "Adding build pipeline test command: $*"
  mkdir -p /.exegol/build_pipeline_tests/
  echo "$*" >> "/.exegol/build_pipeline_tests/$PIPELINE_TESTS_FILE"
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
  split -l 200 -d /.exegol/build_pipeline_tests/commands.txt /.exegol/build_pipeline_tests/tests.
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
#  git -C /opt/tools/ clone https://github.com/ShutdownRepo/Exegol-history
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
  apt-get -y install tmux
  cp -v /root/sources/tmux/tmux.conf ~/.tmux.conf
  touch ~/.hushlogin
}

function install_gowitness() {
  colorecho "Installing gowitness"
  go install -v github.com/sensepost/gowitness@latest
  add-history gowitness
}

function install_goshs(){
  colorecho "Installing goshs"
  go install -v github.com/patrickhener/goshs@latest
  add-history goshs
}

function install_sslyze(){
  colorecho "Installing sslyze"
  python3 -m pipx install sslyze
  add-history sslyze
}

function install_responder() {
  colorecho "Installing Responder"
  git -C /opt/tools/ clone https://github.com/lgandx/Responder
  sed -i 's/ Random/ 1122334455667788/g' /opt/tools/Responder/Responder.conf
  sed -i 's/files\/AccessDenied.html/\/opt\/tools\/Responder\/files\/AccessDenied.html/g' /opt/tools/Responder/Responder.conf
  sed -i 's/files\/BindShell.exe/\/opt\/tools\/Responder\/files\/BindShell.exe/g' /opt/tools/Responder/Responder.conf
  sed -i 's/certs\/responder.crt/\/opt\/tools\/Responder\/certs\/responder.crt/g' /opt/tools/Responder/Responder.conf
  sed -i 's/certs\/responder.key/\/opt\/tools\/Responder\/certs\/responder.key/g' /opt/tools/Responder/Responder.conf
  fapt gcc-mingw-w64-x86-64
  x86_64-w64-mingw32-gcc /opt/tools/Responder/tools/MultiRelay/bin/Runas.c -o /opt/tools/Responder/tools/MultiRelay/bin/Runas.exe -municode -lwtsapi32 -luserenv
  x86_64-w64-mingw32-gcc /opt/tools/Responder/tools/MultiRelay/bin/Syssvc.c -o /opt/tools/Responder/tools/MultiRelay/bin/Syssvc.exe -municode
  cd /opt/tools/Responder || exit
  /opt/tools/Responder/certs/gen-self-signed-cert.sh
  add-aliases responder
  add-history responder
  add-test-command "responder --version"
}

function install_sublist3r() {
  colorecho "Installing Sublist3r"
  git -C /opt/tools/ clone https://github.com/aboul3la/Sublist3r.git
  python3 -m pip install -r /opt/tools/Sublist3r/requirements.txt
  add-aliases sublist3r
  add-history sublist3r
}

function install_recondog() {
  colorecho "Installing ReconDog"
  git -C /opt/tools/ clone https://github.com/s0md3v/ReconDog
  python3 -m pip install -r /opt/tools/ReconDog/requirements.txt
  add-aliases recondog
}

function install_githubemail() {
  colorecho "Installing github-email"
  npm install --global github-email
  add-history github-email
}

function install_onionsearch() {
  colorecho "Installing onionsearch"
  git -C /opt/tools/ clone https://github.com/megadose/onionsearch
  cd /opt/tools/onionsearch || exit
  python3 setup.py install
  rm -rf /opt/tools/onionsearch
  add-history onionsearch
}

function install_photon() {
  colorecho "Installing photon"
  git -C /opt/tools/ clone https://github.com/s0md3v/photon
  python3 -m pip install -r /opt/tools/photon/requirements.txt
  add-aliases photon
}

function install_wikileaker() {
  colorecho "Installing WikiLeaker"
  git -C /opt/tools/ clone https://github.com/jocephus/WikiLeaker.git
  python3 -m pip install -r /opt/tools/WikiLeaker/requirements.txt
  add-aliases wikileaker
  add-history wikileaker
}

function install_osrframework() {
  colorecho "Installing OSRFramework"
  python3 -m pipx install osrframework
}

function install_cloudfail() {
  colorecho "Installing CloudFail"
  git -C /opt/tools/ clone https://github.com/m0rtem/CloudFail
  python3 -m pip install -r /opt/tools/CloudFail/requirements.txt
  add-aliases cloudfail
  add-history cloudfail
}

function install_oneforall() {
  colorecho "Installing OneForAll"
  git -C /opt/tools/ clone https://github.com/shmilylty/OneForAll.git
  python3 -m pip install -r /opt/tools/OneForAll/requirements.txt
  add-aliases oneforall
}

function install_eyewitness() {
  colorecho "Installing EyeWitness"
  git -C /opt/tools/ clone https://github.com/FortyNorthSecurity/EyeWitness
  cd /opt/tools/EyeWitness/Python/setup || exit
  ./setup.sh
  add-aliases eyewitness
}

function install_wafw00f() {
  colorecho "Installing wafw00f"
  python3 -m pipx install wafw00F
}

function install_jsparser() {
  colorecho "Installing JSParser"
  git -C /opt/tools/ clone https://github.com/rickjms1337/JSParser.git
  cd /opt/tools/JSParser || exit
  git checkout remotes/origin/master_upgrading_python3
  apt-get update
  apt-get install python3-pycurl
  python3 -m pip install -r requirements.txt
  python3 setup.py install
}

function install_linkfinder() {
  colorecho "Installing LinkFinder"
  git -C /opt/tools/ clone https://github.com/GerbenJavado/LinkFinder.git
  cd /opt/tools/LinkFinder || exit
  python3 -m pip install -r requirements.txt
  python3 setup.py install
  add-aliases linkfinder
}

function install_ssrfmap() {
  colorecho "Installing SSRFmap"
  git -C /opt/tools/ clone https://github.com/swisskyrepo/SSRFmap
  cd /opt/tools/SSRFmap || exit
  python3 -m pip install -r requirements.txt
  add-aliases ssrfmap
}

function install_nosqlmap() {
  colorecho "Installing NoSQLMap"
  git -C /opt/tools clone https://github.com/codingo/NoSQLMap.git
  cd /opt/tools/NoSQLMap || exit
  python setup.py install
  add-aliases nosqlmap
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
}

function install_fuxploider() {
  colorecho "Installing fuxploider"
  git -C /opt/tools/ clone https://github.com/almandin/fuxploider.git
  cd /opt/tools/fuxploider || exit
  python3 -m pip install -r requirements.txt
  add-aliases fuxploider
}

function install_corscanner() {
  colorecho "Installing CORScanner"
  git -C /opt/tools/ clone https://github.com/chenjj/CORScanner.git
  cd /opt/tools/CORScanner || exit
  python3 -m pip install -r requirements.txt
  add-aliases corscanner
}

function install_blazy() {
  colorecho "Installing Blazy"
  git -C /opt/tools/ clone https://github.com/UltimateHackers/Blazy
  cd /opt/tools/Blazy || exit
  python -m pip install -r requirements.txt
  add-aliases blazy
}

function install_xsstrike() {
  colorecho "Installing XSStrike"
  git -C /opt/tools/ clone https://github.com/s0md3v/XSStrike.git
  python3 -m pipx install fuzzywuzzy
  add-aliases xsstrike
}

function install_xspear() {
  colorecho "Installing XSpear"
  gem install XSpear
}

function install_pass_station() {
  colorecho "Installing Pass Station"
  gem install pass-station
  add-history pass-station
}

function install_username-anarchy() {
  colorecho "Installing Username-Anarchy"
  git -C /opt/tools/ clone https://github.com/urbanadventurer/username-anarchy
  add-aliases username-anarchy
}

function install_evilwinrm() {
  colorecho "Installing evil-winrm"
  gem install evil-winrm
  add-history evil-winrm
}

function install_bolt() {
  colorecho "Installing Bolt"
  git -C /opt/tools/ clone https://github.com/s0md3v/Bolt.git
  add-aliases bolt
}

function install_crackmapexec() {
  colorecho "Installing CrackMapExec"
  apt-get -y install libffi-dev libxml2-dev libxslt-dev libssl-dev openssl autoconf g++ python3-dev libkrb5-dev
  git -C /opt/tools/ clone --recursive https://github.com/byt3bl33d3r/CrackMapExec
  cd /opt/tools/CrackMapExec || exit
  # Sourcing rustup shell setup, so that rust binaries are found when installing cme
  source "$HOME/.cargo/env"
  python3 -m pipx install .
  ~/.local/bin/crackmapexec
  mkdir -p ~/.cme
  [ -f ~/.cme/cme.conf ] && mv ~/.cme/cme.conf ~/.cme/cme.conf.bak
  cp -v /root/sources/crackmapexec/cme.conf ~/.cme/cme.conf
  # below is for having the ability to check the source code when working with modules and so on
  # git -C /opt/tools/ clone https://github.com/byt3bl33d3r/CrackMapExec
  cp -v /root/sources/grc/conf.cme /usr/share/grc/conf.cme
  add-aliases crackmapexec
  add-history crackmapexec
  add-test-command "crackmapexec --help"
}

function install_lsassy() {
  colorecho "Installing lsassy"
  python3 -m pipx install lsassy
  add-history lsassy
  add-test-command "lsassy --version"
}

function install_sprayhound() {
  colorecho "Installing sprayhound"
  git -C /opt/tools/ clone https://github.com/Hackndo/sprayhound
  cd /opt/tools/sprayhound || exit
  apt-get -y install libsasl2-dev libldap2-dev
  python3 -m pip install "pyasn1<0.5.0,>=0.4.6"
  python3 setup.py install
  add-history sprayhound
  add-test-command "sprayhound --help"
}

function install_impacket() {
  colorecho "Installing Impacket scripts"
  apt-get -y install libffi-dev
  git -C /opt/tools/ clone https://github.com/ShutdownRepo/impacket
  git -C /opt/tools/impacket checkout exegol

  # Following PRs are merged in the forked repo
  # 1135: [GetUserSPNs] Improved searchFilter for GetUserSPNs
  # 1154: [ntlmrelayx] Unfiltered SID query when operating ACL attack
  # 1184: [findDelegation] Added user filter on findDelegation
  # 1201: [describeTicket] Added describeTicket
  # 1202: [getST] Added self for getST
  # 1224: [renameMachine] Added renameMachine.py
  # 1253: [ntlmrelayx] Added LSA dump on top of SAM dump for ntlmrelayx
  # 1256: [tgssub] Added tgssub script for service substitution
  # 1267: [Get-GPPPasswords] Better handling of various XML files in Group Policy Preferences
  # 1270: [ticketer] Fix ticketer duration to support default 10 hours tickets
  # 1280: [machineAccountQuota] added machineAccountQuota.py
  # 1289: [ntlmrelayx] LDAP attack: Add DNS records through LDAP
  # 1291: [dacledit] New example script for DACL manipulation
  # 1323: [owneredit.py] New example script to change an object's owner
  # 1329: [secretsdump.py] Use a custom LDAP filter during a DCSync
  # 1353: [ntlmrelayx.py] add filter option
  # 1391: [ticketer.py, pac.py] Ticketer extra-pac implementation
  # 1393: [rbcd.py] Handled SID not found in LDAP error #1393
  # 1397: [mssqlclient.py] commands and prompt improvements
  # and a few other, check https://github.com/ShutdownRepo/impacket/tree/exegol directly for more

  # Following PRs are not merged yet because of conflict or for other reasons, but should be merged soon
  # to understand first 1288: [ntlmrelayx] LDAP attack: bypass computer creation restrictions with CVE-2021-34470
  # conflict 1290: [ntlmrelayx] Adds the creation of a new machine account through SMB
  # conflict 1360: [smbserver.py] Added flag to drop SSP from Net-NTLMv1 auth

  python3 -m pipx install /opt/tools/impacket/

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
  add-test-command "getST.py --help | grep 'u2u'"
  add-test-command "ticketer.py --help | grep impersonate"
  add-test-command "dacledit.py --help"
  add-test-command "describeTicket.py --help"
}

function install_bloodhound-py() {
  colorecho "Installing and Python ingestor for BloodHound"
  git -C /opt/tools/ clone https://github.com/fox-it/BloodHound.py
  add-aliases bloodhound-py
  add-history bloodhound-py
  add-test-command "bloodhound.py --help"
}

function install_neo4j() {
  colorecho "Installing neo4j"
  fapt openjdk-11-jre
  # TODO: when temporary fix is not needed anymore --> fapt openjdk-17-jre
  update-java-alternatives --jre --set "$(find /usr/lib/jvm/ -maxdepth 1 -type l -name 'java-1.11.0-openjdk*' -printf '%P')"
  # TODO: when temporary fix is not needed anymore --> update-java-alternatives --jre --set $(find /usr/lib/jvm/ -maxdepth 1 -type l -name 'java-1.17.0-openjdk*' -printf '%P')
  wget -O - https://debian.neo4j.com/neotechnology.gpg.key | apt-key add -
  # TODO: temporary fix => rollback to 4.4 stable until perf issue is fix on neo4j 5.x
  #echo 'deb https://debian.neo4j.com stable latest' | tee /etc/apt/sources.list.d/neo4j.list
  echo 'deb https://debian.neo4j.com stable 4.4' | tee /etc/apt/sources.list.d/neo4j.list
  apt-get update
  apt-get -y install --no-install-recommends gnupg libgtk2.0-bin libcanberra-gtk-module libx11-xcb1 libva-glx2 libgl1-mesa-glx libgl1-mesa-dri libgconf-2-4 libasound2 libxss1
  apt-get -y install neo4j
  # TODO: when temporary fix is not needed anymore --> neo4j-admin dbms set-initial-password exegol4thewin
  mkdir -p /usr/share/neo4j/logs/
  touch /usr/share/neo4j/logs/neo4j.log
  add-history neo4j
  add-test-command "neo4j version"
}

function install_cyperoth() {
  colorecho "Installing cypheroth"
  git -C /opt/tools/ clone https://github.com/seajaysec/cypheroth/
  add-aliases cypheroth
  add-history cypheroth
  add-test-command "cypheroth -u neo4j -p exegol4thewin | grep 'Quitting Cypheroth'"
}

function install_mitm6_sources() {
  colorecho "Installing mitm6 from sources"
  git -C /opt/tools/ clone https://github.com/fox-it/mitm6
  cd /opt/tools/mitm6/ || exit
  python3 -m pip install -r requirements.txt
  python3 setup.py install
}

function install_mitm6_pip() {
  colorecho "Installing mitm6 with pip"
  python3 -m pip install service_identity
  python3 -m pip install mitm6
  cd /usr/lib/x86_64-linux-gnu/ || exit
  ln -s -f libc.a liblibc.a
  add-history mitm6
  add-test-command "mitm6 --help"
}

function install_aclpwn() {
  colorecho "Installing aclpwn with pip"
  python3 -m pipx install git+https://github.com/aas-n/aclpwn.py
  add-test-command "aclpwn -h"
}

function install_routersploit() {
  colorecho "Installing RouterSploit"
  git -C /opt/tools/ clone https://www.github.com/threat9/routersploit
  cd /opt/tools/routersploit || exit
  python3 -m pip install -r requirements.txt
  add-aliases routersploit
}

function install_empire() {
  colorecho "Installing Empire"
  python3 -m pip install poetry
  git -C /opt/tools/ clone --recursive https://github.com/BC-SECURITY/Empire
  cd /opt/tools/Empire/ || exit
  colorecho "Applying Exegol specific patch"
  git apply /root/sources/patches/empire_install_sh_patch.diff
  ./setup/install.sh
  python3 -m pip install .
  # Changing password
  sed -i 's/password123/exegol4thewin/' /opt/tools/Empire/empire/server/config.yaml
  add-aliases empire
}

function install_starkiller() {
  colorecho "Installing Starkiller"
  apt-get -y install libfuse2
  version="$(curl -s https://github.com/BC-SECURITY/Starkiller/tags|grep /releases/tag/v -m1 |grep -Eo 'v[0-9]+\.[0-9]+\.[0-9]+'|cut -d 'v' -f2|head -n 1)"
  mkdir /opt/tools/starkiller
  wget -O /opt/tools/starkiller/starkiller.AppImage "https://github.com/BC-SECURITY/Starkiller/releases/download/v$version/starkiller-$version.AppImage"
  chmod +x /opt/tools/starkiller/starkiller.AppImage
  add-aliases starkiller
}

function install_assetfinder() {
  colorecho "Installing assetfinder"
  go install -v github.com/tomnomnom/assetfinder@latest
  add-history assetfinder
}

function install_subfinder() {
  colorecho "Installing subfinder"
  go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
  add-history subfinder
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
}

function install_gobuster() {
  colorecho "Installing gobuster"
  go install github.com/OJ/gobuster/v3@latest
  add-history gobuster
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
}

function install_dirsearch() {
  colorecho "Installing dirsearch"
  python3 -m pipx install git+https://github.com/maurosoria/dirsearch
  add-history dirsearch
}

function install_cmsmap() {
  colorecho "Installing CMSmap"
  python3 -m pipx install git+https://github.com/Dionach/CMSmap.git
  cmsmap -U PC
  add-history cmsmap
}

function install_tomcatwardeployer() {
  colorecho "Installing tomcatWarDeployer"
  git -C /opt/tools/ clone https://github.com/mgeeky/tomcatWarDeployer.git
  cd /opt/tools/tomcatWarDeployer/ || exit
  python -m pip install -r requirements.txt
  add-aliases tomcatwardeployer
}

function install_clusterd() {
  colorecho "Installing clusterd"
  git -C /opt/tools/ clone https://github.com/hatRiot/clusterd.git
  cd /opt/tools/clusterd/ || exit
  python -m pip install -r requirements.txt
  echo -e '#!/bin/sh\n(cd /opt/tools/clusterd/ && python clusterd.py $@)' > /usr/local/bin/clusterd
  chmod +x /usr/local/bin/clusterd
  add-history clusterd
}

function install_moodlescan() {
  colorecho "Installing moodlescan"
  git -C /opt/tools/ clone https://github.com/inc0d3/moodlescan.git
  cd /opt/tools/moodlescan/ || exit
  python3 -m pip install -r requirements.txt
  /opt/tools/moodlescan/moodlescan.py -a
  add-aliases moodlescan
  add-history moodlescan
}

function install_arjun() {
  colorecho "Installing arjun"
  python3 -m pipx install arjun
}

function install_ffuf() {
  colorecho "Installing ffuf"
  go install -v github.com/ffuf/ffuf@latest
  add-history ffuf
}

function install_waybackurls() {
  colorecho "Installing waybackurls"
  go install -v github.com/tomnomnom/waybackurls@latest
  add-history waybackurls
}

function install_gitrob(){
  colorecho "Installing gitrob"
  go install -v github.com/michenriksen/gitrob@latest
}

function install_gron() {
  colorecho "Installing gron"
  go install -v github.com/tomnomnom/gron@latest
}

function install_timing_attack() {
  colorecho "Installing timing_attack"
  gem install timing_attack
}

function install_updog() {
  colorecho "Installing updog"
  python3 -m pipx install updog
  add-history updog
}

function install_findomain() {
  colorecho "Installing findomain"
  wget -O /opt/tools/bin/findomain https://github.com/Edu4rdSHL/findomain/releases/latest/download/findomain-linux
  chmod +x /opt/tools/bin/findomain
}

function install_proxychains() {
  colorecho "Installing proxychains"
  git -C /opt/tools/ clone https://github.com/rofl0r/proxychains-ng
  cd /opt/tools/proxychains-ng/ || exit
  ./configure --prefix=/usr --sysconfdir=/etc
  make
  make install
  make install-config
  cp -v /root/sources/proxychains/proxychains.conf /etc/proxychains.conf
  add-aliases proxychains
}

function install_grc() {
  colorecho "Installing and configuring grc"
  apt-get -y install grc
  cp -v /root/sources/grc/grc.conf /etc/grc.conf
  add-aliases grc
}

function install_nvm() {
  colorecho "Installing nvm (in zsh context)"
  zsh -c "source ~/.zshrc && nvm install node"
}

function install_pykek() {
  colorecho "Installing Python Kernel Exploit Kit (pykek) for MS14-068"
  git -C /opt/tools/ clone https://github.com/preempt/pykek
  add-aliases pykek
  # TODO add-test-command
}

function install_autorecon() {
  colorecho "Installing autorecon"
  apt-get -y install wkhtmltopdf python3-venv
  python3 -m pipx install git+https://github.com/Tib3rius/AutoRecon
  add-history autorecon
}

function install_simplyemail() {
  colorecho "Installing SimplyEmail"
  git -C /opt/tools/ clone https://github.com/SimplySecurity/SimplyEmail.git
  cd /opt/tools/SimplyEmail/ || exit
  bash setup/setup.sh #TODO update install process ?
  add-aliases simplyemail
  add-history simplyemail
}

function install_privexchange() {
  colorecho "Installing privexchange"
  git -C /opt/tools/ clone https://github.com/dirkjanm/PrivExchange
  add-aliases privexchange
  add-history privexchange
  add-test-command "python3 /opt/tools/PrivExchange/privexchange.py --help"
}

function install_lnkup() {
  colorecho "Installing LNKUp"
  git -C /opt/tools/ clone https://github.com/Plazmaz/LNKUp
  cd /opt/tools/LNKUp || exit
  python -m pip install -r requirements.txt
  add-aliases lnkup
  add-history lnkup
}

function install_pwntools() {
  colorecho "Installing pwntools"
  python -m pip install pwntools
  python3 -m pip install pwntools
  add-test-command "python -c 'import pwn'"
  add-test-command "python3 -c 'import pwn'"
}

function install_angr() {
  colorecho "Installing angr"
  fapt python3-dev libffi-dev build-essential virtualenvwrapper
  python3 -m pip install virtualenv virtualenvwrapper
  mkvirtualenv --python="$(which python3)" angr
  python3 -m pip install angr
  add-test-command "python3 -c 'import angr'"
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
}

function install_darkarmour() {
  colorecho "Installing darkarmour"
  git -C /opt/tools/ clone https://github.com/bats3c/darkarmour
  cd /opt/tools/darkarmour || exit
  apt-get -y install mingw-w64-tools mingw-w64-common g++-mingw-w64 gcc-mingw-w64 upx-ucl osslsigncode
  add-aliases darkarmour
  add-history darkarmour
}

function install_powershell() {
  colorecho "Installing powershell"
  apt-get install -y software-properties-common
  curl -sSL https://packages.microsoft.com/keys/microsoft.asc | apt-key add -
  apt-add-repository https://packages.microsoft.com/debian/11/prod
  apt-get update
  apt-get install -y powershell
  mv /opt/microsoft /opt/tools/microsoft
  rm /usr/bin/pwsh
  ln -s /opt/tools/microsoft/powershell/7/pwsh /opt/tools/bin/pwsh
  add-aliases powershell
}

function install_fzf() {
  colorecho "Installing fzf"
  git -C /opt/tools/ clone --depth 1 https://github.com/junegunn/fzf.git
  cd /opt/tools/fzf || exit
  ./install --all
  add-aliases fzf
}

function install_shellerator() {
  colorecho "Installing shellerator"
  python3 -m pipx install git+https://github.com/ShutdownRepo/shellerator
  add-history shellerator
}

function install_uberfile() {
  colorecho "Installing uberfile"
  python3 -m pipx install git+https://github.com/ShutdownRepo/uberfile
}

function install_kadimus() {
  colorecho "Installing kadimus"
  apt-get -y install libcurl4-openssl-dev libpcre3-dev libssh-dev
  git -C /opt/tools/ clone https://github.com/P0cL4bs/Kadimus
  cd /opt/tools/Kadimus || exit
  make
  add-aliases kadimus
  add-history kadimus
}

function install_testssl() {
  colorecho "Installing testssl"
  apt-get -y install bsdmainutils
  git -C /opt/tools/ clone --depth 1 https://github.com/drwetter/testssl.sh.git
  add-aliases testssl
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
    criticalecho-noexit "This installation function doesn't support architecture $(uname -m)"
  fi
  fapt -f /tmp/bat.deb
  rm /tmp/bat.deb
}

function install_mdcat() {
  colorecho "Installing mdcat"
  source "$HOME/.cargo/env"
  cargo install mdcat
}

function install_xsrfprobe() {
  colorecho "Installing XSRFProbe"
  git -C /opt/tools/ clone https://github.com/0xInfection/XSRFProbe
  cd /opt/tools/XSRFProbe || exit
  python3 setup.py install
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
}

function install_hakrawler() {
  colorecho "Installing hakrawler"
  go install -v github.com/hakluke/hakrawler@latest
  add-history hakrawler
}

function install_jwt_tool() {
  colorecho "Installing JWT tool"
  git -C /opt/tools/ clone https://github.com/ticarpi/jwt_tool
  python3 -m pip install pycryptodomex
  add-aliases jwt_tool
}

function install_jwt_cracker() {
  colorecho "Installing JWT cracker"
  apt-get -y install npm
  npm install --global jwt-cracker
}

function install_wuzz() {
  colorecho "Installing wuzz"
  go install -v github.com/asciimoo/wuzz@latest
}

function install_pypykatz() {
  colorecho "Installing pypykatz"
  python3 -m pipx install pypykatz
  add-history pypykatz
}

function install_enyx() {
  colorecho "Installing enyx"
  git -C /opt/tools/ clone https://github.com/trickster0/Enyx
  add-aliases enyx
  add-history enyx
}

function install_enum4linux-ng() {
  colorecho "Installing enum4linux-ng"
  git -C /opt/tools/ clone https://github.com/cddmp/enum4linux-ng
  add-aliases enum4linux-ng
  add-history enum4linux-ng
}

function install_git-dumper() {
  colorecho "Installing git-dumper"
  git -C /opt/tools/ clone https://github.com/arthaud/git-dumper
  cd /opt/tools/git-dumper || exit
  python3 -m pip install -r requirements.txt
  add-aliases git-dumper
}

function install_gittools() {
  colorecho "Installing GitTools"
  git -C /opt/tools/ clone https://github.com/internetwache/GitTools.git
  add-aliases gittools
}

function install_gopherus() {
  colorecho "Installing gopherus"
  git -C /opt/tools/ clone https://github.com/tarunkant/Gopherus
  cd /opt/tools/Gopherus || exit
  ./install.sh
  add-aliases install_gopherus
}

function install_ysoserial() {
  colorecho "Installing ysoserial"
  mkdir /opt/tools/ysoserial/
  wget -O /opt/tools/ysoserial/ysoserial.jar "https://jitpack.io/com/github/frohoff/ysoserial/master-SNAPSHOT/ysoserial-master-SNAPSHOT.jar"
  add-aliases ysoserial
}

function install_phpggc(){
  colorecho "Installing phpggc"
  git -C /opt/tools clone https://github.com/ambionics/phpggc.git
  add-aliases phpggc
}

function install_symfony-exploits(){
  colorecho "Installing symfony-exploits"
  git -C /opt/tools clone https://github.com/ambionics/symfony-exploits
  add-aliases symfony-exploits
}

function install_john() {
  colorecho "Installing john the ripper"
  fapt qtbase5-dev
  git -C /opt/tools/ clone https://github.com/openwall/john
  cd /opt/tools/john/src || exit
  ./configure && make
  ln -s /opt/tools/john/run/john /opt/tools/bin/john
  add-history john
}

function install_name-that-hash() {
  colorecho "Installing Name-That-Hash"
  python3 -m pipx install name-that-hash
  add-history name-that-hash
}

function install_memcached-cli() {
  colorecho "Installing memcached-cli"
  npm install -g memcached-cli
}

function install_zerologon() {
  colorecho "Pulling CVE-2020-1472 exploit and scan scripts"
  git -C /opt/tools/ clone https://github.com/SecuraBV/CVE-2020-1472
  mv /opt/tools/CVE-2020-1472 /opt/tools/zerologon-scan
  git -C /opt/tools/ clone https://github.com/dirkjanm/CVE-2020-1472
  mv /opt/tools/CVE-2020-1472 /opt/tools/zerologon-exploit
  add-aliases zerologon
  add-history zerologon
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
}

function install_checksec-py() {
  colorecho "Installing checksec.py"
  python3 -m pipx install checksec.py
  add-test-command "checksec --help"
}

function install_arsenal() {
  echo "Installing Arsenal"
  git -C /opt/tools/ clone https://github.com/Orange-Cyberdefense/arsenal
  cd /opt/tools/arsenal || exit
  python3 -m pip install -r requirements.txt
  add-aliases arsenal
}

function install_tldr() {
  colorecho "Installing tldr"
  apt-get install -y tldr
  mkdir -p ~/.local/share/tldr
  tldr -u
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
    criticalecho-noexit "This installation function doesn't support architecture $(uname -m)"
  fi
  mkdir -p ~/.config/bloodhound
  cp -v /root/sources/bloodhound/config.json ~/.config/bloodhound/config.json
  cp -v /root/sources/bloodhound/customqueries.json ~/.config/bloodhound/customqueries.json
  add-aliases bloodhound
  # TODO add-test-command
}

function install_bloodhound_old_v3() {
  colorecho "Installing Bloodhound v3 (just-in-case)"
  fapt libxss1
  wget -P /tmp/ "https://github.com/BloodHoundAD/BloodHound/releases/download/3.0.5/BloodHound-linux-x64.zip"
  unzip /tmp/BloodHound-linux-x64.zip -d /opt/tools/
  mv /opt/tools/BloodHound-linux-x64 /opt/tools/BloodHound3
  rm /tmp/BloodHound-linux-x64.zip
}

function install_bloodhound_old_v2() {
  colorecho "Installing BloodHound v2 (for older databases/collections)"
  wget -P /tmp/ https://github.com/BloodHoundAD/BloodHound/releases/download/2.2.1/BloodHound-linux-x64.zip
  unzip /tmp/BloodHound-linux-x64.zip -d /opt/tools/
  mv /opt/tools/BloodHound-linux-x64 /opt/tools/BloodHound2
  rm /tmp/BloodHound-linux-x64.zip
}

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
}

function install_hcxtools() {
  colorecho "Installing hcxtools"
  fapt libcurl4 libcurl4-openssl-dev libssl-dev openssl pkg-config
  git -C /opt/tools/ clone https://github.com/ZerBea/hcxtools
  cd /opt/tools/hcxtools/ || exit
  make
  make install
  add-history hcxtools
}

function install_hcxdumptool() {
  colorecho "Installing hcxdumptool"
  apt-get -y install libcurl4-openssl-dev libssl-dev
  git -C /opt/tools/ clone https://github.com/ZerBea/hcxdumptool
  cd /opt/tools/hcxdumptool || exit
  make
  make install
  ln -s /usr/local/bin/hcxpcapngtool /usr/local/bin/hcxpcaptool
  add-history hcxdumptool
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
}

function install_wifite2() {
  colorecho "Installing wifite2"
  git -C /opt/tools/ clone https://github.com/derv82/wifite2.git
  cd /opt/tools/wifite2/ || exit
  python3 setup.py install
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
}

function install_infoga() {
  colorecho "Installing infoga"
  git -C /opt/tools/ clone https://github.com/m4ll0k/Infoga.git
  find /opt/tools/Infoga/ -type f -print0 | xargs -0 dos2unix
  cd /opt/tools/Infoga || exit
  python setup.py install
  add-aliases infoga
  add-history infoga
}

function install_buster() {
  colorecho "Installing buster"
  git -C /opt/tools/ clone https://github.com/sham00n/buster.git
  cd /opt/tools/buster || exit
  python3 setup.py install
  add-history buster
}

function install_pwnedornot() {
  colorecho "Installing pwnedornot"
  git -C /opt/tools/ clone https://github.com/thewhiteh4t/pwnedOrNot
  add-aliases pwnedornot
}

function install_ghunt() {
  colorecho "Installing ghunt"
  apt-get update
  apt-get install -y curl unzip gnupg
  curl -sS -o - https://dl-ssl.google.com/linux/linux_signing_key.pub | apt-key add -
  echo "deb http://dl.google.com/linux/chrome/deb/ stable main" >> /etc/apt/sources.list.d/google-chrome.list
  apt-get update
  apt-get install -y google-chrome-stable
  rm -rf /var/lib/apt/lists/*
  git -C /opt/tools/ clone https://github.com/mxrch/GHunt
  cd /opt/tools/GHunt || exit
  python3 -m pip install -r requirements.txt
  add-aliases ghunt
}

function install_oaburl() {
  colorecho "Downloading oaburl.py"
  mkdir /opt/tools/OABUrl
  wget -O /opt/tools/OABUrl/oaburl.py "https://gist.githubusercontent.com/snovvcrash/4e76aaf2a8750922f546eed81aa51438/raw/96ec2f68a905eed4d519d9734e62edba96fd15ff/oaburl.py"
  chmod +x /opt/tools/OABUrl/oaburl.py
  add-aliases oaburl
  add-history oaburl
}

function install_libmspack() {
  colorecho "Installing libmspack"
  git -C /opt/tools/ clone https://github.com/kyz/libmspack.git
  cd /opt/tools/libmspack/libmspack || exit
  ./rebuild.sh
  ./configure
  make
  add-aliases libmspack
}

function install_peas_offensive() {
  colorecho "Installing PEAS-Offensive"
  git -C /opt/tools/ clone https://github.com/snovvcrash/peas.git peas-offensive
  python3 -m pip install pipenv
  cd /opt/tools/peas-offensive || exit
  pipenv --python 2.7 install -r requirements.txt
}

function install_ruler() {
  colorecho "Downloading ruler and form templates"
  mkdir -p /opt/tools/ruler/templates
  wget -O /opt/tools/ruler/ruler "$(curl -s https://github.com/sensepost/ruler/releases/latest | grep -o '"[^"]*"' | tr -d '"' | sed 's/tag/download/')/ruler-linux64"
  chmod +x /opt/tools/ruler/ruler
  ln -s /opt/tools/ruler/ruler /opt/tools/bin/ruler
  wget -O /opt/tools/ruler/templates/formdeletetemplate.bin "https://github.com/sensepost/ruler/raw/master/templates/formdeletetemplate.bin"
  wget -O /opt/tools/ruler/templates/formtemplate.bin "https://github.com/sensepost/ruler/raw/master/templates/formtemplate.bin"
  wget -O /opt/tools/ruler/templates/img0.bin "https://github.com/sensepost/ruler/raw/master/templates/img0.bin"
  wget -O /opt/tools/ruler/templates/img1.bin "https://github.com/sensepost/ruler/raw/master/templates/img1.bin"
  add-history ruler
}

function install_ghidra() {
  colorecho "Installing Ghidra"
  apt-get install -y openjdk-11-jdk
  #wget -P /tmp/ "https://ghidra-sre.org/ghidra_9.2.3_PUBLIC_20210325.zip"
  wget -P /tmp/ "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_10.1.2_build/ghidra_10.1.2_PUBLIC_20220125.zip"
  unzip /tmp/ghidra_10.1.2_PUBLIC_20220125.zip -d /opt/tools
  rm /tmp/ghidra_10.1.2_PUBLIC_20220125.zip
  add-aliases ghidra
  # TODO add-test-command GUI app
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
    criticalecho-noexit "This installation function doesn't support architecture $(uname -m), IDA Free only supports x86/x64"
  fi
  add-aliases ida
  # TODO add-test-command GUI app
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
}

function install_linkedin2username() {
  colorecho "Installing linkedin2username"
  git -C /opt/tools/ clone https://github.com/initstring/linkedin2username
  cd /opt/tools/linkedin2username || exit
  python3 -m python -m pip install -r requirements.txt
  add-aliases linkedin2username
  add-history linkedin2username
}

function install_toutatis() {
  colorecho "Installing toutatis"
  git -C /opt/tools/ clone https://github.com/megadose/toutatis
  cd /opt/tools/toutatis || exit
  python3 setup.py install
  add-aliases toutatis
  add-history toutatis
}

function install_carbon14() {
  colorecho "Installing Carbon14"
  git -C /opt/tools/ clone https://github.com/Lazza/Carbon14
  cd /opt/tools/Carbon14 || exit
  python3 -m pip install -r requirements.txt
  add-aliases carbon14
  add-history carbon14
}

function install_youtubedl() {
  colorecho "Installing youtube-dl"
  python3 -m pipx install youtube-dl
}

function install_ipinfo() {
  colorecho "Installing ipinfo"
  sudo npm install ipinfo-cli --global
  add-history ipinfo
}

function install_constellation() {
  colorecho "Installing constellation"
  cd /opt/tools/ || exit
  wget https://github.com/constellation-app/constellation/releases/download/v2.1.1/constellation-linux-v2.1.1.tar.gz
  tar xvf constellation-linux-v2.1.1.tar.gz
  rm constellation-linux-v2.1.1.tar.gz
  ln -s /opt/tools/constellation/bin/constellation /opt/tools/bin/constellation
}

function install_holehe() {
  colorecho "Installing holehe"
  python3 -m pipx install holehe
  add-history holehe
}

function install_twint() {
  colorecho "Installing twint"
  python3 -m pipx install twint
  add-history twint
}

function install_tiktokscraper() {
  colorecho "Installing tiktok-scraper"
  npm i -g tiktok-scraper
  add-history tiktok-scraper
}

function install_h8mail() {
  colorecho "Installing h8mail"
  python3 -m pipx install h8mail
  add-history h8mail
}

function install_phoneinfoga() {
  colorecho "Installing phoneinfoga"
  curl -sSL https://raw.githubusercontent.com/sundowndev/PhoneInfoga/master/support/scripts/install | bash
  sudo mv ./phoneinfoga /opt/tools/bin
  add-history phoneinfoga
}

function install_windapsearch-go() {
  colorecho "Installing Go windapsearch"
  if [[ $(uname -m) = 'x86_64' ]]
  then
    wget -O /opt/tools/bin/windapsearch "$(curl -o /dev/null -Ls -w %{url_effective} https://github.com/ropnop/go-windapsearch/releases/latest/ |  sed 's/tag/download/')/windapsearch-linux-amd64"
  else
    criticalecho-noexit "This installation function doesn't support architecture $(uname -m)"
  fi
  chmod +x /opt/tools/bin/windapsearch
  add-history windapsearch
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
}

function install_ntlmv1-multi() {
  colorecho "Installing ntlmv1 multi tool"
  git -C /opt/tools clone https://github.com/evilmog/ntlmv1-multi
  add-aliases ntlmv1-multi
  add-history ntlmv1-multi
}

function install_droopescan() {
  colorecho "Installing droopescan"
  git -C /opt/tools clone https://github.com/droope/droopescan.git
  cd /opt/tools/droopescan || exit
  python3 -m pip install -r requirements.txt
  python3 setup.py install
}

function install_drupwn() {
  colorecho "Installing drupwn"
  git -C /opt/tools clone https://github.com/immunIT/drupwn.git
  cd /opt/tools/drupwn || exit
  python3 setup.py install
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
    criticalecho-noexit "This installation function doesn't support architecture $(uname -m)"
  fi
  install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl
  add-test-command "kubectl --help"
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
    criticalecho-noexit "This installation function doesn't support architecture $(uname -m)"
  fi
  unzip awscliv2.zip
  ./aws/install -i /opt/tools/aws-cli -b /usr/local/bin
  rm -rf aws
  rm awscliv2.zip
  add-test-command "aws --version"
}

function install_scout() {
  colorecho "Installing ScoutSuite"
  python3 -m pipx install scoutsuite
  add-test-command "scout --help"
}

function install_jdwp_shellifier(){
  colorecho "Installing jdwp_shellifier"
  git -C /opt/tools/ clone https://github.com/IOActive/jdwp-shellifier.git
  add-aliases jdwp_shellifier
}

function install_maigret_pip() {
  colorecho "Installing maigret"
  python3 -m pipx install maigret
  add-history maigret
}

function install_amber() {
  colorecho "Installing amber"
  go install -v github.com/EgeBalci/amber@latest
  add-history amber
}

function install_hashonymize() {
  colorecho "Installing hashonymizer"
  git -C /opt/tools/ clone https://github.com/ShutdownRepo/hashonymize
  cd /opt/tools/hashonymize || exit
  python3 setup.py install
}

function install_theharvester() {
  colorecho "Installing theHarvester"
  git -C /opt/tools/ clone https://github.com/laramies/theHarvester
  python3 -m pip install -r theHarvester/requirements.txt
  add-aliases theharvester
  add-history theharvester
}

function install_pcsc() {
  colorecho "Installing tools for PC/SC (smartcard)"
  apt-get install -y pcsc-tools pcscd libpcsclite-dev libpcsclite1
}

function install_libnfc() {
  colorecho "Installing libnfc"
  apt-get install -y libnfc-dev libnfc-bin
  # TODO fixme
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
}

function install_mfcuk() {
  colorecho "Installing mfcuk"
  apt-get install -y mfcuk
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
}

function install_mfdread() {
  colorecho "Installing mfdread"
  pip3 install bitstring
  git -C /opt/tools/ clone https://github.com/zhovner/mfdread
  add-aliases mfdread
  add-history mfdread
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
}

function install_jackit() {
  colorecho "Installing jackit"
  git -C /opt/tools/ clone https://github.com/insecurityofthings/jackit
  cd /opt/tools/jackit || exit
  pip install -e .
  add-history jackit
}

function install_gosecretsdump() {
  colorecho "Installing gosecretsdump"
  git -C /opt/tools/ clone https://github.com/c-sto/gosecretsdump
  go install -v github.com/C-Sto/gosecretsdump@latest
  add-history gosecretsdump
}

function install_hackrf() {
  colorecho "Installing HackRF tools"
  apt-get -y install hackrf
}

function install_gqrx() {
  colorecho "Installing gqrx"
  apt-get -y install gqrx-sdr
}

function install_sipvicious() {
  colorecho "Installing SIPVicious"
  git -C /opt/tools/ clone https://github.com/enablesecurity/sipvicious.git
  cd /opt/tools/sipvicious/ || exit
  python3 setup.py install
}

function install_httpmethods() {
  colorecho "Installing httpmethods"
  git -C /opt/tools/ clone https://github.com/ShutdownRepo/httpmethods
  cd /opt/tools/httpmethods || exit
  python3 setup.py install
  add-history httpmethods
}

function install_adidnsdump() {
  colorecho "Installing adidnsdump"
  python3 -m pipx install git+https://github.com/dirkjanm/adidnsdump
  add-history adidnsdump
}

function install_dnschef() {
  colorecho "Installing DNSChef"
  git -C /opt/tools/ clone https://github.com/iphelix/dnschef
  add-aliases dnschef
}

function install_h2csmuggler() {
  colorecho "Installing h2csmuggler"
  git -C /opt/tools/ clone https://github.com/BishopFox/h2csmuggler
  python3 -m pipx install h2
  add-aliases h2csmuggler
}

function install_byp4xx() {
  colorecho "Installing byp4xx"
  git -C /opt/tools/ clone https://github.com/lobuhi/byp4xx
  add-aliases byp4xx
}

function install_pipx() {
  colorecho "Installing pipx"
  python3 -m pip install pipx
  pipx ensurepath
}

function install_peepdf() {
  colorecho "Installing peepdf"
  fapt libjpeg-dev
  python2.7 -m pip install peepdf
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
  add-aliases volatility
  add-test-command "volatility --help"
}

function install_zsteg() {
  colorecho "Installing zsteg"
  gem install zsteg
  add-test-command "zsteg --help"
}

function install_stegolsb() {
  colorecho "Installing stegolsb"
  python3 -m pipx install stego-lsb
  add-test-command "stegolsb --version"
}

function install_whatportis() {
  colorecho "Installing whatportis"
  python3 -m pipx install whatportis
  echo y | whatportis --update
  add-history whatportis
}

function install_ultimate_vimrc() {
  colorecho "Installing The Ultimate vimrc"
  git clone --depth=1 https://github.com/amix/vimrc.git ~/.vim_runtime
  sh ~/.vim_runtime/install_awesome_vimrc.sh
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
    criticalecho-noexit "This installation function doesn't support architecture $(uname -m)"
  fi
  unzip -d /opt/tools/bin/ /tmp/ngrok.zip
  add-history ngrok
}

function install_chisel() {
  colorecho "Installing chisel"
  go install github.com/jpillora/chisel@latest -v
  #FIXME: add windows pre-compiled binaries in /opt/ressources/windows?
}

function install_sshuttle() {
  colorecho "Installing sshtuttle"
  git -C /opt/tools/ clone https://github.com/sshuttle/sshuttle.git
  cd /opt/tools/sshuttle || exit
  python3 setup.py install
}

function install_pygpoabuse() {
  colorecho "Installing pyGPOabuse"
  git -C /opt/tools/ clone https://github.com/Hackndo/pyGPOAbuse
  add-aliases pygpoabuse
}

function install_rsactftool() {
  colorecho "Installing RsaCtfTool"
  git -C /opt/tools/ clone https://github.com/Ganapati/RsaCtfTool
  cd /opt/tools/RsaCtfTool || exit
  apt-get -y install libgmp3-dev libmpc-dev
  python3 -m pip install -r requirements.txt
  add-aliases rsactftool
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
}

function install_bloodhound-import() {
  colorecho "Installing bloodhound-import"
  python3 -m pipx install bloodhound-import
  add-history bloodhound-import
}

function install_bloodhound-quickwin() {
  colorecho "Installing bloodhound-quickwin"
  python3 -m pip install py2neo pandas prettytable
  git -C /opt/tools/ clone https://github.com/kaluche/bloodhound-quickwin
  add-aliases bloodhound-quickwin
  add-history bloodhound-quickwin
}

function install_ldapsearch-ad() {
  colorecho "Installing ldapsearch-ad"
  git -C /opt/tools/ clone https://github.com/yaap7/ldapsearch-ad
  cd /opt/tools/ldapsearch-ad/ || exit
  python3 -m pip install -r requirements.txt
  add-aliases ldapsearch-ad
  add-history ldapsearch-ad
  add-history ldapsearch
}

function install_ntlm-scanner() {
  colorecho "Installing ntlm-scanner"
  git -C /opt/tools/ clone https://github.com/preempt/ntlm-scanner
  add-aliases ntlm-scanner
  add-history ntlm-scanner
}

function install_rustscan() {
  colorecho "Installing RustScan"
  source "$HOME/.cargo/env"
  cargo install rustscan
}

function install_divideandscan() {
  colorecho "Installing DivideAndScan"
  python3 -m pipx install git+https://github.com/snovvcrash/DivideAndScan
  add-history divideandscan
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
  add-test-command "trid | grep 'This help'"
}

function install_pcredz() {
  colorecho "Installing PCredz"
  python3 -m pip install Cython
  fapt libpcap-dev
  python3 -m pip install Cython python-libpcap
  git -C /opt/tools/ clone https://github.com/lgandx/PCredz
  add-aliases pcredz
}

function install_smartbrute() {
  colorecho "Installing smartbrute"
  git -C /opt/tools/ clone https://github.com/ShutdownRepo/smartbrute
  cd /opt/tools/smartbrute || exit
  python3 -m pip install -r requirements.txt
  add-aliases smartbrute
  add-test-command "smartbrute --help"
}

function install_frida() {
  colorecho "Installing frida"
  python3 -m pipx install frida-tools
}

function install_androguard() {
  colorecho "Installing androguard"
  python3 -m pipx install androguard
}

function install_petitpotam() {
  colorecho "Installing PetitPotam"
  git -C /opt/tools/ clone https://github.com/ly4k/PetitPotam
  mv /opt/tools/PetitPotam /opt/tools/PetitPotam_alt
  git -C /opt/tools/ clone https://github.com/topotam/PetitPotam
  add-aliases petitpotam
  add-history petitpotam
}

function install_dfscoerce() {
  colorecho "Installing DfsCoerce"
  git -C /opt/tools/ clone https://github.com/Wh04m1001/DFSCoerce.git
  add-aliases dfscoerce
  add-history dfscoerce
}

function install_coercer() {
  colorecho "Installing Coercer"
  python3 -m pipx install git+https://github.com/p0dalirius/Coercer
  add-history coercer
}

function install_PKINITtools() {
  colorecho "Installing PKINITtools"
  git -C /opt/tools/ clone https://github.com/dirkjanm/PKINITtools
  add-aliases pkinittools
  add-history pkinittools
}

function install_pywhisker() {
  colorecho "Installing pyWhisker"
  git -C /opt/tools/ clone https://github.com/ShutdownRepo/pywhisker
  cd /opt/tools/pywhisker || exit
  python3 -m pip install -r requirements.txt
  add-aliases pywhisker
  add-history pywhisker
}

function install_targetedKerberoast() {
  colorecho "Installing targetedKerberoast"
  git -C /opt/tools/ clone https://github.com/ShutdownRepo/targetedKerberoast
  cd /opt/tools/targetedKerberoast || exit
  python3 -m pip install -r requirements.txt
  add-aliases targetedkerberoast
  add-history targetedkerberoast
}

function install_manspider() {
  colorecho "Installing MANSPIDER"
  #git -C /opt/tools/ clone https://github.com/blacklanternsecurity/MANSPIDER
  fapt antiword
  install_tesseract-ocr
  python3 -m pipx install git+https://github.com/blacklanternsecurity/MANSPIDER
  add-history manspider
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
}

function install_ignorant() {
  colorecho "Installing ignorant"
  python3 -m pipx install git+https://github.com/megadose/ignorant
}

function install_donpapi() {
  colorecho "Installing DonPAPI"
  git -C /opt/tools/ clone https://github.com/login-securite/DonPAPI.git
  python3 -m pip install -r /opt/tools/DonPAPI/requirements.txt
  add-aliases donpapi
  add-history donpapi
}

function install_gau() {
  colorecho "Installing gau"
  GO111MODULE=on go install -v github.com/lc/gau@latest
}

function install_webclientservicescanner() {
  colorecho "Installing webclientservicescanner"
  git -C /opt/tools/ clone https://github.com/Hackndo/WebclientServiceScanner
  cd /opt/tools/WebclientServiceScanner || exit
  python3 setup.py install
  add-history webclientservicescanner
}

function install_certipy() {
  colorecho "Installing Certipy"
  python3 -m pipx install git+https://github.com/ly4k/Certipy
  add-history certipy
}

function install_eaphammer() {
  # Debian port : working ?
  colorecho "Installing EPA hammer"
  git -C /opt/tools/ clone https://github.com/s0lst1c3/eaphammer
  cd /opt/tools/eaphammer || exit
  echo y | ./kali-setup
  add-aliases eaphammer
}

function install_vulny-code-static-analysis() {
  colorecho "Installing Vulny Code Static Analysis"
  git -C /opt/tools/ clone https://github.com/swisskyrepo/Vulny-Code-Static-Analysis
  add-aliases vulny-code-static-analysis
  add-test-command "vulny-code-static-analysis --help"
}

function install_nuclei() {
  # Vulnerability scanner
  colorecho "Installing Nuclei"
  go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
  nuclei -update-templates
  add-history nuclei
}

function install_prips() {
  # Print the IP addresses in a given range
  colorecho "Installing Prips"
  fapt prips
  add-history prips
}

function install_hakrevdns() {
  # Reverse DNS lookups
  colorecho "Installing Hakrevdns"
  go install github.com/hakluke/hakrevdns@latest
  add-history hakrevdns
}

function install_httprobe() {
  colorecho "Installing httprobe"
  go install -v github.com/tomnomnom/httprobe@latest
}

function install_httpx() {
  colorecho "Installing httpx"
  go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
  add-history httpx
}

function install_anew() {
  colorecho "Installing anew"
  go install -v github.com/tomnomnom/anew@latest
}

function install_naabu() {
  colorecho "Installing naabu"
  apt-get install -y libpcap-dev
  go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
}

function install_tor() {
  colorecho "Installing tor"
  mkdir /opt/tools/tor
  cd /opt/tools/tor || exit
  wget https://dist.torproject.org/tor-0.4.3.7.tar.gz
  tar xf tor-0.4.3.7.tar.gz
  cd tor-0.4.3.7 || exit
  apt-get install libevent-dev
  ./configure
  make install
}

function install_pwndb() {
  colorecho "Installing pwndb"
  git -C /opt/tools/ clone https://github.com/davidtavarez/pwndb.git
  cd /opt/tools/pwndb || exit
  chmod +x pwndb.py
  add-aliases pwndb
  add-history pwndb
}

function install_robotstester() {
  # This Python script can enumerate all URLs present in robots.txt files, and test whether they can be accessed or not.
  # https://github.com/p0dalirius/robotstester
  colorecho "Installing Robotstester"
  python3 -m pipx install git+https://github.com/p0dalirius/robotstester
  add-history robotstester
}

function install_finduncommonshares() {
  colorecho "Installing FindUncommonShares"
  git -C /opt/tools/ clone https://github.com/p0dalirius/FindUncommonShares
  cd /opt/tools/FindUncommonShares/ || exit
  python3 -m pip install -r requirements.txt
  add-aliases finduncommonshares
  add-history finduncommonshares
}

function install_shadowcoerce() {
  colorecho "Installing ShadowCoerce PoC"
  git -C /opt/tools/ clone https://github.com/ShutdownRepo/ShadowCoerce
  add-aliases shadowcoerce
  add-history shadowcoerce
}

function install_pwncat() {
  colorecho "Installing pwncat"
  python3 -m pipx install pwncat-cs
}

function install_gmsadumper() {
  colorecho "Installing gMSADumper"
  git -C /opt/tools/ clone https://github.com/micahvandeusen/gMSADumper
  add-aliases gmsadumper
  add-history gmsadumper
}

function install_modifyCertTemplate() {
  colorecho "Installing modifyCertTemplate"
  git -C /opt/tools/ clone https://github.com/fortalice/modifyCertTemplate
  add-aliases modifycerttemplate
  add-history modifycerttemplate
}

function install_pylaps() {
  colorecho "Installing pyLAPS"
  git -C /opt/tools/ clone https://github.com/p0dalirius/pyLAPS
  add-history pylaps
}

function install_ldaprelayscan() {
  colorecho "Installing LdapRelayScan"
  git -C /opt/tools/ clone https://github.com/zyn3rgy/LdapRelayScan
  cd /opt/tools/LdapRelayScan || exit
  python3 -m pip install -r requirements.txt
  add-aliases ldaprelayscan
  add-history ldaprelayscan
}

function install_goldencopy() {
  colorecho "Installing GoldenCopy"
  python3 -m pipx install goldencopy
  add-aliases goldencopy
  add-history goldencopy
}

function install_crackhound() {
  colorecho "Installing CrackHound"
  git -C /opt/tools/ clone https://github.com/trustedsec/CrackHound
  add-aliases crackhound
  add-history crackhound
}

function install_kerbrute() {
  colorecho "Installing Kerbrute"
  wget https://github.com/ropnop/kerbrute/releases/latest/download/kerbrute_linux_amd64 -O /opt/tools/bin/kerbrute
  chmod +x /opt/tools/bin/kerbrute
  add-history kerbrute
}

function install_searchsploit() {
  colorecho "Installing Searchsploit"
  git clone https://github.com/offensive-security/exploitdb.git /opt/exploitdb
  ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit
  cp -n /opt/exploitdb/.searchsploit_rc ~/
  sed -i 's/\(.*[pP]aper.*\)/#\1/' ~/.searchsploit_rc
  searchsploit -u
}

function install_seclists(){
  colorecho "Installing Seclists"
  git -C /usr/share/ clone https://github.com/danielmiessler/SecLists.git seclists
  cd /usr/share/seclists || exit
  rm -r LICENSE .git* CONTRIBUT* .bin
}

function install_rockyou(){
  colorecho "Installing rockyou"
  mkdir /usr/share/wordlists
  tar -xvf /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt.tar.gz -C /usr/share/wordlists/
  ln -s /usr/share/seclists/ /usr/share/wordlists/seclists
}

function install_amass(){
  colorecho "Installing Amass"
  go install -v github.com/OWASP/Amass/v3/...@master
}

function install_maltego(){
  colorecho "Installing Maltego"
  wget https://maltego-downloads.s3.us-east-2.amazonaws.com/linux/Maltego.v4.3.0.deb -O /tmp/maltegov4.3_package.deb
  dpkg -i /tmp/maltegov4.3_package.deb
}

function install_spiderfoot(){
  colorecho "Installing Spiderfoot"
  git -C /opt/tools/ clone https://github.com/smicallef/spiderfoot.git # depends on alias declaration in order to work
  add-aliases spiderfoot
}

function install_finalrecon(){
  colorecho "Installing FinalRecon"
  git -C /opt/tools/ clone https://github.com/thewhiteh4t/FinalRecon.git
  cd /opt/tools/FinalRecon || exit
  pip3 install -r requirements.txt
}

function install_xsser(){
  colorecho "Installing xsser"
  pip3 install pycurl bs4 pygeoip gobject cairocffi selenium
}

function install_joomscan(){
  colorecho "Installing joomscan"
  git -C /opt/tools/ clone https://github.com/rezasp/joomscan.git
  add-aliases joomscan
}

function install_wpscan(){
  colorecho "Installing wpscan"
  apt-get install -y procps ruby-dev
  apt-get install -y apt-transport-https ca-certificates gnupg2 curl
  curl -sSL https://rvm.io/pkuczynski.asc | gpg2 --import -
  curl -sSL https://get.rvm.io | bash -s stable --ruby
  gem install nokogiri
  gem install wpscan
  add-history wpscan
}

function install_padbuster(){
  colorecho "Installing padbuster"
  git -C /opt/tools/ clone https://github.com/AonCyberLabs/PadBuster
  add-aliases padbuster
}

function install_go(){
  colorecho "Installing go (Golang)"
  cd /tmp/ || exit
  if [[ $(uname -m) = 'x86_64' ]]
  then
    wget -O /tmp/go.tar.gz https://go.dev/dl/go1.18.2.linux-amd64.tar.gz
  elif [[ $(uname -m) = 'aarch64' ]]
  then
    wget -O /tmp/go.tar.gz https://go.dev/dl/go1.18.2.linux-arm64.tar.gz
  elif [[ $(uname -m) = 'armv7l' ]]
  then
    wget -O /tmp/go.tar.gz https://go.dev/dl/go1.18.2.linux-armv6l.tar.gz
  else
    criticalecho-noexit "This installation function doesn't support architecture $(uname -m)"
  fi
  rm -rf /usr/local/go
  tar -C /usr/local -xzf /tmp/go.tar.gz
  export PATH=$PATH:/usr/local/go/bin
}

function install_metasploit(){
  colorecho "Installing Metasploit"
  mkdir /tmp/metasploit_install
  cd /tmp/metasploit_install || exit
  curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && chmod 755 msfinstall && ./msfinstall
  cd /opt/tools || exit
  rm -rf /tmp/metasploit_install
}

function install_smbmap(){
  colorecho "Installing smbmap"
  git -C /opt/tools/ clone -v https://github.com/ShawnDEvans/smbmap
  cd /opt/tools/smbmap || exit
  # installing requirements manually to skip impacket overwrite
  # wish we could install smbmap in virtual environment :'(
  python3 -m pip install pyasn1 pycrypto configparser termcolor
  add-aliases smbmap
  add-history smbmap
}

function install_pth-tools(){
  colorecho "Installing pth-tools"
  git -C /opt/tools clone -v https://github.com/byt3bl33d3r/pth-toolkit
  cd /opt/tools/pth-toolkit || exit
  for bin_name in pth*; do ln -s "/opt/tools/pth-toolkit/$bin_name" "/opt/tools/bin/$bin_name"; done
  add-history pth-tools
}

function install_smtp-user-enum(){
  colorecho "Installing smtp-user-enum"
  python3 -m pipx install smtp-user-enum
  add-history smtp-user-enum
}

function install_gpp-decrypt(){
  colorecho "Installing gpp-decrypt"
  python3 -m pip install pycrypto colorama
  git -C /opt/tools/ clone -v https://github.com/t0thkr1s/gpp-decrypt
  add-aliases gpp-decrypt
}

function install_smali(){
  colorecho "Installing smali"
  apt-get install default-jre wget
  mkdir /opt/tools/smali/
  wget https://bitbucket.org/JesusFreke/smali/downloads/smali-2.5.2.jar -O /opt/tools/smali/smali-2.5.2.jar
  add-aliases smali
}

function install_tesseract-ocr(){
  colorecho "Installing tesseract-ocr"
  apt-get install -y tesseract-ocr
}

function install_dex2jar(){
  colorecho "Installing dex2jar"
  mkdir /opt/tools/dex2jar/ && cd /opt/tools/dex2jar || exit
  wget https://github.com/pxb1988/dex2jar/releases/latest/download/dex2jar-2.1.zip -O dex2jar.zip
  unzip dex2jar.zip
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
}

function install_radare2(){
  colorecho "Installing radare2"
  git -C /opt/tools/ clone https://github.com/radareorg/radare2
  /opt/tools/radare2/sys/install.sh
  add-test-command "radare2 -h"
}

function install_jd-gui(){
  colorecho "Installing jd-gui"
  mkdir -p /opt/tools/jd-gui && cd /opt/tools/jd-gui || exit
  wget https://github.com/java-decompiler/jd-gui/releases/download/v1.6.6/jd-gui-1.6.6.jar
  add-aliases jd-gui
  # TODO add-test-command GUI app
}

function install_rust_cargo() {
  colorecho "Installing rustc, cargo, rustup"
  curl https://sh.rustup.rs -sSf | sh -s -- -y
  source "$HOME/.cargo/env"
}

function install_fierce() {
  colorecho "Installing fierce"
  python3 -m pipx install git+https://github.com/mschwager/fierce
  add-history fierce
}

function install_yarn() {
  colorecho "Installing yarn"
  curl -sS https://dl.yarnpkg.com/debian/pubkey.gpg | apt-key add -
  echo "deb https://dl.yarnpkg.com/debian/ stable main" | tee /etc/apt/sources.list.d/yarn.list
  apt update
  apt install -y yarn
}

function install_aircrack-ng() {
  colorecho "Installing aircrack-ng"
  fapt aircrack-ng
  add-aliases aircrack-ng
  add-history aircrack-ng
}

function install_emacs-nox() {
  colorecho "Installing emacs-nox"
  fapt emacs-nox
  add-aliases emacs-nox
}

function install_nmap() {
  colorecho "Installing nmap"
  fapt nmap
  add-aliases nmap
  add-history nmap
}

function install_php() {
  colorecho "Installing php"
  fapt php
  add-aliases php
}

function install_python3-pyftpdlib() {
  colorecho "Installing python3-pyftpdlib"
  fapt python3-pyftpdlib
  add-aliases pyftpdlib
  add-history pyftpdlib
}

function install_python3() {
  colorecho "Installing python3"
  fapt python3
  add-aliases python3
}

function install_libxml2-utils() {
  colorecho "Installing libxml2-utils"
  fapt libxml2-utils
  add-aliases xmllint
}

function install_xsel() {
  colorecho "Installing xsel"
  fapt xsel
  add-aliases xsel
}

function install_cewl() {
  colorecho "Installing cewl"
  fapt cewl
  add-history cewl
}

function install_curl() {
  colorecho "Installing curl"
  fapt curl
  add-history curl
}

function install_dirb() {
  colorecho "Installing dirb"
  fapt dirb
  add-history dirb
}

function install_dnsutils() {
  colorecho "Installing dnsutils"
  fapt dnsutils
  add-history dnsutils
}

function install_faketime() {
  colorecho "Installing faketime"
  fapt faketime
  add-history faketime
}

function install_fcrackzip() {
  colorecho "Installing fcrackzip"
  fapt fcrackzip
  add-history fcrackzip
}

function install_hashcat() {
  colorecho "Installing hashcat"
  fapt hashcat
  add-history hashcat
}

function install_ldapdomaindump() {
  colorecho "Installing ldapdomaindump"
  pipx install git+https://github.com/dirkjanm/ldapdomaindump
  add-history ldapdomaindump
  add-test-command "ldapdomaindump --help"
}

function install_masscan() {
  colorecho "Installing masscan"
  fapt masscan
  add-history masscan
}

function install_nbtscan() {
  colorecho "Installing nbtscan"
  fapt nbtscan
  add-history nbtscan
}

function install_ntpdate() {
  colorecho "Installing ntpdate"
  fapt ntpdate
  add-history ntpdate
}

function install_onesixtyone() {
  colorecho "Installing onesixtyone"
  fapt onesixtyone
  add-history onesixtyone
}

function install_polenum() {
  colorecho "Installing polenum"
  fapt polenum
  add-history polenum
}

function install_rlwrap() {
  colorecho "Installing rlwrap"
  fapt rlwrap
  add-history rlwrap
}

function install_samba() {
  colorecho "Installing samba"
  fapt samba
  add-history samba
}

function install_smbclient() {
  colorecho "Installing smbclient"
  fapt smbclient
  add-history smbclient
}

function install_snmp() {
  colorecho "Installing snmp"
  fapt snmp
  add-history snmp
}

function install_sqlmap() {
  colorecho "Installing sqlmap"
  fapt sqlmap
  add-history sqlmap
}

function install_ssh() {
  colorecho "Installing ssh"
  fapt ssh
  add-history ssh
}

function install_wfuzz() {
  colorecho "Installing wfuzz"
  fapt wfuzz
  add-history wfuzz
}

function install_freerdp2-x11() {
  colorecho "Installing freerdp2-x11"
  fapt freerdp2-x11
  add-history xfreerdp
}

# Package dedicated to the basic things the env needs
function package_base() {
  export PIPELINE_TESTS_FILE="package_base"
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
  # fapt gifsicle
  fapt sudo                       # Sudo
  install_curl                    # HTTP handler
  fapt wget                       # Wget
  fapt gnupg2                     # gnugpg
  install_python3-pyftpdlib          # FTP server python library
  install_php                        # Php language
  fapt python2                    # Python 2 language
  install_python3                    # Python 3 language
  fapt python2-dev                # Python 2 language (dev version)
  fapt python3-dev                # Python 3 language (dev version)
  fapt python3-venv
  fapt libffi-dev
  install_rust_cargo
  ln -s /usr/bin/python2.7 /usr/bin/python  # fix shit
  install_python-pip                      # Pip
  fapt python3-pip                # Pip
  python3 pip install --upgrade pip
  filesystem
  install_go                      # Golang language
  set_go_env
  install_locales
  install_tmux                            # Tmux
  fapt zsh                        # Awesome shell
  install_ohmyzsh                         # Awesome shell
  install_tldr                    # TL;DR man
  fapt python-setuptools
  fapt python3-setuptools
  python3 -m pip install wheel
  python -m pip install wheel
  install_pipx
  install_fzf                             # File fuzzer
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
  install_mdcat                           # cat markdown files
  install_bat                             # Beautiful cat
  fapt tidy
  fapt mlocate
  install_xsel
  fapt libtool
  install_dnsutils                   # DNS utilities like dig and nslookup
  fapt dos2unix                   # Convert encoded dos script
  DEBIAN_FRONTEND=noninteractive fapt macchanger  # Macchanger
  install_samba                      # Samba
  fapt ftp                        # FTP client
  install_ssh                        # SSH client
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
  fapt-noexit rar                        # rar
  fapt unrar                      # unrar
  fapt xz-utils                   # xz (de)compression
  fapt xsltproc                   # apply XSLT stylesheets to XML documents (Nmap reports)
  fapt parallel
  fapt tree
  install_faketime
  fapt ruby ruby-dev
  install_libxml2-utils
  install_exegol-history
  install_logrotate
}

# Package dedicated to offensive miscellaneous tools
function package_misc() {
  export PIPELINE_TESTS_FILE="package_misc"
  set_go_env
  install_goshs                   # Web uploader/downloader page
  install_searchsploit            # Exploitdb local search engine
  install_rlwrap                     # Reverse shell utility
  install_shellerator             # Reverse shell generator
  install_uberfile                # file uploader/downloader commands generator
  install_arsenal                         # Cheatsheets tool
  install_trilium                 # notes taking tool
  fapt exiftool                   # Meta information reader/writer
  fapt imagemagick                # Copy, modify, and distribute image
  install_ngrok                   # expose a local development server to the Internet
  install_whatportis              # Search default port number
  fapt ascii                      # The ascii table in the shell
}

# Package dedicated to most used offensive tools
function package_most_used() {
  export PIPELINE_TESTS_FILE="package_most_used"
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
  install_sqlmap                     # SQL injection scanner
  fapt hydra                      # Login scanner
  install_joomscan                # Joomla scanner
  install_wpscan                  # Wordpress scanner
  install_droopescan              # Drupal scanner
  install_drupwn                  # Drupal scanner
  install_testssl                 # SSL/TLS scanner
  fapt sslscan                    # SSL/TLS scanner
  fapt weevely                    # Awesome secure and light PHP webshell
  install_cloudfail               # Cloudflare misconfiguration detector
  install_eyewitness              # Website screenshoter
  install_wafw00f                 # Waf detector
  install_jwt_tool                # Toolkit for validating, forging, scanning and tampering JWTs
  install_gittools                # Dump a git repository from a website
  install_ysoserial               # Deserialization payloads
  install_responder               # LLMNR, NBT-NS and MDNS poisoner
  install_crackmapexec            # Network scanner
  install_impacket                # Network protocols scripts
  install_enum4linux-ng                   # Active Directory enumeration tool, improved Python alternative to enum4linux
  install_smbclient                  # Small dynamic library that allows iOS apps to access SMB/CIFS file servers
  install_smbmap                  # Allows users to enumerate samba share drives across an entire domain
  install_nuclei                  # Vulnerability scanner
  install_evilwinrm                       # WinRM shell
  install_john                    # Password cracker
  install_hashcat                    # Password cracker
  install_fcrackzip                  # Zip cracker
}

# Package dedicated to the installation of wordlists and tools like wl generators
function package_wordlists() {
  export PIPELINE_TESTS_FILE="package_wordlists"
  set_go_env
  fapt crunch                     # Wordlist generator
  install_seclists                # Awesome wordlists
  install_rockyou                 # Basically installs rockyou (~same as Kali)
  install_cewl                    # Wordlist generator
  fapt cupp                       # User password profiler
  install_pass_station            # Default credentials database
  install_username-anarchy        # Generate possible usernames based on heuristics
}

# Package dedicated to offline cracking/bruteforcing tools
function package_cracking() {
  export PIPELINE_TESTS_FILE="package_cracking"
  set_go_env
  install_hashcat                    # Password cracker
  install_john                    # Password cracker
  fapt fcrackzip                  # Zip cracker
  fapt pdfcrack                   # PDF cracker
  fapt bruteforce-luks            # Find the password of a LUKS encrypted volume
  install_name-that-hash                     # Name-That-Hash, the hash identifier tool
}

# Package dedicated to osint, recon and passive tools
function package_osint() {
  export PIPELINE_TESTS_FILE="package_osint"
  set_go_env
  # Picture And Videos
  install_youtubedl                       # Command-line program to download videos from YouTube.com and other video sites
  fapt exiftool                   # For read exif information
  fapt exifprobe                  # Probe and report structure and metadata content of camera image files
  # Subdomain
  install_sublist3r                       # Fast subdomains enumeration tool
  install_assetfinder                     # Find domains and subdomains potentially related to a given domain
  install_subfinder               # Subfinder is a subdomain discovery tool that discovers valid subdomains for websites
  install_amass                   # OWASP Amass tool suite is used to build a network map of the target
  install_findomain                       # Findomain Monitoring Service use OWASP Amass, Sublist3r, Assetfinder and Subfinder
  # DNS
  fapt dnsenum                    # DNSEnum is a command-line tool that automatically identifies basic DNS records
  # Email
  install_holehe                          # Check if the mail is used on different sites
  install_simplyemail             # Gather emails
  install_theharvester            # Gather emails, subdomains, hosts, employee names, open ports and banners
  install_h8mail                          # Email OSINT & Password breach hunting tool
  install_infoga                          # Gathering email accounts informations
  install_buster                          # An advanced tool for email reconnaissance
  install_pwnedornot                      # OSINT Tool for Finding Passwords of Compromised Email Addresses
  install_ghunt                           # Investigate Google Accounts with emails
  # Phone
  install_phoneinfoga                     # Advanced information gathering & OSINT framework for phone numbers
  # Social Network
  install_maigret_pip                     # Search pseudos and information about users on many platforms
  install_linkedin2username               # Generate username lists for companies on LinkedIn
  install_toutatis                        # Toutatis is a tool that allows you to extract information from instagrams accounts
  install_tiktokscraper                   # TikTok Scraper. Download video posts, collect user/trend/hashtag/music feed metadata, sign URL and etc
  # Website
  install_waybackurls             # Website history
  install_carbon14                        # OSINT tool for estimating when a web page was written
  install_wikileaker                      # A WikiLeaks scraper
  install_photon                          # Incredibly fast crawler designed for OSINT.
  install_cloudfail               # Utilize misconfigured DNS and old database records to find hidden IP's behind the CloudFlare network
  # IP
  install_ipinfo                          # Get information about an IP address using command line with ipinfo.io
  # Data visualization
  install_constellation                   # A graph-focused data visualisation and interactive analysis application.
  # Framework
  install_maltego                 # Maltego is a software used for open-source intelligence and forensics
  install_spiderfoot              # SpiderFoot automates OSINT collection
  install_finalrecon              # A fast and simple python script for web reconnaissance
  # fapt recon-ng                   # External recon tool
  # TODO : http://apt.vulns.sexy make apt-get update print a warning, and the repo has a weird name, we need to fix this in order to not alarm users
  install_osrframework                    # OSRFramework, the Open Sources Research Framework
  # Dark
  install_tor					            # Tor proxy
  fapt-noexit torbrowser-launcher        # Tor browser
  install_onionsearch                     # OnionSearch is a script that scrapes urls on different .onion search engines.
  install_pwndb					          # No need to say more, no ? Be responsible with this tool please !
  # Github
  install_githubemail                     # Retrieve a GitHub user's email even if it's not public
  # Other
  # fapt whois                      # See information about a specific domain name or IP address
  install_recondog                        # Informations gathering tool
  install_jsparser                        # Parse JS files
  install_gron                            # JSON parser
  # install_ignorant                # holehe but for phone numbers
}

# Package dedicated to applicative and active web pentest tools
function package_web() {
  export PIPELINE_TESTS_FILE="package_web"
  set_go_env
  install_gobuster                # Web fuzzer (pretty good for several extensions)
  install_kiterunner              # Web fuzzer (fast and pretty good for api bruteforce)
  install_amass                   # Web fuzzer
  install_ffuf                    # Web fuzzer (little favorites)
  install_dirb                    # Web fuzzer
  install_wfuzz                      # Web fuzzer (second favorites)
  install_dirsearch               # Web fuzzer
  fapt sqlmap                     # SQL injection scanner
  install_ssrfmap                         # SSRF scanner
  install_gopherus                        # SSRF helper
  install_nosqlmap                        # NoSQL scanner
  install_xsstrike                        # XSS scanner
  install_xspear                  # XSS scanner
  install_xsser                   # XSS scanner
  install_xsrfprobe                       # CSRF scanner
  install_bolt                            # CSRF scanner
  install_kadimus                         # LFI scanner
  install_fuxploider                      # File upload scanner
  install_blazy                           # Login scanner
  fapt patator                    # Login scanner
  install_joomscan                # Joomla scanner
  install_wpscan                     # Wordpress scanner
  install_droopescan              # Drupal scanner
  install_drupwn                  # Drupal scanner
  install_cmsmap                  # CMS scanner (Joomla, Wordpress, Drupal)
  install_moodlescan              # Moodle scanner
  install_testssl                 # SSL/TLS scanner
  fapt sslscan                    # SSL/TLS scanner
  install_tls-scanner             # SSL/TLS scanner
  install_sslyze                  # SSL/TLS scanner
  fapt weevely                    # Awesome secure and light PHP webshell
  install_cloudfail                       # Cloudflare misconfiguration detector
  install_eyewitness                      # Website screenshoter
  install_oneforall                       
  install_wafw00f                         # Waf detector
  install_corscanner                      # CORS misconfiguration detector
  install_hakrawler                       # Web endpoint discovery
  install_gowitness               # Web screenshot utility
  install_linkfinder                      # Discovers endpoint JS files
  install_timing_attack                   # Cryptocraphic timing attack
  install_updog                           # New HTTPServer
  install_jwt_tool                # Toolkit for validating, forging, scanning and tampering JWTs
  install_jwt_cracker                     # JWT cracker and bruteforcer
  install_wuzz                            # Burp cli
  install_git-dumper              # Dump a git repository from a website
  install_gittools                # Dump a git repository from a website
  install_padbuster               # Automated script to perform a Padding Oracle attack
  install_ysoserial               # Deserialization payloads
  fapt whatweb                    # Recognises web technologies including content management
  install_phpggc                          # php deserialization payloads
  install_symfony-exploits                #  symfony secret fragments exploit
  install_jdwp_shellifier                 # exploit java debug
  install_httpmethods             # Tool for HTTP methods enum & verb tampering
  install_h2csmuggler             # Tool for HTTP2 smuggling
  install_byp4xx                  # Tool to automate 40x errors bypass attempts
  install_feroxbuster             # ffuf but with multithreaded recursion
  install_tomcatwardeployer       # Apache Tomcat auto WAR deployment & pwning tool
  install_clusterd                # Axis2/JBoss/ColdFusion/Glassfish/Weblogic/Railo scanner
  install_arjun                   # HTTP Parameter Discovery
  install_nuclei                  # Needed for gau install
  install_gau                     #
  install_prips                   # Print the IP addresses in a given range
  install_hakrevdns               # Reverse DNS lookups
  install_httprobe                # Probe http
  install_httpx                   # Probe http
  install_anew                    # A tool for adding new lines to files, skipping duplicates
  install_robotstester            # Robots.txt scanner
  install_naabu                   # Fast port scanner
  # install_gitrob                  # Senstive files reconnaissance in github
  install_burpsuite
}

# Package dedicated to command & control frameworks
function package_c2() {
  export PIPELINE_TESTS_FILE="package_c2"
  set_go_env
  install_empire                  # Exploit framework
  install_starkiller              # GUI for Empire
  install_metasploit              # Offensive framework
  install_routersploit            # Exploitation Framework for Embedded Devices
  install_pwncat                  # netcat and rlwrap on steroids to handle revshells, automates a few things too
}

# Package dedicated to internal Active Directory tools
function package_ad() {
  export PIPELINE_TESTS_FILE="package_ad"
  set_go_env
  install_responder                       # LLMNR, NBT-NS and MDNS poisoner
  install_ldapdomaindump
  install_crackmapexec            # Network scanner
  install_sprayhound                      # Password spraying tool
  install_smartbrute              # Password spraying tool
  install_bloodhound-py           # AD cartographer
  install_neo4j                   # Bloodhound dependency
  install_bloodhound
  # install_bloodhound_old_v3
  # install_bloodhound_old_v2
  install_cyperoth                       # Bloodhound dependency
  # install_mitm6_sources                 # Install mitm6 from sources
  install_mitm6_pip                       # DNS server misconfiguration exploiter
  install_aclpwn                          # ACL exploiter
  install_impacket                        # Network protocols scripts
  install_pykek                           # AD vulnerability exploiter
  install_lsassy                          # Credentials extracter
  install_privexchange                    # Exchange exploiter
  install_ruler                           # Exchange exploiter
  install_darkarmour                      # Windows AV evasion
  install_amber                           # AV evasion
  install_powershell                      # Windows Powershell for Linux
  install_krbrelayx                       # Kerberos unconstrained delegation abuse toolkit
  install_evilwinrm                       # WinRM shell
  install_pypykatz                        # Mimikatz implementation in pure Python
  install_enyx                            # Hosts discovery
  install_enum4linux-ng                   # Hosts enumeration
  install_zerologon                       # Exploit for zerologon cve-2020-1472
  install_libmspack                       # Library for some loosely related Microsoft compression format
  install_peas_offensive                  # Library and command line application for running commands on Microsoft Exchange
  install_windapsearch-go                 # Active Directory Domain enumeration through LDAP queries
  install_oaburl                       # Send request to the MS Exchange Autodiscover service
  install_lnkup
  fapt samdump2                   # Dumps Windows 2k/NT/XP/Vista password hashes
  fapt smbclient                  # Small dynamic library that allows iOS apps to access SMB/CIFS file servers
  install_polenum
  install_smbmap                  # Allows users to enumerate samba share drives across an entire domain
  install_pth-tools               # Pass the hash attack
  install_smtp-user-enum             # SMTP user enumeration via VRFY, EXPN and RCPT
  install_onesixtyone                # SNMP scanning
  install_nbtscan                    # NetBIOS scanning tool
  fapt rpcbind                    # RPC scanning
  install_gpp-decrypt                # Decrypt a given GPP encrypted string
  install_ntlmv1-multi                    # NTLMv1 multi tools: modifies NTLMv1/NTLMv1-ESS/MSCHAPv2
  install_hashonymize                     # Anonymize NTDS, ASREProast, Kerberoast hashes for remote cracking
  install_gosecretsdump           # secretsdump in Go for heavy files
  install_adidnsdump              # enumerate DNS records in Domain or Forest DNS zones
  install_powermad                # MachineAccountQuota and DNS exploit tools
  install_pygpoabuse              
  install_bloodhound-import       # Python script to import BH data to a neo4j db
  install_bloodhound-quickwin     # Python script to find quickwins from BH data in a neo4j db
  install_ldapsearch-ad           # Python script to find quickwins from basic ldap enum
  install_ntlm-scanner            # Python script to check public vulns on DCs
  install_petitpotam              # Python script to coerce auth through MS-EFSR abuse
  install_DFSCoerce               # Python script to coerce auth through NetrDfsRemoveStdRoot and NetrDfsAddStdRoot abuse
  install_coercer                 # Python script to coerce auth through multiple methods
  install_PKINITtools             # Python scripts to use kerberos PKINIT to obtain TGT
  install_pywhisker               # Python script to manipulate msDS-KeyCredentialLink
  install_manspider               # Snaffler-like in Python
  install_targetedKerberoast
  install_pcredz
  install_pywsus
  install_donpapi
  install_webclientservicescanner
  install_certipy
  npm install ntpsync             # sync local time with remote server
  install_shadowcoerce
  install_gmsadumper
  install_modifyCertTemplate
  install_pylaps
  install_finduncommonshares
  install_ldaprelayscan
  install_goldencopy
  install_crackhound
  install_kerbrute                # Tool to enumerate and bruteforce AD accounts through kerberos pre-authentication
}

# Package dedicated to mobile apps pentest tools
function package_mobile() {
  export PIPELINE_TESTS_FILE="package_mobile"
  set_go_env
  fapt android-tools-adb
  install_smali
  install_dex2jar
  fapt zipalign
  fapt apksigner
  fapt apktool
  install_frida
  install_androguard              # Reverse engineering and analysis of Android applications
}

# Package dedicated to VOIP/SIP pentest tools
function package_voip() {
  export PIPELINE_TESTS_FILE="package_voip"
  set_go_env
  install_sipvicious              # Set of tools for auditing SIP based VOIP systems
}

# Package dedicated to RFID/NCF pentest tools
function package_rfid() {
  export PIPELINE_TESTS_FILE="package_rfid"
  set_go_env
  fapt git
  fapt libusb-dev
  fapt autoconf
  fapt nfct
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
  export PIPELINE_TESTS_FILE="package_iot"
  fapt avrdude
  fapt minicom
}

# Package dedicated to SDR
function package_sdr() {
  export PIPELINE_TESTS_FILE="package_sdr"
  install_mousejack               # tools for mousejacking
  install_jackit                  # tools for mousejacking
  install_hackrf                  # tools for hackrf
  install_gqrx                    # spectrum analyzer for SDR
  fapt rtl-433                    # decode radio transmissions from devices on the ISM bands
}

# Package dedicated to network pentest tools
function package_network() {
  export PIPELINE_TESTS_FILE="package_network"
  export PATH=$PATH:/usr/local/go/bin
  install_proxychains                     # Network tool
  DEBIAN_FRONTEND=noninteractive fapt wireshark # Wireshark packet sniffer
  DEBIAN_FRONTEND=noninteractive fapt tshark    # Tshark packet sniffer
  # install_wireshark_sources             # Install Wireshark from sources
  fapt hping3                     # Discovery tool
  install_masscan                    # Port scanner
  install_nmap                       # Port scanner
  install_autorecon               # External recon tool
  fapt tcpdump                    # Capture TCP traffic
  install_dnschef                 # Python DNS server
  install_divideandscan           # Python project to automate port scanning routine
  fapt iptables                   # iptables for the win
  fapt traceroute                 # ping ping
  install_chisel                  # Fast TCP/UDP tunnel over HTTP
  install_sshuttle                # Transparent proxy over SSH
  fapt dns2tcp                    # TCP tunnel over DNS
  install_eaphammer
  install_freerdp2-x11
  fapt rdesktop
  fapt xtightvncviewer
  install_fierce
  fapt ssh-audit                  # SSH server audit
  fapt hydra                      # Login scanner
  install_memcached-cli           
  fapt mariadb-client             # Mariadb client
  fapt redis-tools                # Redis protocol
  install_odat                    # Oracle Database Attacking Tool
}

# Package dedicated to wifi pentest tools
function package_wifi() {
  export PIPELINE_TESTS_FILE="package_wifi"
  set_go_env
  install_pyrit                           # Databases of pre-computed WPA/WPA2-PSK authentication phase
  install_wifite2                         # Retrieving password of a wireless access point (router)
  install_aircrack-ng                # WiFi security auditing tools suite
  # install_hostapd-wpe            # Modified hostapd to facilitate AP impersonation attacks -> broken install, need official release of hostapd-2.6.tar.gz
  fapt reaver                     # Brute force attack against Wifi Protected Setup
  fapt bully                      # WPS brute force attack
  fapt cowpatty                   # WPA2-PSK Cracking
  install_bettercap               # MiTM tool
  install_hcxtools                        # Tools for PMKID and other wifi attacks
  install_hcxdumptool                     # Small tool to capture packets from wlan devices
}

# Package dedicated to forensic tools
function package_forensic() {
  # CI/CD install_ [x]
  export PIPELINE_TESTS_FILE="package_forensic"
  fapt pst-utils                  # Reads a PST and prints the tree structure to the console
  fapt binwalk                    # Tool to find embedded files
  fapt foremost                   # Alternative to binwalk
  install_volatility2             # Memory analysis tool
  install_trid                    # filetype detection tool
  # install_peepdf                  # PDF analysis
}

# Package dedicated to steganography tools
function package_steganography() {
  # CI/CD install_ [x]
  export PIPELINE_TESTS_FILE="package_steganography"
  install_zsteg                   # Detect stegano-hidden data in PNG & BMP
  fapt stegosuite
  fapt steghide
  install_stegolsb                # (including wavsteg)
}

# Package dedicated to cloud tools
function package_cloud() {
  # CI/CD install_ [x]
  export PIPELINE_TESTS_FILE="package_cloud"
  install_kubectl
  install_awscli
  install_scout                   # Multi-Cloud Security Auditing Tool
}

# Package dedicated to reverse engineering tools
function package_reverse() {
  # CI/CD install_ [x]
  export PIPELINE_TESTS_FILE="package_reverse"
  install_pwntools                        # CTF framework and exploit development library
  install_pwndbg                          # Advanced Gnu Debugger
  install_angr                    # Binary analysis
  install_checksec-py                     # Check security on binaries
  fapt nasm                       # Netwide Assembler
  install_radare2                    # Awesome debugger
  fapt wabt                       # The WebAssembly Binary Toolkit
  fapt-noexit ltrace
  fapt strace
  install_ghidra
  install_ida
  install_jd-gui                     # Java decompiler
}

# Package dedicated to attack crypto
function package_crypto() {
  export PIPELINE_TESTS_FILE="package_crypto"
#  install_rsactftool              # attack rsa
# todo : install_rsactftool function fails and make the whole build stop, temporarily removing
  echo "nothing to install"
}

# Package dedicated to SAST and DAST tools
function package_code_analysis() {
  export PIPELINE_TESTS_FILE="package_code_analysis"
  install_vulny-code-static-analysis
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
