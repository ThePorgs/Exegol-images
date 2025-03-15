#!/bin/bash
# Author: The Exegol Project

source common.sh

function install_wordlists_apt_tools() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing wordlists apt tools"
    fapt crunch cupp

    add-history cupp
    add-history crunch

    add-test-command "crunch --help" # Wordlist generator
    add-test-command "cupp --help"   # User password profiler

    add-to-list "crunch,https://github.com/crunchsec/crunch,A wordlist generator where you can specify a standard character set or a character set you specify."
    add-to-list "cupp,https://github.com/Mebus/cupp,Cupp is a tool used to generate personalized password lists based on target information."
}

function install_cewl() {
    colorecho "Installing cewl"
    rvm use 3.1.2@cewl --create # currently does not support a version higher than 3.1.2
    gem install mime mime-types mini_exiftool nokogiri rubyzip spider
    git -C /opt/tools clone --depth 1 https://github.com/digininja/CeWL.git
    bundle install --gemfile /opt/tools/CeWL/Gemfile
    rvm use 3.2.2@default
    add-aliases cewl
    add-history cewl
    add-test-command "cewl --help"
    add-to-list "cewl,https://digi.ninja/projects/cewl.php,Generates custom wordlists by spidering a target's website and parsing the results"
}

function install_cewler() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing cewler"
    pipx install --system-site-packages cewler
    add-history cewler
    add-test-command "cewler --output cewler.txt https://thehacker.recipes/"
    add-to-list "cewler,https://github.com/roys/cewler,CeWL alternative in Python"
}

function install_seclists() {
    # CODE-CHECK-WHITELIST=add-aliases,add-history
    colorecho "Installing seclists"
    git -C /opt/lists clone --single-branch --branch master --depth 1 https://github.com/danielmiessler/SecLists.git seclists
    cd /opt/lists/seclists|| exit
    rm -r LICENSE .git* CONTRIBUT* .bin
    tar -xvf /opt/lists/seclists/Passwords/Leaked-Databases/rockyou.txt.tar.gz -C /opt/lists/
    # helping people to find wordlists in common places
    ln -v -s /opt/lists/seclists /usr/share/seclists
    mkdir -p /usr/share/wordlists
    ln -v -s /opt/lists/seclists /usr/share/wordlists/seclists
    ln -v -s /opt/lists/rockyou.txt /usr/share/wordlists/rockyou.txt
    add-test-command "[[ -f '/opt/lists/rockyou.txt' ]]"
    add-test-command "[[ -d '/opt/lists/seclists/Discovery/' ]]"
    add-to-list "seclists,https://github.com/danielmiessler/SecLists,A collection of multiple types of lists used during security assessments"
}

function install_pass_station() {
    colorecho "Installing Pass Station"
    rvm use 3.1.2@pass-station --create # currently does not support a version higher than 3.1.2
    gem install pass-station
    rvm use 3.1.2@default
    add-aliases pass-station
    add-history pass-station
    add-test-command "pass-station --help"
    add-to-list "pass,https://github.com/hashcat/hashcat,TODO"
}

function install_username-anarchy() {
    colorecho "Installing Username-Anarchy"
    git -C /opt/tools/ clone --depth 1 https://github.com/urbanadventurer/username-anarchy
    add-aliases username-anarchy
    add-history username-anarchy
    add-test-command "username-anarchy --help"
    add-to-list "username-anarchy,https://github.com/urbanadventurer/username-anarchy,Tools for generating usernames when penetration testing. Usernames are half the password brute force problem."
}

function install_genusernames() {
    # CODE-CHECK-WHITELIST=add-aliases
    colorecho "Installing genusernames"
    mkdir -p /opt/tools/genusernames
    wget -O /opt/tools/genusernames/genusernames.function https://gitlab.com/-/snippets/2480505/raw/main/bash
    sed -i 's/genadname/genusernames/g' /opt/tools/genusernames/genusernames.function
    {
      # adding new-line
      echo ''
      echo '# genusernames function'
      # shellcheck disable=SC2016
      echo 'source /opt/tools/genusernames/genusernames.function'
    } >> ~/.zshrc
    add-history genusernames
    add-test-command "genusernames 'john doe'"
    add-to-list "genusernames,https://gitlab.com/-/snippets/2480505/raw/main/bash,GenUsername is a Python tool for generating a list of usernames based on a name or email address."
}

function install_onelistforall() {
    # CODE-CHECK-WHITELIST=add-aliases,add-history
    colorecho "Installing onelistforall"
    wget https://raw.githubusercontent.com/six2dez/OneListForAll/main/onelistforallmicro.txt -P /opt/lists/
    wget https://raw.githubusercontent.com/six2dez/OneListForAll/main/onelistforallshort.txt -P /opt/lists/
    add-test-command "[[ -f '/opt/lists/onelistforallshort.txt' ]]"
    add-to-list "onelistforall,https://github.com/six2dez/OneListForAll,Rockyou for web fuzzing"
}


function install_rules_from_repo() {
    # CODE-CHECK-WHITELIST=add-test-command,add-to-list,add-aliases,add-history
    local owner="$1"
    local repo_name="$2"
    local branch="$3"
    shift 3
    local paths=("$@")

    # Validate required arguments
    if [[ -z "$owner" || -z "$repo_name" || -z "$branch" || ${#paths[@]} -eq 0 ]]; then
        criticalecho "Usage: install_rules_from_repo <owner> <repo_name> <branch> <path1> [<path2> ...]"
    fi

    # Display installation information
    colorecho "Installing rules from $owner/$repo_name ($branch): ${paths[*]}"

    for path in "${paths[@]}"; do
        url="https://github.com/$owner/$repo_name/raw/refs/heads/$branch/$path"
        list_name=$(basename "$path")
        wget -q --show-progress "$url" -P /opt/rules/
        add-test-command "[[ -f '/opt/rules/$list_name' ]]"
    done
}

function install_rules(){
    # CODE-CHECK-WHITELIST=add-aliases,add-history,add-test-command
    colorecho "Installing rules"

    install_rules_from_repo "NSAKEY" "nsa-rules" "master" \
        "_NSAKEY.v1.dive.rule" \
        "_NSAKEY.v2.dive.rule"
    add-to-list "NSAKEY rules,https://github.com/NSAKEY/nsa-rules,Password cracking rules and masks for hashcat"

    install_rules_from_repo "praetorian-inc" "Hob0Rules" "master" \
        "d3adhob0.rule" \
        "hob064.rule"
    add-to-list "Hob0Rules rules,https://github.com/praetorian-inc/Hob0Rules,Password cracking rules for Hashcat based on statistics and industry patterns"

    install_rules_from_repo "stealthsploit" "OneRuleToRuleThemStill" "main" "OneRuleToRuleThemStill.rule"
    add-to-list "OneRuleToRuleThemStill rules,https://github.com/stealthsploit/OneRuleToRuleThemStill,One rule to crack all passwords. A revamped - optimised and updated version of the original OneRuleToRuleThemAll hashcat rule"

    install_rules_from_repo "rarecoil" "pantagrule" "master" \
        "rules/hashesorg.v6/pantagrule.hashorg.v6.hybrid.rule.gz" \
        "rules/hashesorg.v6/pantagrule.hashorg.v6.one.rule.gz" \
        "rules/hashesorg.v6/pantagrule.hashorg.v6.popular.rule.gz" \
        "rules/hashesorg.v6/pantagrule.hashorg.v6.random.rule.gz" \
        "rules/hashesorg.v6/pantagrule.hashorg.v6.raw1m.rule.gz" \
        "rules/private.hashorg.royce/pantagrule.popular.royce.rule.gz" \
        "rules/private.hashorg.royce/pantagrule.hybrid.royce.rule.gz" \
        "rules/private.hashorg.royce/pantagrule.one.royce.rule.gz" \
        "rules/private.hashorg.royce/pantagrule.random.royce.rule.gz" \
        "rules/private.v5/pantagrule.private.v5.hybrid.rule.gz" \
        "rules/private.v5/pantagrule.private.v5.one.gz" \
        "rules/private.v5/pantagrule.private.v5.popular.rule.gz" \
        "rules/private.v5/pantagrule.private.v5.random.rule.gz"
    add-to-list "Pantagrule rules,https://github.com/rarecoil/pantagrule,large hashcat rulesets generated from real-world compromised passwords"
}


# Package dedicated to the installation of wordlists and tools like wl generators
function package_wordlists() {
    set_env
    local start_time
    local end_time
    start_time=$(date +%s)
    install_wordlists_apt_tools
    install_cewl                    # Wordlist generator
    install_cewler                  # cewl alternative in Python
    install_seclists                # Awesome wordlists
    install_pass_station            # Default credentials database
    install_username-anarchy        # Generate possible usernames based on heuristics
    install_genusernames
    install_onelistforall
    install_rules
    post_install
    end_time=$(date +%s)
    local elapsed_time=$((end_time - start_time))
    colorecho "Package wordlists completed in $elapsed_time seconds."
}
