#!/bin/zsh

function api_key_loader_subfinder() {
        CONFIG_FILENAME="~/.config/subfinder/provider-config.yaml"

        if [ ! -f ${CONFIG_FILENAME} ]; then
           return
        fi

        yq-go -i ".virustotal = [\"${VIRUSTOTAL_API_KEY}\"]" $CONFIG_FILENAME
        yq-go -i ".shodan = [\"${SHODAN_API_KEY}\"]" $CONFIG_FILENAME
        yq-go -i ".censys = [\"${CENSYS_API_KEY}\"]" $CONFIG_FILENAME
        yq-go -i ".dnsdumpster = [\"${DNSDUMPSTER_API_KEY}\"]" $CONFIG_FILENAME
}

function api_key_loader_uncover() {
        CONFIG_FILENAME="~/.config/uncover/provider-config.yaml"

        if [ ! -f ${CONFIG_FILENAME} ]; then
           return
        fi

        yq-go -i ".shodan = [\"${SHODAN_API_KEY}\"]" $CONFIG_FILENAME
        yq-go -i ".censys = [\"${CENSYS_API_KEY}\"]" $CONFIG_FILENAME
}

function api_key_loader_pwnedornot() {
        CONFIG_FILENAME="~/.config/pwnedornot/config.json"

        if [ ! -f ${CONFIG_FILENAME} ]; then
           return
        fi

        yq-go -i ".api_key = \"${HIBP_API_KEY}\"" $CONFIG_FILENAME
}

function api_key_loader_simplyemail() {
        CONFIG_FILENAME="/opt/tools/SimplyEmail/Common/SimplyEmail.ini"

        if [ ! -f ${CONFIG_FILENAME} ]; then
           return
        fi

        yq-go -i ".APIKeys.Hunter = \"${HUNTER_API_KEY}\"" $CONFIG_FILENAME
}

function api_key_loader_theharvester() {
        CONFIG_FILENAME="/opt/tools/theHarvester/theHarvester/data/api-keys.yaml"

        if [ ! -f ${CONFIG_FILENAME} ]; then
           return
        fi

        yq-go -i ".apikeys.censys.secret = \"${CENSYS_API_KEY}\"" $CONFIG_FILENAME
        yq-go -i ".apikeys.dnsdumpster.key = \"${DNSDUMPSTER_API_KEY}\"" $CONFIG_FILENAME
        yq-go -i ".apikeys.haveibeenpwned.key = \"${HIBP_API_KEY}\"" $CONFIG_FILENAME
        yq-go -i ".apikeys.shodan.key = \"${SHODAN_API_KEY}\"" $CONFIG_FILENAME
        yq-go -i ".apikeys.virustotal.key = \"${VIRUSTOTAL_API_KEY}\"" $CONFIG_FILENAME
}

function api_key_loader_blackbird() {
        CONFIG_FILENAME="/opt/tools/blackbird/.env"

        if [ ! -f ${CONFIG_FILENAME} ]; then
           return
        fi

        sed -i -e "s/INSTAGRAM_SESSION_ID=/INSTAGRAM_SESSION_ID=${INSTAGRAM_API_KEY}/g" $CONFIG_FILENAME
}

function api_key_loader_recon_ng() {
        CONFIG_FILENAME="~/.recon-ng/keys.db"

        if [ ! -f ${CONFIG_FILENAME} ]; then
           return
        fi

        # Keys are stored in an SQLite database
        sqlite3 $CONFIG_FILENAME "UPDATE keys SET value=\"${CENSYS_API_KEY}\" WHERE name=\"censysio_secret\""
        sqlite3 $CONFIG_FILENAME "UPDATE keys SET value=\"${SHODAN_API_KEY}\" WHERE name=\"shodan_api\""
        sqlite3 $CONFIG_FILENAME "UPDATE keys SET value=\"${VIRUSTOTAL_API_KEY}\" WHERE name=\"virustotal_api\""
}

api_key_loader_subfinder
api_key_loader_uncover
api_key_loader_pwnedornot
api_key_loader_simplyemail
api_key_loader_theharvester
api_key_loader_blackbird
api_key_loader_recon_ng