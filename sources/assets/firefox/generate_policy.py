#!/usr/bin/env python3
# -- coding: utf-8 --
# File name          : generate_policy.py
# Author             : Wlayzz (@wlayzz - Lucien Doustaly) and Skilo (@askilow - Alexis Marquois) and lap1nou (@lapinousexy)
# Date created       : 27 February 2023
# Date modifieded    : 07 May 2024
# Python Version     : 3.*

import requests
import re
import json

from R2Log import logger

POLICY_FILENAME = "policies.json"
POLICY_PATH = "/usr/lib/firefox-esr/distribution/"

names = [
    "foxyproxy-standard",
    "uaswitcher",
    "cookie-editor",
    "wappalyzer",
    "multi-account-containers"
]

def get_extension_id(extension_name):
    logger.info(f"Getting extension id for {extension_name}")

    extension_id_regex = r'"guid":"([^"]+)"'
    response = requests.get(f"https://addons.mozilla.org/fr/firefox/addon/{extension_name}")
    match = re.search(extension_id_regex, response.text)

    if match:
        return match.group(1)
    else:
        logger.error(f"Couldn't get extension id for {extension_name}")


def generate_firefox_policy():
    logger.info(f"Generating the Firefox policy")

    try:
        with open(f"/opt/tools/firefox/{POLICY_FILENAME}.template", "r") as policy_template:
            data = json.load(policy_template)

            for name in names:
                extension_guid = get_extension_id(name)
                data['policies']['ExtensionSettings'][extension_guid] = {"installation_mode": "force_installed", "install_url": f"https://addons.mozilla.org/firefox/downloads/latest/{name}/latest.xpi"}

            with open(f"{POLICY_PATH}{POLICY_FILENAME}", "w") as policy_file:
                json.dump(data, policy_file)
    except:
        logger.error("Couldn't generate the Firefox policy")
        raise


if __name__ == "__main__":
    generate_firefox_policy()
