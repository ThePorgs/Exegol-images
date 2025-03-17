#!/usr/bin/env python3
# -- coding: utf-8 --
# File name          : setup.py
# Author             : Wlayzz (@wlayzz - Lucien Doustaly) and Skilo (@askilow - Alexis Marquois)
# Date created       : 27 February 2023
# Python Version     : 3.*

import json
import os
import re
import shutil
import subprocess
import zipfile
import sqlite3
import requests
from pathlib import Path
from time import sleep
from R2Log import logger
from glob import glob
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import NameOID

PATHNAME = "/root/.mozilla/firefox/**.Exegol/"

# Define addons urls
urls = [
    "https://addons.mozilla.org/en-US/firefox/addon/foxyproxy-standard/",
    "https://addons.mozilla.org/en-US/firefox/addon/uaswitcher/",
    "https://addons.mozilla.org/en-US/firefox/addon/cookie-editor/",
    "https://addons.mozilla.org/en-US/firefox/addon/wappalyzer/",
    "https://addons.mozilla.org/en-US/firefox/addon/multi-account-containers/"
]

# Define regex
reurl = r"(https:\/\/addons\.mozilla\.org\/firefox\/downloads\/file\/[0-9]+\/)([a-zA-Z0-9\-\_\.]+\.xpi)"
reid = r'"id": "([^"]+)"'

def get_link(url):
    logger.info(f"Extracting download link from {url}")
    response = requests.get(url)
    # Extract download link and addon name from the response text using regex
    dlextract = re.search(reurl, response.text)
    # Concat link (group 1) and addon name (group 2)
    link = ''.join(dlextract.groups())
    # Extract xpi filename
    addon_name = dlextract.group(2)
    return link, addon_name


def download_addon(link, addon_name):
    logger.info(f"Downloading addon {addon_name}")
    addon_dl = requests.get(link)
    # Save xpi addon on filesystem
    with open("/tmp/" + addon_name, 'wb') as addon_file:
        addon_file.write(addon_dl.content)


def get_addon_id(addon_path):
    archive = zipfile.ZipFile(addon_path, 'r')
    manifest = archive.read('manifest.json').decode()
    try:
        # Read the id in the manifest
        addon_id = re.search(reid, manifest).group(1)
    except:
        # Read the id in the mozilla.rsa file
        cert = archive.read('META-INF/mozilla.rsa')
        der_cert = pkcs7.load_der_pkcs7_certificates(cert)
        extension_cert = der_cert[0]
        ext_cert_name = extension_cert.subject
        addon_id = ext_cert_name.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    return addon_id


def install_addons(addon_name, addon_id, addon_path):
    logger.info(f"Installing addon {addon_name} with id {addon_id}")
    # Get the path of the Exegol profile
    try:
        dest = glob("%s" % PATHNAME)[0]
    except:
        logger.error("Firefox profile Exegol does not exist")
        raise
    # Create the extensions folder
    Path(dest + "/extensions").mkdir(parents=True, exist_ok=True)
    # Move the addon to the extensions folder
    shutil.move(addon_path + "/" + addon_name, dest + "/extensions/" + addon_id + ".xpi")


def activate_addons(addon_list):
    for addons in addon_list:
        addon_id, addon_name, disable = addons
        if disable:
            logger.info(f"Disabling {addon_name}")
        else:
            logger.info(f"Enabling {addon_name}")
        try:
            with open(Path(glob("%s" % PATHNAME)[0] + "/extensions.json"), 'r+') as extensions_file:
                extensions_config = json.load(extensions_file)
                for addon in extensions_config["addons"]:
                    if addon["id"] == addon_id:
                        addon["active"] = not disable
                        addon["userDisabled"] = disable
                        addon["seen"] = not disable
                extensions_file.seek(0)  # <--- should reset file position to the beginning.
                json.dump(extensions_config, extensions_file)
                extensions_file.truncate()  # remove remaining part
            if disable:
                logger.success(f"{addon_name} sucessfully disabled\n")
            else:
                logger.success(f"{addon_name} sucessfully enabled\n")
        except:
            if disable:
                logger.error(f"Could not disable {addon_name}\n")
            else:
                logger.error(f"Could not enable {addon_name}\n")
            pass

def adjust_ui():
    with open(Path(glob("%s" % PATHNAME)[0] + "/prefs.js"), 'r+') as pref_js:
        # removing import-button
        new_pref = re.sub(r'\\"import-button\\",', '', pref_js.read())
        # removing save-to-pocket button
        new_pref = re.sub(r'\\"save-to-pocket-button\\",', '', new_pref)
        # switching active theme to firefox-compact-dark
        new_pref = re.sub('"extensions.activeThemeID", "default-theme@mozilla.org"', '"extensions.activeThemeID", "firefox-compact-dark@mozilla.org"', new_pref)
        # removing title bar
        new_pref = re.sub('"browser.tabs.inTitlebar", 1', '"browser.tabs.inTitlebar", 0', new_pref)
        pref_js.seek(0)
        pref_js.write(new_pref)
        pref_js.truncate()

def import_bookmarks():
    dirname = os.path.dirname(__file__)
    filename = os.path.join(dirname, 'places.sqlite')
    src = sqlite3.connect(filename)
    dst = sqlite3.connect(glob("%s" % PATHNAME)[0] + "places.sqlite")
    with dst:
        src.backup(dst)
    dst.close()
    src.close()

if __name__ == "__main__":

    # Initialize variables
    install_ko = []

    # Create firefox profile Exegol
    logger.info("Creating Firefox profile")
    try:
        subprocess.run(["firefox", "-CreateProfile", "Exegol", "-headless"], stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
        assert(Path(glob("%s" % PATHNAME)[0]).is_dir())
        logger.success("Firefox profile Exegol created\n")
    except:
        logger.error("Could not create Firefox profile Exegol")
        raise

    # Define a list containing all addons names and ids
    addon_list = []

    # Iterate through addons
    for url in urls:
        # Make a request to the URL
        link, addon_name = get_link(url)
        # Download the addon
        download_addon(link, addon_name)
        try:
            # Read manifest.json in the archive
            addon_id = get_addon_id("/tmp/" + addon_name)
            install_addons(addon_name, addon_id, "/tmp/")
            logger.success(f"{addon_name} installed sucessfully\n")
            addon_list.append((addon_id, addon_name[0:-4], False))
        except:
            install_ko.append("- " + addon_name)
            logger.error(f"{addon_name} could not be installed\n")
            continue
    if install_ko:
        logger.info("All addons from the list were installed sucessfully except:\n%s\n" % "\n".join(install_ko))
    else:
        logger.success("All addons from the list were installed sucessfully\n")

    # Run firefox to initialise profile
    logger.info("Initialising Firefox profile")
    try:
        p_firefox = subprocess.Popen(["firefox", "-P", "Exegol", "-headless"], stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
        # Wait for firefox to be initialised
        while not b'sessionstore-backups' in subprocess.check_output(["ls", glob("%s" % PATHNAME)[0]]):
            sleep(0.5)
        p_firefox.kill()
        assert(Path(glob("%s" % PATHNAME)[0] + "/extensions.json").is_file())
        logger.success("Firefox profile initialised sucessfully\n")
    except:
        logger.error("Could not initialise Firefox profile")
        raise

    # Enable dark mode
    addon_list.append(("firefox-compact-dark@mozilla.org", "Dark mode", False))
    # Disable default theme
    addon_list.append(("default-theme@mozilla.org", "Default theme", True))
    # Activate all addons
    activate_addons(addon_list)

    # Update UI
    logger.info("Updating user interface")
    try:
        adjust_ui()
        # Remove existing sessions
        shutil.rmtree(glob("%s" % PATHNAME)[0] + "sessionstore-backups")
        logger.success("User interface successfully updated\n")
    except:
        logger.error("An error has occurred while trying to update user interface\n")
        raise

    # Restore bookmarks
    logger.info("Setting up profile's bookmarks")
    try:
        import_bookmarks()
        logger.success("Bookmarks successfully setup\n")
    except:
        logger.error("Could not setup profile's bookmarks")
        raise

    # Remove backup file interfering with addons activation
    logger.info("Removing backup file interfering with addons activation")
    try:
        Path(glob("%s" % PATHNAME)[0] + "/addonStartup.json.lz4").unlink()
        logger.success("Backup file successfully removed\n")
    except:
        logger.error("Could not remove the backup file")
        raise

    # Restart firefox to apply modifications
    logger.info("Restarting firefox to apply modifications")
    try:
        p_firefox = subprocess.Popen(["firefox", "-headless"], stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
        # Wait for modifications to be applied
        while not b'addonStartup.json.lz4' in subprocess.check_output(["ls", glob("%s" % PATHNAME)[0]]):
            sleep(0.5)
        p_firefox.kill()
        logger.success("Modifications successfully applied")
    except:
        logger.error("Could not restart firefox")
        raise
