#!/usr/bin/env python3
# -- coding: utf-8 --
# File name          : user-setup.py
# Author             : Skilo (@askilow - Alexis Marquois)
# Date created       : 07 march 2023
# Python Version     : 3.*

from setup import get_link, download_addon, get_addon_id, install_addons, activate_addons
from R2Log import logger
from pathlib import Path
from glob import glob
from time import sleep
import re
import subprocess
import argparse

PATHNAME = "/root/.mozilla/firefox/**.Exegol/"
re_links = r'^https://addons\.mozilla\.org/[a-z]{2}(\-[A-Z]{2})?/firefox/addon/[^/]+/?$'

def parse_args():
    arg_parser = argparse.ArgumentParser(description="Automatically installs addons from a list or folder containing .xpi files.")
    arg_parser.add_argument('-L', dest="addon_links", help="txt document containing addon link (ie: https://addons.mozilla.org/fr/firefox/addon/duckduckgo-for-firefox).")
    arg_parser.add_argument('-D', dest="addon_folder", help="Path to a folder containing .xpi files to install.")
    args = arg_parser.parse_args()
    return args

if __name__ == "__main__":

    # Initialize variables
    args = parse_args()
    addon_links = args.addon_links
    addon_folder = args.addon_folder
    install_ok = False
    install_ko = []

    # Define a list containing all addons names and ids
    addon_list = []

    if addon_links is not None:
        # Read the list input by the user
        with open(addon_links, "r") as url_file:
            urls = url_file.read().splitlines()

        # Iterate through addons
        for url in urls:
            if re.findall(pattern=re_links, string=url, flags=re.IGNORECASE):
                # Make a request to the URL
                link, addon_name = get_link(url)
                # Download the addon
                download_addon(link, addon_name)
                # Read manifest.json in the archive
                try:
                    addon_id = get_addon_id("/tmp/" + addon_name)
                    install_addons(addon_name, addon_id, "/tmp/")
                    logger.success(f"{addon_name} installed sucessfully\n")
                    addon_list.append((addon_id, addon_name[0:-4], False))
                    install_ok = True
                except:
                    install_ko.append("- " + addon_name)
                    logger.error(f"{addon_name} could not be installed\n")
                    continue
        if install_ok:
            if install_ko:
                logger.info("All addons from the list were installed sucessfully except:\n%s\n" % "\n".join(install_ko))
            else:
                logger.success("All addons from the list were installed sucessfully\n")
        else:
            logger.error("No addons were found in the list %s\n" % addon_links)

    if addon_folder is not None:
        if glob(addon_folder + "/*.xpi"):
            for addon_path in glob(addon_folder + "/*.xpi"):
                addon_name = addon_path.split("/")[-1]
                addon_id = get_addon_id(addon_path)
                install_addons(addon_name, addon_id, addon_folder)
                logger.success(f"{addon_name} installed sucessfully\n")
                addon_list.append((addon_id, addon_name[0:-4], False))
                install_ok = True
            logger.success("All addons from the folder %s were installed sucessfully\n" % addon_folder)
        else:
            logger.error("No addons were found in the folder %s\n" % addon_folder)

    if install_ok:
        # Run firefox to initialise profile
        logger.info("Initialising Firefox profile")
        try:
            p_firefox = subprocess.Popen(["firefox", "-P", "Exegol", "-headless"], stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
            # Wait for firefox to be initialised
            while not addon_list[0][0].encode() in subprocess.check_output(["cat", glob("%s" % PATHNAME)[0] + "/extensions.json"]):
                sleep(0.5)
            p_firefox.kill()
            assert(Path(glob("%s" % PATHNAME)[0] + "/extensions.json").is_file())
            logger.success("Firefox profile initialised sucessfully\n")
        except:
            logger.error("Could not initialise Firefox profile")
            raise

        # Activate all addons
        activate_addons(addon_list)

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
    else:
        logger.error("No addons were found.")
