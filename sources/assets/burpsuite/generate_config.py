import json
import requests
import pathlib
import zipfile
import logging
from enum import Enum
from io import BytesIO
from bs4 import BeautifulSoup

BURP_CONFIG_FILE = "/root/.BurpSuite/UserConfigCommunity.json"
BURPSUITE_EXTENSIONS_PATH = "/opt/tools/BurpSuiteCommunity/extensions/"
BURP_MANIFEST_NAME = "BappManifest.bmf"
BURP_BAPP_URL = "https://portswigger.net/bappstore"
BURPSUITE_EXTENSIONS_FILE = "/opt/my-resources/setup/burpsuite/extensions.txt"
LOG_FILE="/var/log/exegol/burp_config.log"

logger = logging.getLogger(__name__)

class ExtensionType(Enum):
    JAVA = 1
    PYTHON = 2
    RUBY = 3

def load_burp_config(file_path):
    with open(file_path, "r") as file:
        return json.load(file)

def save_json(file_path, data):
    with open(file_path, "w") as file:
        json.dump(data, file, indent=4)

def burp_manifest_parsing(manifest_file):
    with open(manifest_file, "r") as file:
        for line in file.readlines():
            if line.startswith('ExtensionType:'):
                extension_type = int(line.split(':', 1)[1].strip())
            elif line.startswith('Name:'):
                name = line.split(':', 1)[1].strip()
            elif line.startswith('EntryPoint:'):
                entrypoint = line.split(':', 1)[1].strip()

    return name, extension_type, entrypoint

def add_extension_to_config(burp_config, extensions):
    burp_config["user_options"]["extender"]["extensions"] = extensions

    save_json(BURP_CONFIG_FILE, burp_config)

def install_extensions(burp_config):
    extensions_names = []
    extensions = []

    with open(BURPSUITE_EXTENSIONS_FILE, 'r') as extensions_file:
        for extension_line in extensions_file:
            extensions_names.append(extension_line.strip())

    if not extensions_names:
        return

    # Gather extensions list from Burpsuite website
    r = requests.get(BURP_BAPP_URL)
    soup = BeautifulSoup(r.text, "html.parser")
    extensions_html = soup.find("tbody").find_all("a")

    for extension_html in extensions_html:
        if extension_html.string in extensions_names:
            logger.info(f"Installing {extension_html.string}...")
            extension_uuid = extension_html.get('href').split('/')[-1]

            # Download and extract the extension ZIP
            extension_zip = BytesIO(requests.get(f"https://portswigger.net/bappstore/bapps/download/{extension_uuid}").content)
            extension_folder_path = pathlib.Path(BURPSUITE_EXTENSIONS_PATH) / extension_html.string
            extension_folder_path.mkdir(parents=True, exist_ok=True)
            
            with zipfile.ZipFile(extension_zip) as zip_file:
                zip_file.extractall(extension_folder_path)

            logger.info(f"Finished extracting {extension_html.string}...")

            manifest_file = extension_folder_path / BURP_MANIFEST_NAME
            name, extension_type, entrypoint = burp_manifest_parsing(manifest_file)
            final_entrypoint = extension_folder_path / entrypoint

            if extension_type == ExtensionType.JAVA.value:
                ext_type = "java"
            elif extension_type == ExtensionType.PYTHON.value:
                ext_type = "python"
            elif extension_type == ExtensionType.RUBY.value:
                ext_type = "ruby"

            extension_object = {
                "errors": "ui",
                "extension_file": str(final_entrypoint),
                "extension_type": ext_type,
                "loaded": False,
                "name": name,
                "output": "ui"
            }

            extensions.append(extension_object)

    add_extension_to_config(burp_config, extensions)

if __name__ == "__main__":
    logging.basicConfig(filename=LOG_FILE, level=logging.INFO)
    burp_config = load_burp_config(BURP_CONFIG_FILE)
    install_extensions(burp_config)
