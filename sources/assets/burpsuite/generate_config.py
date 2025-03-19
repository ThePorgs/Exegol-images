import json
import os
import subprocess

BURP_CONFIG_FILE = "UserConfigCommunity.json"
BURPSUITE_EXTENSIONS_PATH = "/opt/tools/BurpSuiteCommunity/extensions/"
BURP_MANIFEST_NAME = "BappManifest.bmf"

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
                extension_type = int(line.split(':')[1].strip())
            elif line.startswith('Name:'):
                name = line.split(':')[1].strip()
            elif line.startswith('RepoName:'):
                repo_name = line.split(':')[1].strip()
            elif line.startswith('EntryPoint:'):
                entrypoint = line.split(':')[1].strip()
            elif line.startswith('BuildCommand:'):
                build_command = line.split(':')[1].strip()

    if extension_type == 2: # Python extension do not need to be build
        build_command = None

    return name, extension_type, repo_name, entrypoint, build_command

def add_extension_to_config(extensions):
    burp_config = load_burp_config(BURP_CONFIG_FILE)
    burp_config["user_options"]["extender"]["extensions"] = extensions

    save_json(BURP_CONFIG_FILE, burp_config)

def build_extension(directory, build_command):
    # Be very careful with that one buddy
    subprocess.run(
        [build_command],
        shell=True,
        cwd=directory,
        input=build_command.encode("utf-8"),
        stdout=subprocess.DEVNULL,
    )

def install_extensions():
    extensions = []

    for extension_directory in os.listdir(BURPSUITE_EXTENSIONS_PATH):
        fullpath_extension_directory = os.path.join(BURPSUITE_EXTENSIONS_PATH, extension_directory)
        
        if os.path.isdir(fullpath_extension_directory):
            manifest_file = os.path.join(BURPSUITE_EXTENSIONS_PATH, extension_directory, BURP_MANIFEST_NAME)
            name, extension_type, repo_name, entrypoint, build_command = burp_manifest_parsing(manifest_file)
            final_entrypoint = os.path.join(BURPSUITE_EXTENSIONS_PATH, extension_directory, entrypoint)

            if extension_type == 1: # Java
                build_extension(fullpath_extension_directory, build_command)

                extension_object = {
                    "errors": "ui",
                    "extension_file": final_entrypoint,
                    "extension_type": "java",
                    "loaded": False,
                    "name": name,
                    "output": "ui"
                }
            elif extension_type == 2: # Python
                extension_object = {
                    "errors": "ui",
                    "extension_file": final_entrypoint,
                    "extension_type": "python",
                    "loaded": False,
                    "name": name,
                    "output": "ui"
                }

            extensions.append(extension_object)

    add_extension_to_config(extensions)

if __name__ == "__main__":
    install_extensions()
