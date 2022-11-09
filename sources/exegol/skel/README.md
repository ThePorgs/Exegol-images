# My-Resources

The files (data, configuration files, etc.) stored in `~/.exegol/my-resources` (on the host) are persistent and shared between all local exegol containers (in `/opt/my-resources`).

## Supported setups

Configuration files stored in the `/opt/my-resources/setup/` directory will be deployed on the containers and allow users to customize Exegol further (if supported, refer to the documentation). More information below.

By default, the number of officially supported configuration files is limited, and it depends on the version of the image.
In order to see what configuration files are supported, the `/opt/supported_setups.md` documentation file can be read from any container.
The online documentation can be consulted as well to understand how this feature works and what is supported in the latest Exegol images versions: https://exegol.readthedocs.io/

If a user wants to deploy tools and configurations that are not supported, or more advanced, the `load_user_setup.sh` script can be used, more information below.

## User setup

The `/opt/my-resources/setup/load_user_setup.sh` script is executed on the first startup of each new container that has the "my-resources" feature enabled.
Arbitrary code can be added in this file, in order to customize Exegol (dependency installation, configuration file copy, etc).
It is strongly advised **not** to overwrite the configuration files provided by exegol (e.g. /root/.zshrc, /opt/.exegol_aliases, ...), official updates will not be applied otherwise.
