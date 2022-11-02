# Exegol customization

This document lists the customizations supported by Exegol for the "my-resources" feature.
The files (data, configuration files, etc.) stored in `~/.exegol/my-resources` (on the host) are persistent and shared between all local exegol containers (in `/opt/my-resources`).
For more information, the online documentation can be consulted: https://exegol.readthedocs.io/


## Supported configurations

- **aliases**: Any custom alias can be defined in the `/opt/my-resources/setup/zsh/aliases` file. This file is automatically loaded by zsh.
- **zshrc**: It is possible to add commands at the end of the zshrc routine in `/opt/my-resources/setup/zsh/zshrc` file.
- **tmux**: TODO

## Advanced customizations

Alternatively, the `/opt/my-resources/setup/load_user_setup.sh` script can be used to install additional tools and configurations.
The script is executed on the first startup of each new container with the "my-resources" feature enabled.
Any command added in this script is executed.

## Contribution
Feel free to contribute, implement new supported customizations, etc. and open a pull-request on [Exegol-images](https://github.com/ShutdownRepo/Exegol-images).