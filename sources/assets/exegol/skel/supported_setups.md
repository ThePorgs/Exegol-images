# Exegol customization

This document lists the customizations supported by Exegol for the "my-resources" feature.
The files (data, configuration files, etc.) stored in `~/.exegol/my-resources` (on the host) are persistent and shared between all local exegol containers (in `/opt/my-resources`).
For more information, the online documentation can be consulted: https://exegol.readthedocs.io/


## Supported configurations

### apt

- Custom APT **repositories** can be added in exegol by filling in the `/opt/my-resources/setup/apt/sources.list` file
- Importing custom repositories usually requires importing **GPG keys** as well, which can be done by entering trusted GPG keys download URLs in the `/opt/my-resources/setup/apt/keys.list` file
- To install **APT packages** automatically (after updating the repository including the custom ones), just enter a list of package names in the `/opt/my-resources/setup/apt/packages.list` file

### zsh
- **aliases**: Any custom alias can be defined in the `/opt/my-resources/setup/zsh/aliases` file. This file is automatically loaded by zsh.
- **zshrc**: It is possible to add commands at the end of the zshrc routine in `/opt/my-resources/setup/zsh/zshrc` file.
- **history**: it is possible to automatically add history commands at the end of `~/.zsh_history` from the file `/opt/my-resources/setup/zsh/history`.

### vim

- To automatically overwrite the `~/.vimrc` configuration file, simply create the file `/opt/my-resources/setup/vim/vimrc`
- vim configuration folders are also automatically synchronized:
  - `/opt/my-resources/setup/vim/autoload/*` --> `~/.vim/autoload/`
  - `/opt/my-resources/setup/vim/backup/*` --> `~/.vim/backup/`
  - `/opt/my-resources/setup/vim/colors/*` --> `~/.vim/colors/`
  - `/opt/my-resources/setup/vim/plugged/*` --> `~/.vim/plugged/`
  - `/opt/my-resources/setup/vim/bundle/*` --> `~/.vim/bundle/`

### neovim

To automatically overwrite the `neovim` configuration to allow all users to use their own personal config. 

- To automatically overwrite the `~/.config/nvim/` configuration, copy the custom config in `/opt/my-resources/setup/nvim/`
- It is possible to install plugins dependencies with the APT customization system (see "apt").

### tmux 

To automatically overwrite the `~/.tmux.conf` configuration file, simply create the file `/opt/my-resources/setup/tmux/tmux.conf`

### python3 / pip3

The `/opt/my-resources/setup/python3/requirements.txt` file allows the user to list a set of packages to install with constraints just like a classic **requirements.txt** file.

### firefox

The `/opt/my-resources/setup/firefox/addons.txt` file allows the user to list addons to install from online sources. It must be filled with their links in Mozilla's shop (for example https://addons.mozilla.org/fr/firefox/addon/foxyproxy-standard/ ).
The `.xpi` files in `/opt/my-resources/setup/firefox/addons/` folder will be installed as well.
The `.der` files in `/opt/my-resources/setup/firefox/CA/` folder will be trusted.

## Advanced customizations

Alternatively, the `/opt/my-resources/setup/load_user_setup.sh` script can be used to install additional tools and configurations.
The script is executed on the first startup of each new container with the "my-resources" feature enabled.
Any command added in this script is executed.

## Contribution
Feel free to contribute, implement new supported customizations, etc. and open a pull-request on [Exegol-images](https://github.com/ThePorgs/Exegol-images).
