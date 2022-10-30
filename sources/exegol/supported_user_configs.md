# Exegol customization

This document lists the customizations supported by exegol

## zsh

- You can define any custom alias in the file: `/my-resources/config/aliases`. This file is automatically loaded by zsh.

- It is possible to add commands at the end of the zshrc routine in the user file `/my-resources/config/zshrc`.

## tmux

TODO

## Advanced customizations

To integrate particular tools and configurations that are not (yet) officially included by default (PRs are open), 
it is possible to apply additional modifications through a user-defined script. 
The script `/my-resources/config/load_my_configs.sh` will be executed at the first start of a new exegol container (with the my-resources feature enabled).


If you implement a missing customization, feel free to submit it in PR to share it with everyone! [Exegol-images](https://github.com/ShutdownRepo/Exegol-images)

