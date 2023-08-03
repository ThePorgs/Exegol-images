# Bloodhound Customization

## Config

Any file named `config.json` and placed in this folder will replace `~/.config/bloodhound/config.json`.

## Customqueries

- Any valid Bloodhound `*.json` files placed in the folder `customqueries_replacement` will be `merged` together and the output will then `replace` Exegol's default provided file.
- Any valid Bloodhound `*.json` files placed in the folder `customqueries_merge` will be `merged` altogether with Exegol's default provided file.

The `output` of replacement and merge will replace `~/.config/bloodhound/config.json`.

> Should you have files in both folders, only the end result of `replacement` will be kept.