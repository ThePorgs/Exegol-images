# Tools
- tools are installed in `/opt/tools`
- make sure to start the install function with : `colorecho "[EXEGOL] Installing {name of the tool}"`

# Resources
- "Exegol resources" (https://github.com/ThePorgs/Exegol-resources) are, for instance, tools that won't be used in Exegol but on a target system (e.g. Rubeus, mimikatz and so on)
- resources are installed in `/opt/resources`

# Aliases
- for the time being, aliases must be set in the `sources/zsh/aliases` file instead of using symbolic links.
- aliases can point to binaries or scripts that are not in the path for example

# History
- it is advised to include command examples in the `sources/zsh/history` file in order to facilitate the use of tools.
- the history is a helper to the users. Let's say they start to write "`secretsdump`", they'll be able to go through the commands in the history and then replace the placeholders with their values.
- when using zsh (default, comes with preset plugins in exegol), the history can be easily search with Ctrl+r. 

Any other idea that falls outside this scope?
Any question that is left unanswered?
Feel free to reach out, I'll be happy to help and improve things, Exegol is a community-driven toolkit :rocket:

## Pull request

- Target the `dev` branch
- Try to submit only one tool per PR
