# The Exegol project

> Exegol is a community-driven hacking environment, powerful and yet simple enough to be used by anyone in day to day engagements.
> Script kiddies use Kali Linux, real pentesters use Exegol, megachads maintain it :eyes:

## Wrapper & images
Exegol is two things in one. Try it, and you'll stop using your old, unstable and risky environment, no more Kali Linux as host or single VM.
- **a python wrapper** making everyone's life easier. It handles all docker and git operations so you don't have to, and it allows for l33t hacking following best-practices. No more messed up history, libraries, and workspaces. **Now's the time to have a clean environment** with one container per engagement without the effort. Exegol handles multiple images and multiple containers.
    - Want to test a new tool without risking messing up your environment? Exegol is here, pop up a new container in 5 seconds and try the tool without risk or effort
    - Like the idea of using docker containers without effort but don't want to sacrifice GUI tools like BloodHound and Burp? Exegol is here, new containers are created with X11 sharing by default allowing for GUI tools to work.
    - Like the idea of using docker containers but want to use USB accessories, Wi-Fi, host's network interfaces, etc.? Exegol handles all that flawlessly
    - Want to stop pentesting your clients with the same environment everytime, interconnecting everything and risking being a weak link? Exegol is here, pop multiple containers without breaking a sweat and lead by example!
    - You like this idea but don't want to loose your work when quitting/removing a container? Exegol shares a workspace directory per container with your host, allowing you to work knowing your progress won't be lost.
- a set of pre-built **docker images** and dockerfiles that include a neat choice of tools, awesome resources, custom configs and many more.
    - Fed up with the instability and poor choice of tools of Kali Linux ? Exegol is here, trying to correct all this by being community-driven. Want some not-so-famous tool to be added? Open an issue and let's talk do it!
    - Tired of always having to open `man` or print the help for every tool because the syntax varies? Exegol includes a command history allowing you to just replace the placeholders with your values, saving you precious time
    - Want to improve productivity? Exegol includes all sorts of custom configs and tweaks with ease of use and productivity in mind (colored output for Impacket, custom shortcuts and aliases, custom tool configs, ...).
    - Want to build your own docker images locally? It's absolutely possibe and the wrapper will help in the quest.
    - Tired of always having to search github for your favorite privesc enumeration script? Exegol includes a set of resources, shared with all exegol containers and your host, including LinPEAS, WinPEAS, LinEnum, PrivescCheck, SysinternalsSuite, mimikatz, Rubeus, PowerSploit and many more.
    
> Exegol was built with pentest engagements in mind, but it can also be used in CTFs, Bug Bounties, HackTheBox, OSCP, and so on.

- :wrench: Tools: many tools that are either installed manually or with apt, pip, go etc. Some of those tools are in kali, some are not. Exegol doesn't come with only ultra-famous tools, you will find ones that the community loves to use, even if it's in dev/new/not famous. Some tools are pre-configured and/or customized (colored output, custom NtChallengeResponse in Responder, custom queries in BloodHound, ...)
- :bulb: Resources: many resources can be useful during engagements. Those resources are not referred to as "tools" since they need to be run on a pwned target, and not on the attacker machine (e.g. mimikatz, rubeus, ...).
- :scroll: History: a populated history file that allows exegol users to save time and brain space by not having to remember every tool option and argument or checking the "help" every time.
- :rocket: Aliases: a file containing aliases that can be handful when using manually installed tools, or doing common operations.
- :mag_right: Usage: a powerful Python3 wrapper used to manage Exegol container and image very easily (handles every docker operations).

## Project structure

Below are some bullet points to better understand how Exegol works
- The [Exegol](https://github.com/ShutdownRepo/Exegol) repo contains the code for the Python wrapper. It's the entrypoint of the Exegol project.
- The [Exegol-images](https://github.com/ShutdownRepo/Exegol-images) repo is loaded as a submodule in [Exegol](https://github.com/ShutdownRepo/Exegol). It includes all necessary assets to build Docker images.
- The [Exegol-resources](https://github.com/ShutdownRepo/Exegol-resources) repo is loaded as a submodule . It includes all resources mentioned previously (LinPEAS, WinPEAS, LinEnum, PrivescCheck, SysinternalsSuite, mimikatz, Rubeus, PowerSploit and many more.).
- Getting started with the Exegol project comes down to using the wrapper, which can be installed through pip or with the sources directly.

Want to know more and get started with Exegol? Go to [Exegol](https://github.com/ShutdownRepo/Exegol)

If for some reason you want to go to the Dockerhub repo, here it is: https://hub.docker.com/repository/docker/nwodtuhs/exegol.