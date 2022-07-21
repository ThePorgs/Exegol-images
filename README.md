
> **📌 This repository hosts code for Exegol images, a submodule of the Exegol project.
> If you were looking for Exegol, go to [the main repo](https://github.com/ShutdownRepo/Exegol)**
___

# Exegol images

This repository hosts Dockerfiles for each Exegol image, an installation script, and various assets needed during the install (custom configurations, a history file, an aliases file, etc.). These files can be used to locally build the docker images, there is however a set of automatic build rules configured on a Docerkhub repo ([here](https://hub.docker.com/repository/docker/nwodtuhs/exegol)) offering the official, pre-built, compressed Exegol images.
Users are strongly advised to rely on Dockerhub to download images, this will be way faster than building them locally.
The Dockerhub automatic build includes build and push procedures that are overridden by hooks hosted here.

Below are the different Exegol images and their purpose.

| Image name | Description                                                                                        |
|------------|----------------------------------------------------------------------------------------------------|
| full       | Includes all the tools supported by Exegol (warning: this is the heaviest image)                   |
| nightly    | (for developers and advanced users) contains the latest updates. This image can be unstable!       |
| ad         | Includes tools for Active Directory / internal pentesting only.                                    |
| web        | Includes tools for Web pentesting only.                                                            |
| light      | Includes the lightest and most used tools for various purposes.                                    |
| osint      | Includes tools for OSINT.                                                                          |
| reverse    | Includes tools for Reverse, Stegano and Forensic purposes.                                         |
