# Author: The Exegol Project

FROM debian

ARG TAG="local"
ARG VERSION="local"
ARG BUILD_DATE="n/a"

LABEL org.exegol.tag="${TAG}"
LABEL org.exegol.version="${VERSION}"
LABEL org.exegol.build_date="${BUILD_DATE}"
LABEL org.exegol.app="Exegol"
LABEL org.exegol.src_repository="https://github.com/ThePorgs/Exegol-images"

RUN echo "${TAG}-${VERSION}" > /opt/.exegol_version

ADD . sources /root/sources

WORKDIR /root/sources/install

RUN chmod +x entrypoint.sh

RUN ./entrypoint.sh deploy_exegol
RUN ./entrypoint.sh update
RUN apt-get update && apt-get install -y sudo git curl zsh asciinema zip wget ncat dnsutils python2 python3 python3-setuptools python3-pip vim nano procps automake autoconf make
RUN ln -s /usr/bin/python2.7 /usr/bin/python
RUN ./entrypoint.sh filesystem
#RUN ./entrypoint.sh set_go_env
#RUN ./entrypoint.sh install_locales
#RUN ./entrypoint.sh install_rust_cargo
#RUN ./entrypoint.sh install_tmux
RUN ./entrypoint.sh install_ohmyzsh
RUN ./entrypoint.sh install_fzf
RUN ./entrypoint.sh install_openvpn
RUN ./entrypoint.sh install_pipx
RUN ./entrypoint.sh install_python3
#RUN ./entrypoint.sh install_python-pip
#RUN ./entrypoint.sh install_exegol-history
#RUN ./entrypoint.sh install_kerbrute
RUN ./entrypoint.sh add-test-command "whoami --version"
RUN ./entrypoint.sh add-test-command "fail_command"
RUN ./entrypoint.sh post_install_clean

WORKDIR /workspace

ENTRYPOINT ["/.exegol/entrypoint.sh"]