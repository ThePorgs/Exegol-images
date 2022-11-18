# Author: Charlie BROMBERG (Shutdown - @_nwodtuhs)

FROM debian

ARG TAG="local"
ARG VERSION="local"
ARG BUILD_DATE="n/a"

LABEL org.exegol.tag="${TAG}"
LABEL org.exegol.version="${VERSION}"
LABEL org.exegol.build_date="${BUILD_DATE}"
LABEL org.exegol.app="Exegol"
LABEL org.exegol.src_repository="https://github.com/ShutdownRepo/Exegol-images"

RUN echo "${TAG}-${VERSION}" > /opt/.exegol_version

ADD sources /root/sources
RUN chmod +x /root/sources/install.sh

RUN /root/sources/install.sh deploy_exegol
RUN /root/sources/install.sh update
RUN apt-get update && apt-get install -y sudo git curl zsh zip wget ncat dnsutils python3 python3-setuptools python3-pip vim nano procps automake autoconf make
RUN /root/sources/install.sh filesystem
RUN /root/sources/install.sh set_env
RUN /root/sources/install.sh locales
RUN /root/sources/install.sh install_rust_cargo
RUN /root/sources/install.sh tmux
RUN /root/sources/install.sh install_ohmyzsh
RUN /root/sources/install.sh install_fzf
RUN /root/sources/install.sh install_openvpn
RUN /root/sources/install.sh install_pipx
RUN /root/sources/install.sh install_exegol-history
RUN /root/sources/install.sh install_logrotate

RUN /root/sources/install.sh install_clean

WORKDIR /workspace

ENTRYPOINT ["/.exegol/entrypoint.sh"]