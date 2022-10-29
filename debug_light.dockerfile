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

RUN uname -m
RUN apt update
RUN /root/sources/install.sh fapt git
RUN /root/sources/install.sh fapt ca-certificates
RUN /root/sources/install.sh fapt curl
RUN /root/sources/install.sh fapt zsh
RUN /root/sources/install.sh install_ohmyzsh
RUN rm -rf /root/sources