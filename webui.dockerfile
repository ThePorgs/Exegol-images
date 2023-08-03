# Author: The Exegol Project

FROM debian:11

ARG TAG="local"
ARG VERSION="local"
ARG BUILD_DATE="n/a"

LABEL org.exegol.tag="${TAG}"
LABEL org.exegol.version="${VERSION}"
LABEL org.exegol.build_date="${BUILD_DATE}"
LABEL org.exegol.app="Exegol"
LABEL org.exegol.src_repository="https://github.com/ThePorgs/Exegol-images"

RUN echo "${TAG}-${VERSION}" > /opt/.exegol_version

ADD . sources /root/sources/

WORKDIR /root/sources/install

RUN chmod +x entrypoint.sh

RUN ./entrypoint.sh package_base
RUN ./entrypoint.sh package_webui

RUN ./entrypoint.sh install_bloodhound
RUN ./entrypoint.sh configure_bloodhound
RUN ./entrypoint.sh install_neo4j
RUN ./entrypoint.sh install_ghidra
RUN ./entrypoint.sh install_jd-gui
RUN ./entrypoint.sh install_burpsuite
RUN ./entrypoint.sh install_maltego
RUN apt install -y wireshark

RUN ./entrypoint.sh post_install

RUN rm -rf /root/sources

WORKDIR /workspace

ENTRYPOINT ["/.exegol/entrypoint.sh"]