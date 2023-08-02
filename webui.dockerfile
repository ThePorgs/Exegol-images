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

RUN ./entrypoint.sh package_ad
RUN ./entrypoint.sh package_ad_configure
RUN ./entrypoint.sh package_network
RUN ./entrypoint.sh package_forensic
RUN ./entrypoint.sh package_reverse

RUN ./entrypoint.sh post_install_clean

RUN rm -rf /root/sources

WORKDIR /workspace

ENTRYPOINT ["/.exegol/entrypoint.sh"]