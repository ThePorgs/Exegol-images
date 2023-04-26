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

ADD sources /root/sources

WORKDIR /root/sources/install

RUN chmod +x entrypoint.sh

RUN ./entrypoint.sh package_base

# WARNING: the following installs (except: package_base, post_install_clean) can't be used with package_most_used
RUN ./entrypoint.sh package_misc
RUN ./entrypoint.sh package_misc_configure
RUN ./entrypoint.sh package_c2
RUN ./entrypoint.sh package_c2_configure
RUN ./entrypoint.sh package_wordlists
RUN ./entrypoint.sh package_wordlists_configure
RUN ./entrypoint.sh package_cracking
RUN ./entrypoint.sh package_cracking_configure
RUN ./entrypoint.sh package_web
RUN ./entrypoint.sh package_web_configure
RUN ./entrypoint.sh package_ad
RUN ./entrypoint.sh package_ad_configure
RUN ./entrypoint.sh package_network

RUN ./entrypoint.sh post_install_clean

RUN rm -rf /root/sources

WORKDIR /workspace

ENTRYPOINT ["/.exegol/entrypoint.sh"]