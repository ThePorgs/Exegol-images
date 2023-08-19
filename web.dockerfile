# Author: The Exegol Project

FROM debian:11-slim

ARG TAG="local"
ARG VERSION="local"
ARG BUILD_DATE="n/a"

LABEL org.exegol.tag="${TAG}"
LABEL org.exegol.version="${VERSION}"
LABEL org.exegol.build_date="${BUILD_DATE}"
LABEL org.exegol.app="Exegol"
LABEL org.exegol.src_repository="https://github.com/ThePorgs/Exegol-images"

COPY sources /root/sources/

WORKDIR /root/sources/install

# WARNING: package_most_used can't be used with other functions other than: package_base, post_install
# ./entrypoint.sh package_most_used

RUN echo "${TAG}-${VERSION}" > /opt/.exegol_version
RUN chmod +x entrypoint.sh
RUN ./entrypoint.sh package_base
RUN ./entrypoint.sh package_desktop
RUN ./entrypoint.sh package_misc
RUN ./entrypoint.sh package_misc_configure
RUN ./entrypoint.sh package_wordlists
RUN ./entrypoint.sh package_wordlists_configure
RUN ./entrypoint.sh package_cracking
RUN ./entrypoint.sh package_cracking_configure
RUN ./entrypoint.sh package_osint
RUN ./entrypoint.sh package_osint_configure
RUN ./entrypoint.sh package_web
RUN ./entrypoint.sh package_web_configure
RUN ./entrypoint.sh package_code_analysis
RUN ./entrypoint.sh post_install
RUN rm -rf /root/sources /var/lib/apt/lists/*

WORKDIR /workspace

ENTRYPOINT ["/.exegol/entrypoint.sh"]
