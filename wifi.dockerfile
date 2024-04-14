# Author: The Exegol Project

FROM debian:12-slim

# ARGs need to be placed after the FROM instruction. As per https://docs.docker.com/engine/reference/builder/#arg
# If they are placed before, they will be overwritten somehow, and the LABELs below will be filled with empty ARGs
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
RUN ./entrypoint.sh package_wordlists
RUN ./entrypoint.sh package_cracking
RUN ./entrypoint.sh package_wifi
RUN ./entrypoint.sh post_install

WORKDIR /workspace

ENTRYPOINT ["/.exegol/entrypoint.sh"]
