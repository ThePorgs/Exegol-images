# Author: The Exegol Project

ARG BASE_IMAGE_REGISTRY="nwodtuhs/exegol-misc"
ARG BASE_IMAGE_NAME="base"

FROM ${BASE_IMAGE_REGISTRY}:${BASE_IMAGE_NAME}

# ARGs need to be placed after the FROM instruction. As per https://docs.docker.com/engine/reference/builder/#arg.
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

# WARNING: package_most_used can't be used with other functions other than: package_base
# ./entrypoint.sh package_most_used

RUN echo "${TAG}-${VERSION}" > /opt/.exegol_version
RUN chmod +x entrypoint.sh
RUN ./entrypoint.sh package_misc
RUN ./entrypoint.sh package_c2
RUN ./entrypoint.sh package_wordlists
RUN ./entrypoint.sh package_cracking
RUN ./entrypoint.sh package_osint
RUN ./entrypoint.sh package_web
RUN ./entrypoint.sh package_ad
RUN ./entrypoint.sh package_mobile
RUN ./entrypoint.sh package_iot
RUN ./entrypoint.sh package_rfid
RUN ./entrypoint.sh package_voip
RUN ./entrypoint.sh package_sdr
RUN ./entrypoint.sh package_network
RUN ./entrypoint.sh package_wifi
RUN ./entrypoint.sh package_forensic
RUN ./entrypoint.sh package_cloud
RUN ./entrypoint.sh package_steganography
RUN ./entrypoint.sh package_reverse
RUN ./entrypoint.sh package_crypto
RUN ./entrypoint.sh package_code_analysis
RUN ./entrypoint.sh post_build

WORKDIR /workspace

ENTRYPOINT ["/.exegol/entrypoint.sh"]
