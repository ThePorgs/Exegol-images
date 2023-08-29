# Author: The Exegol Project

ARG BASE_IMAGE_REGISTRY="nwodtuhs/exegol-misc"
ARG BASE_IMAGE_NAME="base"
ARG TAG="local"
ARG VERSION="local"
ARG BUILD_DATE="n/a"

FROM ${BASE_IMAGE_REGISTRY}:${BASE_IMAGE_NAME}

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
RUN apt-get update
RUN ./entrypoint.sh package_desktop
RUN ./entrypoint.sh package_misc
RUN ./entrypoint.sh package_misc_configure
RUN ./entrypoint.sh package_c2
RUN ./entrypoint.sh package_c2_configure
RUN ./entrypoint.sh package_wordlists
RUN ./entrypoint.sh package_wordlists_configure
RUN ./entrypoint.sh package_cracking
RUN ./entrypoint.sh package_cracking_configure
RUN ./entrypoint.sh package_osint
RUN ./entrypoint.sh package_osint_configure
RUN ./entrypoint.sh package_web
RUN ./entrypoint.sh package_web_configure
RUN ./entrypoint.sh package_ad
RUN ./entrypoint.sh package_ad_configure
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
RUN ./entrypoint.sh post_install

WORKDIR /workspace

ENTRYPOINT ["/.exegol/entrypoint.sh"]
