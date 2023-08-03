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

RUN echo "${TAG}-${VERSION}" > /opt/.exegol_version && \
    chmod +x entrypoint.sh && \
    ./entrypoint.sh package_base && \
    ./entrypoint.sh package_misc && \
    ./entrypoint.sh package_misc_configure && \
    ./entrypoint.sh package_c2 && \
    ./entrypoint.sh package_c2_configure && \
    ./entrypoint.sh package_wordlists && \
    ./entrypoint.sh package_wordlists_configure && \
    ./entrypoint.sh package_cracking && \
    ./entrypoint.sh package_cracking_configure && \
    ./entrypoint.sh package_osint && \
    ./entrypoint.sh package_osint_configure && \
    ./entrypoint.sh package_web && \
    ./entrypoint.sh package_web_configure && \
    ./entrypoint.sh package_ad && \
    ./entrypoint.sh package_ad_configure && \
    ./entrypoint.sh package_mobile && \
    ./entrypoint.sh package_iot && \
    ./entrypoint.sh package_rfid && \
    ./entrypoint.sh package_voip && \
    ./entrypoint.sh package_sdr && \
    ./entrypoint.sh package_network && \
    ./entrypoint.sh package_wifi && \
    ./entrypoint.sh package_forensic && \
    ./entrypoint.sh package_cloud && \
    ./entrypoint.sh package_steganography && \
    ./entrypoint.sh package_reverse && \
    ./entrypoint.sh package_crypto && \
    ./entrypoint.sh package_code_analysis && \
    ./entrypoint.sh post_install && \
    rm -rf /root/sources /var/lib/apt/lists/*

WORKDIR /workspace

ENTRYPOINT ["/.exegol/entrypoint.sh"]
