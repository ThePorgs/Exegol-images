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
RUN chmod +x /root/sources/install.sh

RUN /root/sources/install.sh package_base

# WARNING: package_most_used can't be used with other functions other than: package_base, post_install_clean
# RUN /root/sources/install.sh package_most_used

# WARNING: the following installs (except: package_base, post_install_clean) can't be used with package_most_used
RUN /root/sources/install.sh package_misc
RUN /root/sources/install.sh package_wordlists
RUN /root/sources/install.sh package_cracking
# RUN /root/sources/install.sh package_osint
RUN /root/sources/install.sh package_web
RUN /root/sources/install.sh package_c2
RUN /root/sources/install.sh package_ad
# RUN /root/sources/install.sh package_mobile
# RUN /root/sources/install.sh package_iot
# RUN /root/sources/install.sh package_rfid
# RUN /root/sources/install.sh package_sdr
RUN /root/sources/install.sh package_network
# RUN /root/sources/install.sh package_wifi
# RUN /root/sources/install.sh package_forensic
# RUN /root/sources/install.sh package_cloud
# RUN /root/sources/install.sh package_steganography
# RUN /root/sources/install.sh package_reverse
# RUN /root/sources/install.sh package_code_analysis

RUN /root/sources/install.sh post_install_clean

RUN rm -rf /root/sources

WORKDIR /workspace

ENTRYPOINT ["/.exegol/entrypoint.sh"]
