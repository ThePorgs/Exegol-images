# Author: The Exegol Project

ARG BASE_IMAGE_REGISTRY="nwodtuhs/exegol-misc"
ARG BASE_IMAGE_NAME="base"

FROM ${BASE_IMAGE_REGISTRY}:${BASE_IMAGE_NAME}

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
RUN apt-get update
RUN ./entrypoint.sh package_desktop
RUN ./entrypoint.sh package_most_used
RUN ./entrypoint.sh configure_john
RUN ./entrypoint.sh package_misc
RUN ./entrypoint.sh package_misc_configure
RUN ./entrypoint.sh post_install

WORKDIR /workspace

ENTRYPOINT ["/.exegol/entrypoint.sh"]
