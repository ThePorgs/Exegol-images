# Author: The Exegol Project

ARG TAG="local"
ARG VERSION="local"
ARG BUILD_DATE="n/a"

# TODO uncomment below when for prod
# FROM nwodtuhs/exegol-misc:base-${VERSION}
FROM nwodtuhs/exegol-misc-dev:base-${VERSION}

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
RUN touch /tmp/test1
RUN ./entrypoint.sh post_install
RUN rm -rf /root/sources /var/lib/apt/lists/*

WORKDIR /workspace

ENTRYPOINT ["/.exegol/entrypoint.sh"]
