# Author: Charlie BROMBERG (Shutdown - @_nwodtuhs)

FROM debian

ARG TAG="local"
ARG VERSION="local"
ARG BUILD_DATE="n/a"

LABEL org.exegol.tag="${TAG}"
LABEL org.exegol.version="${VERSION}"
LABEL org.exegol.build_date="${BUILD_DATE}"
LABEL org.exegol.app="Exegol"
LABEL org.exegol.src_repository="https://github.com/ShutdownRepo/Exegol-images"

RUN echo "${TAG}-${VERSION}" > /opt/.exegol_version

#ADD sources /root/sources
#RUN chmod +x /root/sources/install.sh

#RUN /root/sources/install.sh install_base

#RUN /root/sources/install.sh install_clean

#RUN rm -rf /root/sources

WORKDIR /data

ENTRYPOINT ["/.exegol/entrypoint.sh"]
