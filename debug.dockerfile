# Author: Charlie BROMBERG (Shutdown - @_nwodtuhs)

FROM kalilinux/kali-rolling

ARG TAG="local"
ARG VERSION="local"
ARG BUILD_DATE="n/a"

LABEL org.exegol.tag="${TAG}"
LABEL org.exegol.version="${VERSION}"
LABEL org.exegol.build_date="${BUILD_DATE}"
LABEL org.exegol.app="Exegol"
LABEL org.exegol.src_repository="https://github.com/ShutdownRepo/Exegol"

WORKDIR /data
#CMD ["/bin/zsh"]
