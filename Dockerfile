# check=skip=CopyIgnoredFile
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Runtime image of mcxanon. The binary is built in the pinned build image of .ci/:
#
#   docker build -t mcxanon-ci .ci
#   docker build -t mcx-anonymizer .
#
# Run with the captures on /work and the projects on /data (see README.md, Install).
ARG BUILDER=mcxanon-ci

FROM ${BUILDER} AS build
WORKDIR /src
COPY . .
RUN set -eux; \
    bash .ci/build.sh gcc14; \
    install -D -m 0755 build/Release/src/cli/mcxanon /out/mcxanon; \
    strip /out/mcxanon; \
    /out/mcxanon --version

FROM debian:13-slim
ARG VERSION=dev
LABEL org.opencontainers.image.title="mcx-anonymizer" \
      org.opencontainers.image.description="Offline, fail-closed anonymiser for MCPTT / MCData / MCVideo packet captures (pcap, pcapng)" \
      org.opencontainers.image.source="https://github.com/UIMS-EU/mcx-anonymizer" \
      org.opencontainers.image.licenses="GPL-3.0-or-later" \
      org.opencontainers.image.vendor="UIMS" \
      org.opencontainers.image.version="${VERSION}"
COPY --from=build /out/mcxanon /usr/local/bin/mcxanon
COPY LICENSE README.md /usr/share/doc/mcx-anonymizer/
RUN set -eux; mkdir -m 1777 /work /data
ENV MCXANON_DATA_DIR=/data
WORKDIR /work
USER 65532:65532
ENTRYPOINT ["mcxanon"]
CMD ["--help"]
