# Source-free Node 24 executor on the previously verified public base.
# The base supplies the complete patched npm 12.0.2 publisher installation.
FROM ghcr.io/t-scheiber/maintenance-node22@sha256:d1b5969e9da2c6e33e31bef573f545b295141cfe472014671266fae60d57df1a AS node24-build
USER root
ARG TARGETARCH
RUN set -eu; test "$TARGETARCH" = amd64; test "$(uname -m)" = x86_64; platform=x64; checksum=2f2c0da162318f0de47665410c7c8c2ed3d36c8f3105de4bbc61176c70a7cbf2; curl --fail --proto '=https' --max-time 120 "https://nodejs.org/dist/v24.20.0/node-v24.20.0-linux-$platform.tar.xz" --output /tmp/node24.tar.xz; echo "$checksum  /tmp/node24.tar.xz" | sha256sum --check --strict; mkdir -p /opt/node24/bin; tar -xJOf /tmp/node24.tar.xz "node-v24.20.0-linux-$platform/bin/node" > /opt/node24/bin/node; chmod 755 /opt/node24/bin/node; /opt/node24/bin/node --version
FROM ghcr.io/t-scheiber/maintenance-node22@sha256:d1b5969e9da2c6e33e31bef573f545b295141cfe472014671266fae60d57df1a
USER root
COPY --from=node24-build /opt/node24 /usr/local/maintenance-node24
ENV PATH="/usr/local/maintenance-node24/bin:/usr/local/maintenance-node22/bin:/usr/local/bin:/usr/bin:/bin"
RUN node -e 'if(process.version!=="v24.20.0")throw Error("Unexpected Node test runtime")' && npm --version && npm ls --prefix /usr/local/maintenance-npm --omit=dev --all
USER ubuntu
WORKDIR /tmp
ENTRYPOINT []
CMD ["node"]
