# SPDX-License-Identifier: GPL-3.0-or-later
#
# CI build image: the same pinned toolchain as the local development container
# (Debian 13 amd64, GCC 14, Clang 19 with compiler-rt, CMake 3.31, Conan 2.31.2),
# plus tshark for the protocol-integrity tests. tshark is an external test tool;
# it is never linked into mcx-anonymizer.
FROM --platform=linux/amd64 debian:13-slim

ARG CONAN_VERSION=2.31.2
ARG DEBIAN_FRONTEND=noninteractive

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        build-essential gcc-14 g++-14 \
        clang-19 llvm-19 libclang-rt-19-dev lld-19 \
        cmake ninja-build make ccache pkgconf patch perl \
        git ca-certificates curl xz-utils file \
        python3 python3-venv \
        tshark util-linux binutils; \
    rm -rf /var/lib/apt/lists/*; \
    update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-14 100; \
    update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-14 100; \
    update-alternatives --install /usr/bin/clang clang /usr/bin/clang-19 100; \
    update-alternatives --install /usr/bin/clang++ clang++ /usr/bin/clang++-19 100

RUN set -eux; \
    python3 -m venv /opt/conan; \
    /opt/conan/bin/pip install --no-cache-dir "conan==${CONAN_VERSION}"; \
    ln -s /opt/conan/bin/conan /usr/local/bin/conan

ENV CONAN_HOME=/opt/conan-home
COPY profiles/ /opt/conan-home/profiles/
RUN set -eux; \
    cp /opt/conan-home/profiles/gcc14 /opt/conan-home/profiles/default

# The toolchain versions are part of the build contract: fail the image build
# if the base image drifts.
RUN set -eux; \
    gcc -dumpfullversion | grep -qE '^14\.'; \
    clang --version | head -1 | grep -qE 'version 19\.'; \
    cmake --version | head -1 | grep -qE ' 3\.31\.'; \
    conan --version | grep -qF "${CONAN_VERSION}"; \
    tshark --version | head -1; \
    chmod -R a+rwX /opt/conan-home   # usable by any UID (CI runs as root, local runs as the user)
