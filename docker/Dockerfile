ARG SRC_IMAGE

FROM $SRC_IMAGE

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive \
    apt-get install -y build-essential git wget \
    virtualenv fakeroot debhelper \
    libpcap-dev libsodium-dev libevent-dev \
    python3-twisted python3-pyroute2 \
    python3-future python3-all python3-all-dev \
    python3-serial dh-python python3-setuptools python3-msgpack


COPY src/Makefile /tmp
ENV ENV=/opt/env
ENV PYTHON=python3
RUN cd /tmp && make $ENV
