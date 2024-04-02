ARG SRC_IMAGE

FROM $SRC_IMAGE

RUN apt update && \
  apt install -y build-essential git wget \
    virtualenv fakeroot debhelper \
    libpcap-dev libsodium-dev \
    python3-twisted python3-pyroute2 \
    python3-future python3-all python3-all-dev \
    python3-serial dh-python python3-msgpack

ENV ENV=/opt/env
ENV PYTHON=python3
RUN virtualenv --python=$PYTHON $ENV
RUN $ENV/bin/pip install stdeb
