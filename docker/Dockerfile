ARG SRC_IMAGE

FROM $SRC_IMAGE

RUN apt update && \
  apt install -y build-essential git wget \
    virtualenv fakeroot debhelper \
    libpcap-dev libsodium-dev \
    python3-twisted python3-pyroute2 \
    python3-future python3-all \
    python3-serial dh-python

RUN pip3 install --upgrade setuptools stdeb