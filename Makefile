SHELL = /bin/bash
ARCH ?= $(shell uname -m)
PYTHON ?= /usr/bin/python3
OS_CODENAME ?= $(shell lsb_release -cs)

ifneq ("$(wildcard .git)","")
    RELEASE ?= $(or $(shell git rev-parse --abbrev-ref HEAD | grep -v '^stable$$'),\
                    $(shell git describe --all --match 'release-*' --match 'origin/release-*' --abbrev=0 HEAD 2>/dev/null | grep -o '[^/]*$$'),\
                    unknown)
    COMMIT ?= $(shell git rev-parse HEAD)
    SOURCE_DATE_EPOCH ?= $(or $(shell git show -s --format="%ct" $(COMMIT)), $(shell date "+%s"))
    VERSION ?= $(shell $(PYTHON) ./version.py $(SOURCE_DATE_EPOCH) $(RELEASE))
else
    COMMIT ?= release
    SOURCE_DATE_EPOCH ?= $(shell date "+%s")
    VERSION ?= $(or $(shell basename $(PWD) | grep -E -o '[0-9]+.[0-9]+(.[0-9]+)?$$'), 0.0.0)
endif

ENV ?= $(PWD)/env
DOCKER_ARCH ?= amd64
DOCKER_SRC_IMAGE ?= "p2ptech/cross-build:2023-02-21-raspios-bullseye-armhf-lite"
STDEB ?= "git+https://github.com/svpcom/stdeb"
QEMU_CPU ?= "max"

export VERSION COMMIT SOURCE_DATE_EPOCH

_LDFLAGS := $(LDFLAGS) -lrt -lsodium
_CFLAGS := $(CFLAGS) -Wall -O2 -fno-strict-aliasing -DZFEX_UNROLL_ADDMUL_SIMD=8 -DZFEX_USE_INTEL_SSSE3 -DZFEX_USE_ARM_NEON -DZFEX_INLINE_ADDMUL -DZFEX_INLINE_ADDMUL_SIMD -DWFB_VERSION='"$(VERSION)-$(shell /bin/bash -c '_tmp=$(COMMIT); echo $${_tmp::8}')"'

all: all_bin gs.key test

version:
	@echo -e "RELEASE=$(RELEASE)\nCOMMIT=$(COMMIT)\nVERSION=$(VERSION)\nSOURCE_DATE_EPOCH=$(SOURCE_DATE_EPOCH)"

$(ENV):
	$(PYTHON) -m virtualenv --download $(ENV)
	$$(PATH=$(ENV)/bin:$(ENV)/local/bin:$(PATH) which python3) -m pip install --upgrade pip setuptools $(STDEB)

all_bin: wfb_rx wfb_tx wfb_keygen wfb_tx_cmd wfb_tun

gs.key: wfb_keygen
	@if ! [ -f gs.key ]; then ./wfb_keygen; fi

src/%.o: src/%.c src/*.h
	$(CC) $(_CFLAGS) -std=gnu99 -c -o $@ $<

src/%.o: src/%.cpp src/*.hpp src/*.h
	$(CXX) $(_CFLAGS) -std=gnu++11 -c -o $@ $<

wfb_rx: src/rx.o src/radiotap.o src/zfex.o src/wifibroadcast.o
	$(CXX) -o $@ $^ $(_LDFLAGS) -lpcap

wfb_tx: src/tx.o src/zfex.o src/wifibroadcast.o
	$(CXX) -o $@ $^ $(_LDFLAGS)

fec_test: src/fec_test.cpp src/zfex.o
	$(CXX) $(_CFLAGS) -o $@ $^ $(LDFLAGS) $(shell pkg-config --libs catch2-with-main)

libsodium_test: src/libsodium_test.cpp
	$(CXX) $(_CFLAGS) -o $@ $^ $(LDFLAGS) -lsodium $(shell pkg-config --libs catch2-with-main)

wfb_keygen: src/keygen.o
	$(CC) -o $@ $^ $(_LDFLAGS)

wfb_tx_cmd: src/tx_cmd.o
	$(CC) -o $@ $^ $(LDFLAGS)

wfb_tun: src/wfb_tun.o
	$(CC) -o $@ $^ $(LDFLAGS) -levent_core

wfb_rtsp: src/rtsp_server.c
	$(CC) $(_CFLAGS) $(shell pkg-config --cflags gstreamer-rtsp-server-1.0) -o $@ $^ $(LDFLAGS) $(shell pkg-config --libs gstreamer-rtsp-server-1.0)

test: all_bin fec_test libsodium_test
	./fec_test
	./libsodium_test
	PYTHONPATH=`pwd` trial3 wfb_ng.tests

rpm:  all_bin wfb_rtsp $(ENV)
	rm -rf dist
	$$(PATH=$(ENV)/bin:$(ENV)/local/bin:$(PATH) which python3) ./setup.py bdist_rpm --force-arch $(ARCH) --requires python3-twisted,python3-pyroute2,python3-pyserial,python3-msgpack,python3-jinja2,python3-yaml,socat,iw
	rm -rf wfb_ng.egg-info/

deb:  all_bin wfb_rtsp $(ENV)
	rm -rf deb_dist
	$$(PATH=$(ENV)/bin:$(ENV)/local/bin:$(PATH) which python3) ./setup.py --command-packages=stdeb.command sdist_dsc --debian-version 0~$(OS_CODENAME) bdist_deb
	rm -rf wfb_ng.egg-info/ wfb-ng-$(VERSION).tar.gz

bdist: all_bin wfb_rtsp
	rm -rf dist
	$$(PATH=$(ENV)/bin:$(ENV)/local/bin:$(PATH) which python3) ./setup.py bdist --plat-name linux-$(ARCH)
	rm -rf wfb_ng.egg-info/

check:
	cppcheck --force --std=c++11 --library=std --library=posix --library=gnu --inline-suppr --template=gcc --enable=all --suppress=cstyleCast --suppress=missingOverride --suppress=missingIncludeSystem src/
	make clean
	make CFLAGS="$(CFLAGS) -g -fno-omit-frame-pointer -fsanitize=address -fsanitize=undefined -fsanitize=pointer-compare -fsanitize=pointer-subtract -fsanitize=leak -fsanitize-address-use-after-scope" LDFLAGS="-static-libasan -fsanitize=address -fsanitize=undefined -fsanitize=pointer-compare -fsanitize=pointer-subtract -fsanitize=leak -fsanitize-address-use-after-scope" test
	make clean

pylint:
	pylint --disable=R,C wfb_ng/*.py

clean:
	rm -rf env wfb_rx wfb_tx wfb_tx_cmd wfb_tun wfb_rtsp wfb_keygen dist deb_dist build wfb_ng.egg-info wfb_ng-*.tar.gz _trial_temp *~ src/*.o fec_test libsodium_test

deb_docker:  /opt/qemu/bin
	@if ! [ -d /opt/qemu ]; then echo "Docker cross build requires patched QEMU!\nApply ./scripts/qemu/qemu.patch to qemu-7.2.0 and build it:\n  ./configure --prefix=/opt/qemu --static --disable-system && make && sudo make install"; exit 1; fi
	if ! ls /proc/sys/fs/binfmt_misc | grep -q qemu ; then sudo ./scripts/qemu/qemu-binfmt-conf.sh --qemu-path /opt/qemu/bin --persistent yes; fi
	cp -a Makefile docker/src/
	TAG="wfb-ng:build-`date +%s`"; docker build --platform linux/$(DOCKER_ARCH) -t $$TAG --build-arg SRC_IMAGE=$(DOCKER_SRC_IMAGE) --build-arg QEMU_CPU=$(QEMU_CPU) -f docker/Dockerfile.debian docker && \
	docker run --privileged --platform linux/$(DOCKER_ARCH) -i --rm -v $(PWD):/build $$TAG bash -c "trap 'chown -R --reference=/build/. /build' EXIT; export VERSION=$(VERSION) COMMIT=$(COMMIT) SOURCE_DATE_EPOCH=$(SOURCE_DATE_EPOCH) CFLAGS='$(CFLAGS)' && /sbin/sysctl net.unix.max_dgram_qlen=512 && cd /build && make clean && make test && make deb"
	docker image ls -q "wfb-ng:build-*" | uniq | tail -n+6 | while read i ; do docker rmi -f $$i; done

rpm_docker:  /opt/qemu/bin
	@if ! [ -d /opt/qemu ]; then echo "Docker cross build requires patched QEMU!\nApply ./scripts/qemu/qemu.patch to qemu-7.2.0 and build it:\n  ./configure --prefix=/opt/qemu --static --disable-system && make && sudo make install"; exit 1; fi
	if ! ls /proc/sys/fs/binfmt_misc | grep -q qemu ; then sudo ./scripts/qemu/qemu-binfmt-conf.sh --qemu-path /opt/qemu/bin --persistent yes; fi
	cp -a Makefile docker/src/
	TAG="wfb-ng:build-`date +%s`"; docker build --platform linux/$(DOCKER_ARCH) -t $$TAG --build-arg SRC_IMAGE=$(DOCKER_SRC_IMAGE) --build-arg QEMU_CPU=$(QEMU_CPU) -f docker/Dockerfile.redhat docker && \
	docker run --privileged --platform linux/$(DOCKER_ARCH) -i --rm -v $(PWD):/build $$TAG bash -c "trap 'chown -R --reference=/build/. /build' EXIT; export VERSION=$(VERSION) COMMIT=$(COMMIT) SOURCE_DATE_EPOCH=$(SOURCE_DATE_EPOCH) CFLAGS='$(CFLAGS)' && /sbin/sysctl net.unix.max_dgram_qlen=512 && cd /build && make clean && make test && make rpm"
	docker image ls -q "wfb-ng:build-*" | uniq | tail -n+6 | while read i ; do docker rmi -f $$i; done
