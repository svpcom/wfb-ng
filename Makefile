ARCH ?= $(shell uname -i)
PYTHON ?= /usr/bin/python3

ifneq ("$(wildcard .git)","")
    COMMIT ?= $(or $(shell git rev-parse HEAD), local)
    VERSION ?= $(or $(shell $(PYTHON) ./version.py $(shell git show -s --format="%ct" $(shell git rev-parse HEAD)) $(shell git rev-parse --abbrev-ref HEAD)), 0.0.0)
    SOURCE_DATE_EPOCH ?= $(or $(shell git show -s --format="%ct" $(shell git rev-parse HEAD)), $(shell date "+%s"))
else
    COMMIT ?= local
    VERSION ?= 0.0.0
    SOURCE_DATE_EPOCH ?= $(shell date "+%s")
endif

ENV ?= $(PWD)/env
DOCKER_SRC_IMAGE ?= "p2ptech/cross-build:2023-02-21-raspios-bullseye-armhf-lite"
STDEB ?= "git+https://github.com/svpcom/stdeb"

export VERSION COMMIT SOURCE_DATE_EPOCH

_LDFLAGS := $(LDFLAGS) -lrt -lsodium
_CFLAGS := $(CFLAGS) -Wall -O2 -fno-strict-aliasing -DWFB_VERSION='"$(VERSION)-$(shell /bin/bash -c '_tmp=$(COMMIT); echo $${_tmp::8}')"'

all: all_bin gs.key test

$(ENV):
	$(PYTHON) -m virtualenv $(ENV)
	$$(PATH=$(ENV)/bin:$(ENV)/local/bin:$(PATH) which pip3) install --upgrade pip setuptools $(STDEB)

all_bin: wfb_rx wfb_tx wfb_keygen wfb_tx_cmd wfb_tun

gs.key: wfb_keygen
	@if ! [ -f gs.key ]; then ./wfb_keygen; fi

src/%.o: src/%.c src/*.h
	$(CC) $(_CFLAGS) -std=gnu99 -c -o $@ $<

src/%.o: src/%.cpp src/*.hpp src/*.h
	$(CXX) $(_CFLAGS) -std=gnu++11 -c -o $@ $<

wfb_rx: src/rx.o src/radiotap.o src/fec.o src/wifibroadcast.o
	$(CXX) -o $@ $^ $(_LDFLAGS) -lpcap

wfb_tx: src/tx.o src/fec.o src/wifibroadcast.o
	$(CXX) -o $@ $^ $(_LDFLAGS)

wfb_keygen: src/keygen.o
	$(CC) -o $@ $^ $(_LDFLAGS)

wfb_tx_cmd: src/tx_cmd.o
	$(CC) -o $@ $^ $(LDFLAGS)

wfb_tun: src/wfb_tun.o
	$(CC) -o $@ $^ $(LDFLAGS) -levent_core

test: all_bin
	PYTHONPATH=`pwd` trial3 wfb_ng.tests

rpm:  all_bin $(ENV)
	rm -rf dist
	$(PYTHON) ./setup.py bdist_rpm --force-arch $(ARCH)
	rm -rf wfb_ng.egg-info/

deb:  all_bin $(ENV)
	rm -rf deb_dist
	$$(PATH=$(ENV)/bin:$(ENV)/local/bin:$(PATH) which python3) ./setup.py --command-packages=stdeb.command bdist_deb
	rm -rf wfb_ng.egg-info/ wfb-ng-$(VERSION).tar.gz

bdist: all_bin
	rm -rf dist
	$(PYTHON) ./setup.py bdist --plat-name linux-$(ARCH)
	rm -rf wfb_ng.egg-info/

check:
	cppcheck --std=c++11 --library=std --library=posix --library=gnu --inline-suppr --template=gcc --enable=all --suppress=cstyleCast --suppress=missingOverride --suppress=missingIncludeSystem src/
	make clean
	make CFLAGS="-g -fsanitize=address -fno-omit-frame-pointer" LDFLAGS="-fsanitize=address -static-libasan" test
	make clean

pylint:
	pylint --disable=R,C wfb_ng/*.py

clean:
	rm -rf env wfb_rx wfb_tx wfb_tx_cmd wfb_tun wfb_keygen dist deb_dist build wfb_ng.egg-info wfb-ng-*.tar.gz _trial_temp *~ src/*.o

deb_docker:  /opt/qemu/bin
	@if ! [ -d /opt/qemu ]; then echo "Docker cross build requires patched QEMU!\nApply ./scripts/qemu/qemu.patch to qemu-7.2.0 and build it:\n  ./configure --prefix=/opt/qemu --static --disable-system && make && sudo make install"; exit 1; fi
	if ! ls /proc/sys/fs/binfmt_misc | grep -q qemu ; then sudo ./scripts/qemu/qemu-binfmt-conf.sh --qemu-path /opt/qemu/bin --persistent yes; fi
	cp -a Makefile docker/src/
	TAG="wfb-ng:build-`date +%s`"; docker build -t $$TAG docker --build-arg SRC_IMAGE=$(DOCKER_SRC_IMAGE)  && \
	docker run -i --rm -v $(PWD):/build $$TAG bash -c "trap 'chown -R --reference=. .' EXIT; export VERSION=$(VERSION) COMMIT=$(COMMIT) SOURCE_DATE_EPOCH=$(SOURCE_DATE_EPOCH) && cd /build && make clean && make test && make deb"
	docker image ls -q "wfb-ng:build-*" | uniq | tail -n+6 | while read i ; do docker rmi -f $$i; done
