ARCH ?= $(shell uname -i)
PYTHON ?= /usr/bin/python3
COMMIT ?= $(shell git rev-parse HEAD)
VERSION ?= $(shell $(PYTHON) ./version.py $(shell git show -s --format="%ct" $(shell git rev-parse HEAD)) $(shell git rev-parse --abbrev-ref HEAD))
SOURCE_DATE_EPOCH ?= $(shell git show -s --format="%ct" $(shell git rev-parse HEAD))
ENV ?= $(PWD)/env
DOCKER_SRC_IMAGE ?= "p2ptech/cross-build:2023-02-21-raspios-bullseye-armhf-lite"

export VERSION COMMIT SOURCE_DATE_EPOCH

_LDFLAGS := $(LDFLAGS) -lrt -lsodium
_CFLAGS := $(CFLAGS) -Wall -O2 -DWFB_VERSION='"$(VERSION)-$(shell /bin/bash -c '_tmp=$(COMMIT); echo $${_tmp::8}')"'

all: all_bin gs.key test

$(ENV):
	virtualenv --python=$(PYTHON) $(ENV)
	$(ENV)/bin/pip install --upgrade pip setuptools stdeb

all_bin: wfb_rx wfb_tx wfb_keygen

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

test: all_bin
	PYTHONPATH=`pwd` trial3 wfb_ng.tests

rpm:  all_bin $(ENV)
	rm -rf dist
	$(PYTHON) ./setup.py bdist_rpm --force-arch $(ARCH)
	rm -rf wfb_ng.egg-info/

deb:  all_bin $(ENV)
	rm -rf deb_dist
	$(ENV)/bin/python ./setup.py --command-packages=stdeb.command bdist_deb
	rm -rf wfb_ng.egg-info/ wfb-ng-$(VERSION).tar.gz

bdist: all_bin
	rm -rf dist
	$(PYTHON) ./setup.py bdist --plat-name linux-$(ARCH)
	rm -rf wfb_ng.egg-info/

clean:
	rm -rf env wfb_rx wfb_tx wfb_keygen dist deb_dist build wfb_ng.egg-info wfb-ng-*.tar.gz _trial_temp *~ src/*.o

deb_docker:  /opt/qemu/bin
	@if ! [ -d /opt/qemu ]; then echo "Docker cross build requires patched QEMU!\nApply ./scripts/qemu/qemu.patch to qemu-7.2.0 and build it:\n  ./configure --prefix=/opt/qemu --static --disable-system && make && sudo make install"; exit 1; fi
	if ! ls /proc/sys/fs/binfmt_misc | grep -q qemu ; then sudo ./scripts/qemu/qemu-binfmt-conf.sh --qemu-path /opt/qemu/bin --persistent yes; fi
	TAG="wfb-ng:build-`date +%s`"; docker build -t $$TAG docker --build-arg SRC_IMAGE=$(DOCKER_SRC_IMAGE)  && \
	docker run -i --rm -v $(PWD):/build $$TAG bash -c "trap 'chown -R --reference=. .' EXIT; export VERSION=$(VERSION) COMMIT=$(COMMIT) SOURCE_DATE_EPOCH=$(SOURCE_DATE_EPOCH) && cd /build && make clean && make test && make deb"
	docker ps -a -f 'status=exited' --format '{{ .ID }} {{ .Image }}' | grep wfb-ng:build | tail -n+11 | while read c i ; do docker rm $$c && docker rmi $$i; done
