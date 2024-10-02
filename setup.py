#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
from setuptools import setup, find_packages, command

# Mark deb package as binary
try:
    import stdeb.util
    class DebianInfo(stdeb.util.DebianInfo):
        def __init__(self, *args, **kwargs):
            kwargs['has_ext_modules'] = True
            super().__init__(*args, **kwargs)

    stdeb.util.DebianInfo = DebianInfo
except ImportError:
    pass

version = os.environ.get('VERSION')
commit = os.environ.get('COMMIT')
install_data_files = not bool(os.environ.get('OMIT_DATA_FILES'))

assert version and commit

with open('wfb_ng/conf/site.cfg', 'w') as fd:
    fd.write("# Don't make any changes here, use local.cfg instead!\n\n[common]\nversion = %r\ncommit = %r\n" % (version, commit))

def _long_description():
    with open('README.md', encoding='utf-8') as fd:
        start = False
        for line in fd:
            if line.startswith('Main features:'):
                start = True
            elif line.startswith('#'):
                break

            if start:
                yield line

setup(
    url="http://wfb-ng.org",
    name="wfb-ng",
    version=version,
    packages=find_packages(exclude=["*.tests", "*.tests.*", "tests.*", "tests"]),
    zip_safe=False,
    entry_points={'console_scripts': ['wfb-cli=wfb_ng.cli:main',
                                      'wfb-test-latency=wfb_ng.latency_test:main',
                                      'wfb-server=wfb_ng.server:main',
                                      'wfb-log-parser=wfb_ng.log_parser:main']},
    package_data={'wfb_ng.conf': ['master.cfg', 'site.cfg']},
    data_files = [('/usr/bin', ['wfb_tx', 'wfb_rx', 'wfb_keygen', 'wfb_tx_cmd', 'scripts/wfb-cli-x11']),
                  ('/lib/systemd/system', ['scripts/wifibroadcast.service',
                                           'scripts/wifibroadcast@.service',
                                           'scripts/wfb-cluster.service',
                                           'scripts/wfb-cluster-node.service',
                                           'scripts/wfb-cluster-manager@.service']),
                  ('/etc/default', ['scripts/default/wifibroadcast']),
                  ('/etc/sysctl.d', ['scripts/98-wifibroadcast.conf']),
                  ('/etc/logrotate.d', ['scripts/wifibroadcast'])] if install_data_files else [],

    keywords="wfb-ng, wifibroadcast",
    author="Vasily Evseenko",
    author_email="svpcom@p2ptech.org",
    description="Long-range packet radio link based on raw WiFi radio",
    long_description=''.join(_long_description()),
    long_description_content_type='text/markdown',
    license="GPLv3",
)
