#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import time
from twisted import version as twisted_version
from twisted.python import log
from twisted.trial import unittest
from twisted.internet import reactor, defer
from twisted.internet.utils import getProcessOutputAndValue
from incremental import Version
from ..tuntap import TUNTAPTransport, TUNTAPProtocol
from ..common import df_sleep


test_script="""\
set -e
trap 'ip netns delete tuntest' EXIT
ip netns add tuntest
ip link set tuntest2 netns tuntest
ip netns exec tuntest bash -c "ifconfig tuntest2 up 192.168.77.2/24 && ping -c1 -I tuntest2 192.168.77.1"
"""

arch = os.uname().machine
bad_arch = ("mips64", "s390x", "ppc64le")

class TUNTAPTestCase(unittest.TestCase):
    if os.geteuid() != 0 or not os.path.exists('/dev/net/tun') \
       or arch in bad_arch \
       or twisted_version < Version("Twisted", 19, 7, 0):
        skip = "Root requires or system is incompatible"

    def setUp(self):
        self.p1 = TUNTAPProtocol(mtu=1400)
        self.p2 = TUNTAPProtocol(mtu=1400)
        self.p1.peer = self.p2
        self.p2.peer = self.p1
        self.ep1 = TUNTAPTransport(reactor, self.p1, 'tuntest1', '192.168.77.1/24', mtu=1400)
        self.ep2 = TUNTAPTransport(reactor, self.p2, 'tuntest2', '192.168.77.2/24', mtu=1400)

    def tearDown(self):
        self.ep1.loseConnection()
        self.ep2.loseConnection()
        self.p1._cleanup()
        self.p2._cleanup()

    def test_tuntap(self):
        def _got_rc(x):
            (out, err, code) = x
            log.msg(out.decode('utf-8'))
            log.msg(err.decode('utf-8'))
            self.assertEqual(code, 0)

        return getProcessOutputAndValue('bash', env=os.environ, stdinBytes=test_script.encode())\
            .addCallback(_got_rc)

