#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import unicode_literals
from __future__ import print_function
from __future__ import division
from __future__ import absolute_import

from future import standard_library
standard_library.install_aliases()
from builtins import *

import time
from twisted.python import log
from twisted.trial import unittest
from twisted.internet import reactor, defer
from telemetry.tuntap import TUNTAPTransport, TUNTAPProtocol
from telemetry.common import df_sleep


class TUNTAPTestCase(unittest.TestCase):
    def setUp(self):
        self.p1 = TUNTAPProtocol()
        self.p2 = TUNTAPProtocol()
        self.p1.peer = self.p2
        self.p2.peer = self.p1
        self.ep1 = TUNTAPTransport(reactor, self.p1, 'tuntest1', '192.168.77.1/24')
        self.ep2 = TUNTAPTransport(reactor, self.p2, 'tuntest2', '192.168.77.2/24')

    def tearDown(self):
        self.ep1.loseConnection()
        self.ep2.loseConnection()
        self.p1._cleanup()
        self.p2._cleanup()

    def test_tuntap(self):
        # Test manually via "ping -I tuntest1 192.168.77.2" and "tcpdump -i tuntest2 -nn -p icmp"
        return df_sleep(1)

