#!/usr/bin/env python
# -*- coding: utf-8 -*-

import time
from twisted.python import log
from twisted.trial import unittest
from twisted.internet import reactor, defer
from telemetry.proxy import UDPProxyProtocol
from twisted.internet.protocol import DatagramProtocol
from telemetry.common import df_sleep

class Echo(DatagramProtocol):
    def datagramReceived(self, data, addr):
        log.msg("got %r from %s" % (data, addr))
        self.transport.write(data, addr)


class SendPacket(DatagramProtocol):
    def __init__(self, msg, addr, count=1):
        self.df = defer.Deferred()
        self.msg = msg
        self.addr = addr
        self.count = count

    def startProtocol(self):
        log.msg('send %d of %s to %s' % (self.count, self.msg, self.addr))
        for i in range(self.count):
            self.transport.write(self.msg, self.addr)

    def datagramReceived(self, data, addr):
        log.msg("received back %r from %s" % (data, addr))
        self.df.callback(addr)

class UDPProxyTestCase(unittest.TestCase):
    def setUp(self):
        self.p1 = UDPProxyProtocol(agg_max_size=1446, agg_timeout=1)
        self.p2 = UDPProxyProtocol(('127.0.0.1', 14553))
        self.p1.peer = self.p2
        self.p2.peer = self.p1
        self.ep1 = reactor.listenUDP(14551, self.p1)
        self.ep2 = reactor.listenUDP(0, self.p2)

    def tearDown(self):
        self.ep1.stopListening()
        self.ep2.stopListening()
        self.p1._cleanup()
        self.p2._cleanup()

    @defer.inlineCallbacks
    def test_proxy(self):
        addr = ('127.0.0.1', 14551)
        p = SendPacket('test', addr)
        ep3 = reactor.listenUDP(9999, p)
        ep4 = reactor.listenUDP(14553, Echo())
        try:
            ts = time.time()
            _addr = yield p.df
            self.assertGreater(time.time() - ts, 1.0)
            self.assertEqual(_addr, addr)
        finally:
            ep4.stopListening()
            ep3.stopListening()

    @defer.inlineCallbacks
    def test_rssi_injection_and_aggregation(self):
        addr = ('127.0.0.1', 14551)
        p = SendPacket('test', addr)

        ep3 = reactor.listenUDP(9999, p)
        yield df_sleep(0.1)

        try:
            for i in range(100):
                self.p1.send_rssi(1, 2, 3, 4)

            ts = time.time()
            _addr = yield p.df
            self.assertLess(time.time() - ts, 1.0)


            self.assertEqual(_addr, addr)
            self.assertEqual(len(self.p1.agg_queue), 24)
            self.assertEqual(self.p1.agg_queue_size, 456)
        finally:
            ep3.stopListening()

