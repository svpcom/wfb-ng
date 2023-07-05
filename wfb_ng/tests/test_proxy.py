#!/usr/bin/env python
# -*- coding: utf-8 -*-

import time
from twisted.python import log
from twisted.trial import unittest
from twisted.internet import reactor, defer
from twisted.internet.protocol import DatagramProtocol
from ..mavlink import MAVLink_heartbeat_message, MAVLink
from ..proxy import UDPProxyProtocol, MavlinkUDPProxyProtocol
from ..mavlink_protocol import MavlinkARMProtocol
from ..common import df_sleep

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
        self.replies = []

    def startProtocol(self):
        log.msg('send %d of %r to %s' % (self.count, self.msg, self.addr))
        for i in range(self.count):
            self.transport.write(self.msg, self.addr)

    def datagramReceived(self, data, addr):
        log.msg("received back %r from %s" % (data, addr))
        self.replies.append((data, addr))

        if len(self.replies) == self.count:
            self.df.callback(self.replies)


class UDPProxyTestCase(unittest.TestCase):
    def setUp(self):
        self.arm_proto = MavlinkARMProtocol(call_on_arm='/bin/true',
                                            call_on_disarm='/bin/true')

        self.p1 = MavlinkUDPProxyProtocol(addr=None, mirror=None, agg_max_size=1445, agg_timeout=1, inject_rssi=True, mavlink_sys_id=3, mavlink_comp_id=242,
                                          rx_hooks=[self.arm_proto.dataReceived], tx_hooks=[self.arm_proto.dataReceived])
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
        p = SendPacket(b'\xfd\t\x00\x00\x00\x03\xf2m\x00\x00\x02\x00\x03\x00\x01\x01d\x00\x04\xa8\xad', addr, 10)
        ep3 = reactor.listenUDP(9999, p)
        ep4 = reactor.listenUDP(14553, Echo())
        try:
            ts = time.time()
            _replies = yield p.df
            _expected = [(b'\xfd\t\x00\x00\x00\x03\xf2m\x00\x00\x02\x00\x03\x00\x01\x01d\x00\x04\xa8\xad', addr)] * 10
            self.assertGreater(time.time() - ts, 1.0)
            self.assertEqual(_replies, _expected)
        finally:
            ep4.stopListening()
            ep3.stopListening()

    @defer.inlineCallbacks
    def test_rssi_injection(self):
        addr = ('127.0.0.1', 14551)
        p = SendPacket(b'test', addr)

        ep3 = reactor.listenUDP(9999, p)
        yield df_sleep(0.1)

        try:
            self.p1.send_rssi('test', 1, 2, 3, 4)
            ts = time.time()
            _replies = yield p.df
            _expected = [(b'\xfd\t\x00\x00\x00\x03\xf2m\x00\x00\x02\x00\x03\x00\x01\x01d\x00\x04\xa8\xad', addr)]
            self.assertLess(time.time() - ts, 1.0)
            self.assertEqual(_replies, _expected)
        finally:
            ep3.stopListening()

    @defer.inlineCallbacks
    def __test_arm_protocol(self, force_mavlink1):
        addr = ('127.0.0.1', 14551)
        mav = MAVLink(None, srcSystem=1, srcComponent=1)
        msg = MAVLink_heartbeat_message(1, 8, 128, 0, 0, 1).pack(mav, force_mavlink1=force_mavlink1)

        p = SendPacket(msg, addr)

        ep3 = reactor.listenUDP(9999, p)
        ep4 = reactor.listenUDP(14553, Echo())
        try:
            ts = time.time()
            yield p.df
            self.assertEqual(self.arm_proto.armed, True)
        finally:
            ep3.stopListening()
            ep4.stopListening()


    def test_arm_protocol_mav1(self):
        return self.__test_arm_protocol(True)

    def test_arm_protocol_mav2(self):
        return self.__test_arm_protocol(False)
