#!/usr/bin/env python
# -*- coding: utf-8 -*-

import time
import os

from twisted.python import log
from twisted.trial import unittest
from twisted.internet import reactor, defer
from twisted.internet.protocol import DatagramProtocol

from ..common import df_sleep
from ..server import RXProtocol, TXProtocol, call_and_check_rc

class UDP_TXRX(DatagramProtocol):
    def __init__(self, tx_addr):
        self.rxq = []
        self.tx_addr = tx_addr

    def datagramReceived(self, data, addr):
        log.msg("got %r from %s" % (data, addr))
        self.rxq.append(data)

    def send_msg(self, data):
        self.transport.write(data, self.tx_addr)


class TXRXTestCase(unittest.TestCase):
    @defer.inlineCallbacks
    def setUp(self):
        bindir = os.path.join(os.path.dirname(__file__), '../..')
        yield call_and_check_rc(os.path.join(bindir, 'wfb_keygen'))

        self.rxp = UDP_TXRX(('127.0.0.1', 10001))
        self.txp = UDP_TXRX(('127.0.0.1', 10003))

        self.rx_ep = reactor.listenUDP(10002, self.rxp)
        self.tx_ep = reactor.listenUDP(10004, self.txp)

        link_id = int.from_bytes(os.urandom(3), 'big')
        epoch = int(time.time())
        cmd_rx = [os.path.join(bindir, 'wfb_rx'), '-K', 'drone.key', '-a', '10001', '-u', '10002',
                  '-i', str(link_id), '-e', str(epoch), '-R', str(512 * 1024), 'wlan0']
        cmd_tx = [os.path.join(bindir, 'wfb_tx'), '-K', 'gs.key', '-u', '10003', '-D', '10004', '-T', '30',
                  '-i', str(link_id), '-e', str(epoch), '-R', str(512 * 1024), 'wlan0']

        self.rx_pp = RXProtocol(None, cmd_rx, 'debug rx')
        self.tx_pp = TXProtocol(None, cmd_tx, 'debug tx')

        self.rx_pp.start().addErrback(lambda f: f.trap('twisted.internet.error.ProcessTerminated'))
        self.tx_pp.start().addErrback(lambda f: f.trap('twisted.internet.error.ProcessTerminated'))

        # Wait for tx/rx processes to initialize
        yield df_sleep(0.1)

    def tearDown(self):
        self.rx_pp.transport.signalProcess('KILL')
        self.tx_pp.transport.signalProcess('KILL')
        self.rx_ep.stopListening()
        self.tx_ep.stopListening()

    @defer.inlineCallbacks
    def test_txrx(self):
        self.assertEqual(len(self.txp.rxq), 0)
        for i in range(16):
            self.txp.send_msg(b'm%d' % (i + 1,))

        yield df_sleep(0.1)
        self.assertEqual(len(self.txp.rxq), 25) # 1 session + (8 data packets + 4 fec packets) * 2

        # Check FEC fail and recovery
        # 1. Fail on block #1: lost 5 packets
        # 2. Recover on block #2: lost 3 packets
        for i, pkt in enumerate(self.txp.rxq):
            if i not in (4, 9, 10, 11, 12, 11 + 4, 11 + 5, 11 + 6):
                self.rxp.send_msg(pkt)

        yield df_sleep(0.1)
        self.assertEqual([b'm%d' % (i + 1,) for i in range(16) if i + 1 != 4], self.rxp.rxq)


    @defer.inlineCallbacks
    def test_fec_timeout(self):
        self.assertEqual(len(self.txp.rxq), 0)
        for i in range(6):
            self.txp.send_msg(b'm%d' % (i + 1,))

        yield df_sleep(0.1)
        self.assertEqual(len(self.txp.rxq), 13) # 1 session + 8 data packets + 4 fec packets

        # Check FEC recovery
        for i, pkt in enumerate(self.txp.rxq):
            if i not in (2, 4):
                self.rxp.send_msg(pkt)

        yield df_sleep(0.1)
        self.assertEqual([b'm%d' % (i + 1,) for i in range(6)], self.rxp.rxq)

