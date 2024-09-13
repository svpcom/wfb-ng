#!/usr/bin/env python
# -*- coding: utf-8 -*-

import time
import os
import struct
import errno

from twisted.python import log
from twisted.trial import unittest
from twisted.internet import reactor, defer
from twisted.internet.protocol import DatagramProtocol

from ..common import df_sleep
from ..protocols import RXProtocol, TXProtocol
from .. import call_and_check_rc


class UDP_TXRX(DatagramProtocol):
    def __init__(self, tx_addr):
        self.rxq = []
        self.tx_addr = tx_addr

    def datagramReceived(self, data, addr):
        log.msg("got %r from %s" % (data, addr))
        self.rxq.append(data)

    def send_msg(self, data):
        self.transport.write(data, self.tx_addr)


def gen_req_id(f):
    def _f(self, *args, **kwargs):
        req_id = self.req_id % (1 << 32)
        self.req_id = req_id + 1
        return f(self, req_id, *args, **kwargs)
    return _f


class FakeAntennaProtocol(object):
    def process_new_session(self, rx_id, session):
        log.msg('%s new session %r' % (rx_id, session))


    def update_rx_stats(self, rx_id, packet_stats, ant_stats, session):
        log.msg('%s %r %r %r' % (rx_id, packet_stats, ant_stats, session))

        for (((freq, mcs_index, bandwidth), ant_id),
             (pkt_s,
              rssi_min, rssi_avg, rssi_max,
              snr_min, snr_avg, snr_max)) in ant_stats.items():

            assert pkt_s >= 0
            assert freq == 4321
            assert mcs_index == 1
            assert bandwidth == 20
            assert rssi_min == rssi_avg == rssi_max == -42
            assert snr_min == snr_avg == snr_max == 28

            host, port, wlan_idx, ant_id = struct.unpack('!IHBB', ant_id.to_bytes(8, byteorder='big'))
            assert host == 0x7f000001
            assert port == 0
            assert 0 <= wlan_idx < 2
            assert 0 <= ant_id < 2

    def update_tx_stats(self, tx_id, packet_stats, ant_latency):
        log.msg('%s %r %r' % (tx_id, packet_stats, ant_latency))



class TXCommandClient(DatagramProtocol):
    noisy = False

    CMD_SET_FEC = 1
    CMD_SET_RADIO = 2
    CMD_GET_FEC = 3
    CMD_GET_RADIO = 4

    resp_map = {
        CMD_SET_FEC: lambda x: None,
        CMD_SET_RADIO: lambda x: None,
        CMD_GET_FEC: lambda x: struct.unpack('!BB', x),
        CMD_GET_RADIO: lambda x: struct.unpack('!B??BB?B', x)
    }

    def __init__(self, tx_addr):
        self.tx_addr = tx_addr
        self.callbacks = {}
        self.req_id = int(time.time())

    def datagramReceived(self, data, addr):
        if addr != self.tx_addr:
            return

        req_id, rc = struct.unpack('!II', data[:8])
        df = self.callbacks.pop(req_id, None)

        if df is None:
            log.msg("Unknown response from %s %d" % (addr, req_id), isError=1)
            return

        if rc == 0:
            df.callback(data[8:])
        else:
            df.errback(OSError("Error: %s" % (errno.errorcode.get(rc, str(rc)))))

    def _do_cmd(self, req_id, msg):
        df = defer.Deferred()
        self.callbacks[req_id] = df
        self.transport.write(msg, self.tx_addr)
        return df

    @gen_req_id
    def set_fec(self, req_id, k, n):
        def _got_response(data):
            return None

        return self._do_cmd(req_id, struct.pack('!IBBB', req_id, self.CMD_SET_FEC, k, n))\
                   .addCallback(_got_response)

    @gen_req_id
    def set_radio(self, req_id, stbc, ldpc, short_gi, bandwidth, mcs_index, vht_mode, vht_nss):
        def _got_response(data):
            return None

        return self._do_cmd(req_id, struct.pack('!IBB??BB?B', req_id, self.CMD_SET_RADIO,
                                                stbc, ldpc, short_gi, bandwidth, mcs_index, vht_mode, vht_nss))\
                   .addCallback(_got_response)

    @gen_req_id
    def get_fec(self, req_id):
        def _got_response(data):
            return dict(zip(('k', 'n'), self.resp_map[self.CMD_GET_FEC](data)))

        return self._do_cmd(req_id, struct.pack('!IB', req_id, self.CMD_GET_FEC))\
                   .addCallback(_got_response)

    @gen_req_id
    def get_radio(self, req_id):
        def _got_response(data):
            return dict(zip(('stbc', 'ldpc', 'short_gi', 'bandwidth', 'mcs_index', 'vht_mode', 'vht_nss'),
                            self.resp_map[self.CMD_GET_RADIO](data)))

        return self._do_cmd(req_id, struct.pack('!IB', req_id, self.CMD_GET_RADIO))\
                   .addCallback(_got_response)


class TXRXTestCase(unittest.TestCase):
    @defer.inlineCallbacks
    def setUp(self):
        bindir = os.path.join(os.path.dirname(__file__), '../..')
        yield call_and_check_rc(os.path.join(bindir, 'wfb_keygen'))

        self.rxp = UDP_TXRX(('127.0.0.1', 10001))
        self.txp = UDP_TXRX(('127.0.0.1', 10003))
        self.cmdp = TXCommandClient(('127.0.0.1', 7003))

        self.rx_ep = reactor.listenUDP(10002, self.rxp)
        self.tx_ep = reactor.listenUDP(10004, self.txp)
        self.cmd_ep = reactor.listenUDP(0, self.cmdp)

        link_id = int.from_bytes(os.urandom(3), 'big')
        epoch = int(time.time())
        cmd_rx = [os.path.join(bindir, 'wfb_rx'), '-K', 'drone.key', '-a', '10001', '-u', '10002',
                  '-i', str(link_id), '-e', str(epoch), '-R', str(512 * 1024), 'wlan0']
        cmd_tx = [os.path.join(bindir, 'wfb_tx'), '-K', 'gs.key', '-u', '10003', '-D', '10004', '-T', '30', '-F', '3000', '-C', '7003',
                  # '-Q', '-P 1',  ## requires root priv
                  '-i', str(link_id), '-e', str(epoch), '-R', str(512 * 1024), 'wlan0']

        ap = FakeAntennaProtocol()
        self.rx_pp = RXProtocol(ap, cmd_rx, 'debug rx')
        self.tx_pp = TXProtocol(ap, cmd_tx, 'debug tx')

        self.rx_pp.start().addErrback(lambda f: f.trap('twisted.internet.error.ProcessTerminated'))
        self.tx_pp.start().addErrback(lambda f: f.trap('twisted.internet.error.ProcessTerminated'))

        # Wait for tx/rx processes to initialize
        yield df_sleep(0.1)

    @defer.inlineCallbacks
    def tearDown(self):
        self.rx_pp.transport.signalProcess('KILL')
        self.tx_pp.transport.signalProcess('KILL')
        self.rx_ep.stopListening()
        self.tx_ep.stopListening()
        self.cmd_ep.stopListening()
        # Wait for tx/rx processes to die
        yield df_sleep(0.1)


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

        yield df_sleep(1.1)
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


    @defer.inlineCallbacks
    def test_cmd_fec(self):
        self.assertEqual(len(self.txp.rxq), 0)
        for i in range(6):
            self.txp.send_msg(b'm%d' % (i + 1,))

        yield df_sleep(0.02) # don't wait for first fec timeout
        self.assertEqual(len(self.txp.rxq), 7) # 1 session + (6 data packets)

        res = yield self.cmdp.get_fec()
        self.assertEqual(res['k'], 8)
        self.assertEqual(res['n'], 12)

        yield self.cmdp.set_fec(1, 2) # should close FEC block, set FEC 1/2 and issue N-K+1 session packets

        res = yield self.cmdp.get_fec()
        self.assertEqual(res['k'], 1)
        self.assertEqual(res['n'], 2)

        self.assertEqual(len(self.txp.rxq), 15) # 1 session + (8 data packets + 4 fec packets) + 2 session
        self.txp.send_msg(b'm%d' % (7,))
        yield df_sleep(0.1)

        self.assertEqual(len(self.txp.rxq), 17) # 1 session + (8 data packets + 4 fec packets) + 2 session + (1 data packet + 1 fec packet)

        # Check FEC recovery
        for i, pkt in enumerate(self.txp.rxq):
            if i not in (2, 4, 15):
                self.rxp.send_msg(pkt)

        yield df_sleep(0.1)
        self.assertEqual([b'm%d' % (i + 1,) for i in range(7)], self.rxp.rxq)


    @defer.inlineCallbacks
    def test_cmd_fec_invalid_args(self):
        self.assertEqual(len(self.txp.rxq), 0)
        for i in range(6):
            self.txp.send_msg(b'm%d' % (i + 1,))

        yield df_sleep(0.02) # don't wait for first fec timeout
        self.assertEqual(len(self.txp.rxq), 7) # 1 session + (6 data packets)

        try:
            yield self.cmdp.set_fec(1, 0)
            self.fail('Should fail')
        except OSError as v:
            self.assertEqual(str(v), 'Error: EINVAL')

        self.assertEqual(len(self.txp.rxq), 7) # command should be ignored
        yield df_sleep(0.1)

        self.txp.send_msg(b'm%d' % (7,))
        yield df_sleep(0.02)  # don't wait for first fec timeout

        self.assertEqual(len(self.txp.rxq), 14) # 1 session + (8 data packets + 4 fec packets) + 1 data packet

        # Check FEC recovery
        for i, pkt in enumerate(self.txp.rxq):
            if i not in (2, 4):
                self.rxp.send_msg(pkt)

        yield df_sleep(0.1)
        self.assertEqual([b'm%d' % (i + 1,) for i in range(7)], self.rxp.rxq)

    @defer.inlineCallbacks
    def test_cmd_radio(self):
        self.assertEqual(len(self.txp.rxq), 0)
        for i in range(6):
            self.txp.send_msg(b'm%d' % (i + 1,))

        yield df_sleep(0.02) # don't wait for first fec timeout
        self.assertEqual(len(self.txp.rxq), 7) # 1 session + (6 data packets)

        res = yield self.cmdp.get_radio()
        self.assertEqual(res['stbc'], 0)
        self.assertEqual(res['ldpc'], False)
        self.assertEqual(res['short_gi'], False)
        self.assertEqual(res['bandwidth'], 0)
        self.assertEqual(res['mcs_index'], 0)
        self.assertEqual(res['vht_mode'], False)
        self.assertEqual(res['vht_nss'], 0)

        yield self.cmdp.set_radio(stbc=1, ldpc=True, short_gi=False, bandwidth=40, mcs_index=3, vht_mode=False, vht_nss=0)

        res = yield self.cmdp.get_radio()
        self.assertEqual(res['stbc'], 1)
        self.assertEqual(res['ldpc'], True)
        self.assertEqual(res['short_gi'], False)
        self.assertEqual(res['bandwidth'], 40)
        self.assertEqual(res['mcs_index'], 3)
        self.assertEqual(res['vht_mode'], False)
        self.assertEqual(res['vht_nss'], 0)

        self.txp.send_msg(b'm%d' % (7,))
        yield df_sleep(0.1)

        self.assertEqual(len(self.txp.rxq), 13) # 1 session + (8 data packets + 4 fec packets)

        # Check FEC recovery
        for i, pkt in enumerate(self.txp.rxq):
            if i not in (2, 4):
                self.rxp.send_msg(pkt)

        yield df_sleep(0.1)
        self.assertEqual([b'm%d' % (i + 1,) for i in range(7)], self.rxp.rxq)

    @defer.inlineCallbacks
    def test_cmd_radio_invalid_args(self):
        self.assertEqual(len(self.txp.rxq), 0)
        for i in range(6):
            self.txp.send_msg(b'm%d' % (i + 1,))

        yield df_sleep(0.02) # don't wait for first fec timeout
        self.assertEqual(len(self.txp.rxq), 7) # 1 session + (6 data packets)

        try:
            yield self.cmdp.set_radio(stbc=200, ldpc=True, short_gi=False, bandwidth=1, mcs_index=100, vht_mode=False, vht_nss=0)
            self.fail('Should fail')
        except OSError as v:
            self.assertEqual(str(v), 'Error: EINVAL')

        self.txp.send_msg(b'm%d' % (7,))
        yield df_sleep(0.1)

        self.assertEqual(len(self.txp.rxq), 13) # 1 session + (8 data packets + 4 fec packets)

        # Check FEC recovery
        for i, pkt in enumerate(self.txp.rxq):
            if i not in (2, 4):
                self.rxp.send_msg(pkt)

        yield df_sleep(0.1)
        self.assertEqual([b'm%d' % (i + 1,) for i in range(7)], self.rxp.rxq)
