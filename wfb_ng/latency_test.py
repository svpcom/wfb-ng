#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (C) 2018-2024 Vasily Evseenko <svpcom@p2ptech.org>

#
#   This program is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation; version 3.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License along
#   with this program; if not, write to the Free Software Foundation, Inc.,
#   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#

import sys
import time
import struct
import os
from twisted.python import log
from twisted.internet import reactor, defer, task
from twisted.internet.protocol import DatagramProtocol
from twisted.trial import unittest
from .common import df_sleep, abort_on_crash, exit_status


class PacketSource(DatagramProtocol):
    noisy = False
    def __init__(self, addr, size, count, rate, key):
        self.df = defer.Deferred()
        self.addr = addr
        self.size = size
        self.count = count
        self.rate = rate
        self.key = key
        self.tx_slowdown = 0.0

    def startProtocol(self):
        self.df.callback(None)

    def start(self):
        msg = bytearray(b'\0' * self.size)
        i = [0, 0] # sent packets, tx cycles
        ts = reactor.seconds()

        def _sendmsg(c):
            struct.pack_into('!HIdd', msg, 0, self.size, i[0], reactor.seconds(), self.key)
            self.transport.write(msg, self.addr)
            i[0] += 1
            i[1] += c

            if i[0] >= self.count:
                # Update real rate
                self.rate = i[0] / (reactor.seconds() - ts)
                self.tx_slowdown = (i[1] - i[0]) / i[1]
                lc.stop()

        lc = task.LoopingCall.withCount(_sendmsg)
        return lc.start(1.0 / self.rate, now=False)

class PacketSink(DatagramProtocol):
    noisy = False
    def __init__(self, key):
        self.df = defer.Deferred()
        self.count = 0
        self.lmin = -1
        self.lmax = -1
        self.lavg = 0
        self.key = key
        self.id_set = set()
        self.last_id = 0

    def startProtocol(self):
        self.df.callback(None)

    def datagramReceived(self, data, addr):
        size, i, ts, key = struct.unpack_from('!HIdd', data)

        if size != len(data):
            log.msg('bad size %d != %d' % (len(data), size), isError=1)
            return

        if self.key != key:
            log.msg('bad session %d != %d #%d, already got %d packets' % (key, self.key, i, self.count))
            return

        latency = reactor.seconds() - ts
        if latency < 0:
            log.msg('bad latency %f' % (latency,))
            return

        if i < self.last_id:
            log.msg('Out of order #%d (prev #%d)' % (i, self.last_id))
        else:
            self.last_id = i

        self.id_set.add(i)
        self.lmin = latency if self.lmin < 0 else min(latency, self.lmin)
        self.lmax = latency if self.lmax < 0 else max(latency, self.lmax)
        self.lavg += latency
        self.count += 1


@defer.inlineCallbacks
def run_test(port_in, port_out, size, count, rate):
    key = int.from_bytes(os.urandom(2), 'big')
    log.msg('Session: %d' % (key,))
    p1 = PacketSource(('127.0.0.1', port_in), size, count, rate, key)
    p2 = PacketSink(key)

    ep1 = reactor.listenUDP(0, p1)
    ep2 = reactor.listenUDP(port_out, p2)

    yield p1.df
    yield p2.df
    yield p1.start()
    yield df_sleep(2)

    sent = count
    lost = count - p2.count
    dup = p2.count - len(p2.id_set)

    bitrate = p1.rate * size * 8 / 1e6

    log.msg('Sent %d, Lost %d, Dup: %d, Packet rate: %d/%d pkt/s, Bitrate: %.2f MBit/s, TX slowdown: %.2f%% Lmin %.2f ms, Lmax %.2f ms, Lavg %.2f ms' % \
            (sent, lost, dup, p1.rate, rate, bitrate, 100.0 * p1.tx_slowdown, 1000.0 * p2.lmin, 1000.0 * p2.lmax, 1000.0 * p2.lavg / p2.count if p2.count else -1))

    if p2.count == 0:
        raise RuntimeError('ALL PACKETS LOST. Check MTU settings')

    yield ep1.stopListening()
    yield ep2.stopListening()

    defer.returnValue((lost, p2.lavg / p2.count if p2.count else -1, bitrate, p1.tx_slowdown))


@defer.inlineCallbacks
def eval_max_rate(port_in, port_out, size, max_rate):
    min_rate = 1
    while 1:
        dr = int((max_rate - min_rate) / 2)
        if dr <= 0:
            break
        rate = min_rate + dr
        count = 3 * rate # run each test for 3s
        lost, lavg, bitrate, slowdown = yield run_test(port_in, port_out, size, count, rate)
        if lost >= max(count * 0.01, 10) or lavg > 0.005: # or slowdown > 0:
            # rate too big
            max_rate = rate
        else:
            # rate too low
            min_rate = rate

    log.msg('Max bitrate is %.2f MBit/s' % (bitrate,))


def main():
    log.startLogging(sys.stdout)
    port_in, port_out, size, max_packet_rate = sys.argv[1:]
    reactor.callWhenRunning(lambda: defer.maybeDeferred(eval_max_rate, int(port_in), int(port_out), int(size), int(max_packet_rate))\
                            .addCallbacks(lambda _: reactor.stop(), abort_on_crash))
    reactor.run()

    rc = exit_status()
    log.msg('Exiting with code %d' % rc)
    sys.exit(rc)


if __name__ == '__main__':
    main()

