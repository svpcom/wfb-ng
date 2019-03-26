#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import division
from __future__ import unicode_literals
from __future__ import print_function
from __future__ import absolute_import

from future import standard_library
standard_library.install_aliases()
from builtins import *
import sys
import time
import struct
from twisted.python import log
from twisted.internet import reactor, defer, task
from twisted.internet.protocol import DatagramProtocol
from twisted.trial import unittest
from telemetry.common import df_sleep, abort_on_crash, exit_status


class PacketSource(DatagramProtocol):
    noisy = False
    def __init__(self, addr, size, count, rate):
        self.df = defer.Deferred()
        self.addr = addr
        self.size = size
        self.count = count
        self.rate = rate

    def startProtocol(self):
        self.df.callback(None)

    def start(self):
        msg = bytearray('\0' * self.size)
        i = [0]

        def _sendmsg(c):
            if c > 1:
                log.msg('Packet source freeze for %d intervals at iter %d' % (c, i[0]))

            struct.pack_into('!HId', msg, 0, self.size, i[0], reactor.seconds())
            self.transport.write(msg, self.addr)
            i[0] += 1

            if i[0] >= self.count:
                lc.stop()

        lc = task.LoopingCall.withCount(_sendmsg)
        return lc.start(1.0 / self.rate, now=False)

class PacketSink(DatagramProtocol):
    noisy = False
    def __init__(self):
        self.df = defer.Deferred()
        self.count = 0
        self.lmin = -1
        self.lmax = -1
        self.lavg = 0

    def startProtocol(self):
        self.df.callback(None)

    def datagramReceived(self, data, addr):
        size, i, ts = struct.unpack_from('!HId', data)

        if size != len(data):
            log.msg('bad size %d != %d' % (len(data), size), isError=1)

        latency = reactor.seconds() - ts
        if latency < 0:
            log.msg('bad latency %f' % (latency,))
            return

        self.lmin = latency if self.lmin < 0 else min(latency, self.lmin)
        self.lmax = latency if self.lmax < 0 else max(latency, self.lmax)
        self.lavg += latency
        self.count += 1


@defer.inlineCallbacks
def run_test(port_in, port_out, size, count, rate):
    p1 = PacketSource(('127.0.0.1', port_in), size, count, rate)
    p2 = PacketSink()

    ep1 = reactor.listenUDP(0, p1)
    ep2 = reactor.listenUDP(port_out, p2)

    yield p1.df
    yield p2.df
    yield p1.start()
    yield df_sleep(1)

    sent = count
    lost = count - p2.count
    bitrate = rate * size * 8 / 1e6

    log.msg('Sent %d, Lost %d, Packet rate: %d pkt/s, Bitrate: %.2f MBit/s, Lmin %f, Lmax %f, Lavg %f' % \
            (sent, lost, rate, bitrate, p2.lmin, p2.lmax, p2.lavg / p2.count if p2.count else -1))

    yield ep1.stopListening()
    yield ep2.stopListening()

    defer.returnValue((lost, p2.lavg / p2.count if p2.count else -1, bitrate))


@defer.inlineCallbacks
def eval_max_rate(port_in, port_out, size, max_rate):
    min_rate = 1
    while 1:
        dr = int((max_rate - min_rate) / 2)
        if dr <= 0:
            break
        rate = min_rate + dr
        count = 3 * rate # run each test for 3s
        lost, lavg, bitrate = yield run_test(port_in, port_out, size, count, rate)
        if lost >= max(count * 0.01, 1) or lavg > 0.01:
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

