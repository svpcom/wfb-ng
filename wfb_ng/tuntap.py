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

import os
from . import mavlink
import fcntl
import struct

from collections import deque
from twisted.python import log, failure
from twisted.internet import reactor, defer, abstract, main, task
from twisted.internet.protocol import Protocol, connectionDone
from pyroute2 import IPRoute
from contextlib import closing
from .conf import settings
from .proxy import ProxyProtocol

class TUNTAPTransport(abstract.FileDescriptor):
    TUN = 0x0001
    TAP = 0x0002
    TUNSETIFF = 0x400454ca
    IFF_NO_PI = 0x1000

    def __init__(self, reactor, protocol, name, addr, dev=b'/dev/net/tun', mtu=1400, mode=TUN, default_route=False):
        abstract.FileDescriptor.__init__(self, reactor)
        self.queue = deque()
        self.mtu = mtu - 2
        self.name = name
        self.fd = os.open(dev, os.O_RDWR | os.O_NONBLOCK)

        try:
            # We don't need packet info
            mode |= self.IFF_NO_PI
            fcntl.ioctl(self.fd, self.TUNSETIFF, struct.pack('16sH', name.encode('ascii'), mode))
            with closing(IPRoute()) as ip:
                ifidx = ip.link_lookup(ifname=name)[0]
                _addr, _mask = addr.split('/')
                ip.link('set', index=ifidx, state='up', mtu=self.mtu)
                ip.addr('add', index=ifidx, address=_addr, prefixlen=int(_mask))
                if default_route:
                    ip.route('add', dst='default', oif=ifidx, metric=10)
        except Exception:
            os.close(self.fd)
            raise

        # Connect protocol
        self.protocol = protocol
        self.protocol.makeConnection(self)
        self.connected = 1
        self.startReading()

    def connectionLost(self, reason=connectionDone):
        abstract.FileDescriptor.connectionLost(self, reason)
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None
        return self.protocol.connectionLost(reason)

    def loseConnection(self, _connDone=failure.Failure(main.CONNECTION_DONE)):
        self.stopReading()
        return self.connectionLost(_connDone)

    def fileno(self):
        return self.fd

    def doRead(self):
        self.protocol.dataReceived(os.read(self.fd, self.mtu))

    def doWrite(self):
        while self.queue:
            packet = self.queue[0]
            if os.write(self.fd, packet) <= 0:
                return
            self.queue.popleft()

        # queue is empty
        self.stopWriting()

        # If I've got a producer who is supposed to supply me with data,
        if self.producer is not None and ((not self.streamingProducer)
                                          or self.producerPaused):
            # tell them to supply some more.
            self.producerPaused = False
            self.producer.resumeProducing()
        elif self.disconnecting:
            # But if I was previously asked to let the connection die, do
            # so.
            return self._postLoseConnection()
        elif self._writeDisconnecting:
            # I was previously asked to half-close the connection.  We
            # set _writeDisconnected before calling handler, in case the
            # handler calls loseConnection(), which will want to check for
            # this attribute.
            self._writeDisconnected = True
            return self._closeWriteConnection()

    def _isSendBufferFull(self):
        return len(self.queue) > 1000

    def write(self, data):
        if not isinstance(data, (bytes, type(None))): # no, really, I mean it
            raise TypeError("Only binary strings are supported")

        if not self.connected or self._writeDisconnected:
            return

        if data:
            self.queue.append(data)
            self._maybePauseProducer()
            self.startWriting()


class TUNTAPProtocol(Protocol, ProxyProtocol):
    noisy = False
    keepalive_interval = 0.9

    def __init__(self, mtu, agg_timeout=None):
        self.all_peers = []
        ProxyProtocol.__init__(self,
                               agg_max_size=mtu,
                               agg_timeout=agg_timeout)

        # Sent keepalive packets
        self.lc = task.LoopingCall(self.send_keepalive)
        self.lc.start(self.keepalive_interval, now=False)

    def _send_to_all_peers(self, data):
        for peer in self.all_peers:
            self.peer.write(data)

    def _cleanup(self):
        self.lc.stop()
        return ProxyProtocol._cleanup(self)

    # call from peer only!
    def write(self, msg):
        # Remove keepalive messages
        if self.transport is None or not msg:
            return

        # Unpack packets from batch
        i = 0
        while i < len(msg):
            if len(msg) - i < 2:
                log.msg('Corrupted tunneled packet header: %r' % (msg[i:],))
                break

            pkt_size = struct.unpack('!H', msg[i : i + 2])[0]
            i += 2

            if len(msg) - i < pkt_size:
                log.msg('Truncated tunneled packet body: %r' % (msg[i:],))
                break

            self.transport.write(msg[i : i + pkt_size])
            i += pkt_size

    def send_keepalive(self):
        # Send keepalive message via all antennas.
        # This allow to use multiple directed antennas on the both ends
        # and/or use different frequency channels on different cards.
        self._send_to_all_peers(b'')

    def dataReceived(self, data):
        self.lc.reset()  # reset keepalive timer
        return self.messageReceived(struct.pack('!H', len(data)) + data)
