#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (C) 2018, 2019 Vasily Evseenko <svpcom@p2ptech.org>

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

from __future__ import absolute_import
from __future__ import unicode_literals
from __future__ import print_function
from __future__ import division

from future import standard_library
standard_library.install_aliases()

from builtins import *

import os
from . import mavlink
import fcntl
import struct

from collections import deque
from twisted.python import log, failure
from twisted.internet import reactor, defer, abstract, main, task
from twisted.internet.protocol import Protocol, connectionDone
from telemetry.conf import settings
from pyroute2 import IPRoute
from contextlib import closing

class TUNTAPTransport(abstract.FileDescriptor):
    TUN = 0x0001
    TAP = 0x0002
    TUNSETIFF = 0x400454ca
    IFF_NO_PI = 0x1000

    def __init__(self, reactor, protocol, name, addr, dev=b'/dev/net/tun', mtu=1400, mode=TUN):
        abstract.FileDescriptor.__init__(self, reactor)
        self.queue = deque()
        self.mtu = mtu
        self.name = name
        self.fd = os.open(dev, os.O_RDWR | os.O_NONBLOCK)

        try:
            # We don't need packet info
            mode |= self.IFF_NO_PI
            fcntl.ioctl(self.fd, self.TUNSETIFF, struct.pack('16sH', bytes(name, 'ascii'), mode))
            with closing(IPRoute()) as ip:
                ifidx = ip.link_lookup(ifname=name)[0]
                _addr, _mask = addr.split('/')
                ip.link('set', index=ifidx, state='up', mtu=self.mtu)
                ip.addr('add', index=ifidx, address=_addr, prefixlen=int(_mask))
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
            result = self._closeWriteConnection()
            return result

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


class TUNTAPProtocol(Protocol):
    noisy = False
    keepalive_interval = 0.9

    def __init__(self):
        self.peer = None
        # Sent keepalive packets
        self.lc = task.LoopingCall(self.send_keepalive)
        self.lc.start(self.keepalive_interval, now=False)

    def _cleanup(self):
        self.lc.stop()

    # call from peer only!
    def write(self, msg):
        # Remove keepalive messages
        if self.transport is not None and msg:
            self.transport.write(msg)

    def send_keepalive(self):
        if self.peer is not None:
            self.peer.write(b'')

    def dataReceived(self, data):
        self.lc.reset()
        if self.peer is not None:
            self.peer.write(data)

    def send_rssi(self, rssi, rx_errors, rx_fec, flags):
        pass

