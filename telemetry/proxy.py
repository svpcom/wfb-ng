#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (C) 2018 Vasily Evseenko <svpcom@p2ptech.org>

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

import mavlink
from twisted.python import log
from twisted.internet import reactor, defer
from twisted.internet.protocol import DatagramProtocol
from telemetry.conf import settings


class UDPProxyProtocol(DatagramProtocol):
    noisy = False

    def __init__(self, addr=None, agg_max_size=None, agg_timeout=None):
        # use self.write to send mavlink message
        self.mav = mavlink.MAVLink(self, srcSystem=1, srcComponent=242) # WFB
        self.peer = None
        self.reply_addr = addr
        self.agg_max_size = agg_max_size
        self.agg_timeout = agg_timeout
        self.agg_queue = []
        self.agg_queue_size = 0
        self.agg_queue_timer = None

    def _cleanup(self):
        if(self.agg_queue_timer):
            self.agg_queue_timer.cancel()

    def write(self, msg):
        # send message to local transport
        if self.agg_max_size is None:
            return self._write(msg)

        if len(msg) > self.agg_max_size:
            log.msg('Message too big: %d > %d' % (len(msg), self.agg_max_size), isError=1)
            return

        if self.agg_queue_size + len(msg) > self.agg_max_size:
            # message doesn't fit into agg queue
            if self.agg_queue_timer is not None:
                self.agg_queue_timer.cancel()
                self.agg_queue_timer = None

            self._write(''.join(self.agg_queue))
            self.agg_queue = []
            self.agg_queue_size = 0

        self.agg_queue.append(msg)
        self.agg_queue_size += len(msg)

        if self.agg_timeout and self.agg_queue_timer is None:
            self.agg_queue_timer = reactor.callLater(self.agg_timeout, self.flush_queue)

    def flush_queue(self):
        if self.agg_queue_size > 0:
            if self.agg_queue_timer is not None:
                if not self.agg_queue_timer.called:
                    self.agg_queue_timer.cancel()
            self.agg_queue_timer = None
            self._write(''.join(self.agg_queue))
            self.agg_queue = []
            self.agg_queue_size = 0

    def _write(self, msg):
        if self.transport is not None and self.reply_addr is not None:
            self.transport.write(msg, self.reply_addr)

    def datagramReceived(self, data, addr):
        if settings.common.debug:
            log.msg('Got a message from %s' % (addr,))

        self.reply_addr = addr

        if self.peer is not None:
            self.peer.write(data)

    def send_rssi(self, rssi, rx_errors, rx_fec, flags):
        # Send flags as txbuf
        self.mav.radio_status_send(rssi, rssi, flags, 0, 0, rx_errors, rx_fec)

