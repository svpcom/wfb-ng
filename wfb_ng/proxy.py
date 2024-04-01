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

import struct
import os

from contextlib import closing
from twisted.python import log
from twisted.internet import reactor, defer
from twisted.internet.protocol import DatagramProtocol, Protocol

from . import mavlink, mavlink_protocol
from .conf import settings


class ProxyProtocol:
    def __init__(self, agg_max_size, agg_timeout):
        self.peer = None
        self.agg_max_size = agg_max_size
        self.agg_timeout = agg_timeout
        self.agg_queue = []
        self.agg_queue_size = 0
        self.agg_queue_timer = None

    def _cleanup(self):
        if(self.agg_queue_timer):
            self.agg_queue_timer.cancel()

    def flush_queue(self):
        if self.agg_queue_size > 0:
            if self.agg_queue_timer is not None \
               and not self.agg_queue_timer.called:
                self.agg_queue_timer.cancel()
            self.agg_queue_timer = None
            self._send_to_peer(b''.join(self.agg_queue))
            self.agg_queue = []
            self.agg_queue_size = 0

    # call from peer and from mavlink rssi injector only!
    def write(self, msg):
        raise NotImplementedError()

    def _send_to_peer(self, data):
        if self.peer is not None:
            self.peer.write(data)

    def messageReceived(self, data):
        # send message to local transport
        if self.agg_max_size is None or self.agg_timeout is None:
            return self._send_to_peer(data)

        if len(data) > self.agg_max_size:
            log.msg('Message too big: %d > %d' % (len(data), self.agg_max_size), isError=1)
            return

        if self.agg_queue_size + len(data) > self.agg_max_size:
            # message doesn't fit into agg queue
            if self.agg_queue_timer is not None:
                self.agg_queue_timer.cancel()
                self.agg_queue_timer = None

            self._send_to_peer(b''.join(self.agg_queue))
            self.agg_queue = []
            self.agg_queue_size = 0

        self.agg_queue.append(data)
        self.agg_queue_size += len(data)

        if self.agg_timeout and self.agg_queue_timer is None:
            self.agg_queue_timer = reactor.callLater(self.agg_timeout, self.flush_queue)

    # inject radio rssi info
    def send_rssi(self, rx_id, rssi, rx_errors, rx_fec, flags):
        pass


class UDPProxyProtocol(DatagramProtocol, ProxyProtocol):
    noisy = False

    def __init__(self, addr=None):
        ProxyProtocol.__init__(self, agg_max_size=None, agg_timeout=None)
        self.reply_addr = addr
        self.fixed_addr = bool(addr)

    def datagramReceived(self, data, addr):
        if settings.common.debug:
            log.msg('Got a message from %s' % (addr,))

        if not self.fixed_addr:
            self.reply_addr = addr

        return self.messageReceived(data)

    def write(self, msg):
        if self.transport is None or self.reply_addr is None:
            return

        self.transport.write(msg, self.reply_addr)
        return


class MavlinkProxyProtocol(ProxyProtocol):
    def __init__(self, agg_max_size, agg_timeout,
                 inject_rssi,
                 mavlink_sys_id, mavlink_comp_id):

        ProxyProtocol.__init__(self, agg_max_size, agg_timeout)
        self.radio_stats_d = {}
        if inject_rssi:
            self.radio_mav = mavlink.MAVLink(self, srcSystem=mavlink_sys_id, srcComponent=mavlink_comp_id) # WFB
        else:
            self.radio_mav = None

    def send_rssi(self, rx_id, rssi, rx_errors, rx_fec, flags):
        # Send flags as remnoise, because txbuf value is used by PX4 to throttle bandwidth
        # use self.write to send mavlink message
        if self.radio_mav is not None:
            self.radio_stats_d[rx_id] = (rssi, rx_errors, rx_fec, flags)

            rssi = 0
            rx_errors = 0
            rx_fec = 0
            flags = 0

            for _rssi, _rx_errors, _rx_fec, _flags in self.radio_stats_d.values():
                rssi += _rssi
                rx_errors += _rx_errors
                rx_fec += _rx_fec
                flags |= _flags

            rssi //= len(self.radio_stats_d)
            self.radio_mav.radio_status_send(rssi, rssi, 100, 0, flags, rx_errors, rx_fec)


class MavlinkUDPProxyProtocol(DatagramProtocol, MavlinkProxyProtocol):
    noisy = False

    def __init__(self, addr,
                 agg_max_size, agg_timeout,
                 inject_rssi, mirror,
                 mavlink_sys_id, mavlink_comp_id,
                 rx_hooks=None, tx_hooks=None):

        MavlinkProxyProtocol.__init__(self, agg_max_size, agg_timeout,
                                      inject_rssi=inject_rssi,
                                      mavlink_sys_id=mavlink_sys_id, mavlink_comp_id=mavlink_comp_id)
        self.reply_addr = addr
        self.fixed_addr = bool(addr)
        self.mirror = mirror
        self.rx_hooks = list(rx_hooks) if rx_hooks is not None else []
        self.tx_hooks = list(tx_hooks) if tx_hooks is not None else []

    def datagramReceived(self, data, addr):
        if settings.common.debug:
            log.msg('Got a message from %s' % (addr,))

        if not self.fixed_addr:
            self.reply_addr = addr

        for hook in self.rx_hooks:
            hook(data)

        return self.messageReceived(data)

    def write(self, msg):
        for hook in self.tx_hooks:
            hook(msg)

        if self.transport is None or self.reply_addr is None:
            return

        # Mirror packets as is
        if self.mirror:
            self.transport.write(msg, self.mirror)

        # Send non-aggregated packets directly
        if self.agg_max_size is None or self.agg_timeout is None:
            self.transport.write(msg, self.reply_addr)
            return

        # Split batch of mavlink packets due to issues with mavlink-router

        with closing(mavlink_protocol.mavlink_parser_gen()) as mavlink_fsm:
            mavlink_fsm.send(None)

            for m in mavlink_fsm.send(msg):
                self.transport.write(m, self.reply_addr)



class MavlinkSerialProxyProtocol(Protocol, MavlinkProxyProtocol):
    noisy = False

    def __init__(self, agg_max_size, agg_timeout,
                 inject_rssi,
                 mavlink_sys_id, mavlink_comp_id,
                 rx_hooks = None, tx_hooks = None):

        MavlinkProxyProtocol.__init__(self, agg_max_size, agg_timeout,
                                      inject_rssi=inject_rssi,
                                      mavlink_sys_id=mavlink_sys_id, mavlink_comp_id=mavlink_comp_id)

        self.mavlink_fsm = mavlink_protocol.mavlink_parser_gen()
        self.mavlink_fsm.send(None)
        self.rx_hooks = rx_hooks or []
        self.tx_hooks = tx_hooks or []

    def write(self, msg):
        for hook in self.tx_hooks:
            hook(msg)

        if self.transport is not None:
            self.transport.write(msg)

    def dataReceived(self, data):
        for m in self.mavlink_fsm.send(data):
            for hook in self.rx_hooks:
                hook(m)

            self.messageReceived(m)
