#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (C) 2018-2021 Vasily Evseenko <svpcom@p2ptech.org>

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

import struct
import os

from twisted.python import log
from twisted.internet import reactor, defer, utils
from twisted.internet.protocol import DatagramProtocol, Protocol

from . import mavlink
from .conf import settings
from .mavlink_protocol import MAVLinkProtocol


class ExecError(Exception):
    pass


def call_and_check_rc(cmd, *args):
    def _check_rc(_args):
        (stdout, stderr, rc) = _args
        if rc != 0:
            err = ExecError('RC %d: %s %s' % (rc, cmd, ' '.join(args)))
            err.stdout = stdout.strip()
            err.stderr = stderr.strip()
            raise err

        log.msg('# %s' % (' '.join((cmd,) + args),))
        if stdout:
            log.msg(stdout)

    def _got_signal(f):
        f.trap(tuple)
        stdout, stderr, signum = f.value
        err = ExecError('Got signal %d: %s %s' % (signum, cmd, ' '.join(args)))
        err.stdout = stdout.strip()
        err.stderr = stderr.strip()
        raise err

    return utils.getProcessOutputAndValue(cmd, args, env=os.environ).addCallbacks(_check_rc, _got_signal)


class ProxyProtocol:
    def __init__(self, agg_max_size=None, agg_timeout=None, inject_rssi=False, arm_proto=None):
        # use self.write to send mavlink message
        if inject_rssi:
            self.radio_mav = mavlink.MAVLink(self, srcSystem=3, srcComponent=242) # WFB
        else:
            self.radio_mav = None

        self.arm_proto = arm_proto
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
        if self.arm_proto:
            self.arm_proto.dataReceived(data)

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


    def send_rssi(self, rssi, rx_errors, rx_fec, flags):
        # Send flags as remnoise, because txbuf value is used by PX4 to throttle bandwidth
        if self.radio_mav is not None:
            self.radio_mav.radio_status_send(rssi, rssi, 100, 0, flags, rx_errors, rx_fec)



class UDPProxyProtocol(DatagramProtocol, ProxyProtocol):
    noisy = False

    def __init__(self, addr=None, agg_max_size=None, agg_timeout=None, inject_rssi=False, mirror=None, arm_proto=None):
        ProxyProtocol.__init__(self, agg_max_size, agg_timeout, inject_rssi, arm_proto=arm_proto)
        self.reply_addr = addr
        self.fixed_addr = bool(addr)
        self.mirror = mirror

    def datagramReceived(self, data, addr):
        if settings.common.debug:
            log.msg('Got a message from %s' % (addr,))

        if not self.fixed_addr:
            self.reply_addr = addr

        return self.messageReceived(data)

    def write(self, msg):
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

        i = 0
        while i < len(msg):
            if len(msg) - i < 8:
                log.msg('Too short mavlink packet: %r' % (msg[i:],))
                break

            version = struct.unpack('B', msg[i : i + 1])[0]

            # mavlink 1
            if version == 0xfe:
                mlen = 8 + struct.unpack('B', msg[i + 1 : i + 2])[0]
                self.transport.write(msg[i: i + mlen], self.reply_addr)
                i += mlen

            # mavlink 2
            elif version == 0xfd:
                mlen, flags = struct.unpack('BB', msg[i + 1 : i + 3])

                if flags & ~0x01:
                    log.msg('Unsupported mavlink flags: 0x%x' % (flags,))
                    self.transport.write(msg[i:], self.reply_addr)
                    break

                mlen += (25 if flags & 0x01 else 12)
                self.transport.write(msg[i : i + mlen], self.reply_addr)
                i += mlen

            else:
                log.msg('Unsupported mavlink version: 0x%x' % (version,))
                self.transport.write(msg[i:], self.reply_addr)
                break



class SerialProxyProtocol(Protocol, ProxyProtocol):
    noisy = False

    def __init__(self, agg_max_size=None, agg_timeout=None, inject_rssi=False, arm_proto=None):
        ProxyProtocol.__init__(self, agg_max_size, agg_timeout, inject_rssi, arm_proto=arm_proto)
        self.mavlink_fsm = self.mavlink_parser()
        self.mavlink_fsm.send(None)

    def mavlink_parser(self):
        buffer = bytearray()
        mlist = []
        skip = 0
        bad = 0

        while True:
            # GC
            if skip > 4096:
                buffer = buffer[skip:]
                skip = 0

            data = yield mlist
            mlist = []

            if not data:
                continue

            buffer.extend(data)

            while len(buffer) - skip >= 8:
                version = buffer[skip]

                # mavlink 1
                if version == 0xfe:
                    mlen = 8 + buffer[skip + 1]

                # mavlink 2
                elif version == 0xfd:
                    mlen, flags = struct.unpack('BB', buffer[skip + 1 : skip + 3])

                    if flags & ~0x01:
                        log.msg('Unsupported mavlink flags: 0x%x' % (flags,))

                    mlen += (25 if flags & 0x01 else 12)
                else:
                    skip += 1
                    bad += 1
                    continue

                if bad:
                    log.msg('skip %d bad bytes before sync' % (bad,))
                    bad = 0

                if len(buffer) - skip < mlen:
                    break

                mlist.append(bytes(buffer[skip: skip + mlen]))
                skip += mlen

    def write(self, msg):
        if self.transport is not None:
            self.transport.write(msg)

    def dataReceived(self, data):
        m_list = self.mavlink_fsm.send(data)

        for m in m_list:
            self.messageReceived(m)


class ARMProtocol(MAVLinkProtocol):
    def __init__(self, call_on_arm, call_on_disarm):
        MAVLinkProtocol.__init__(self, None, None)
        self.call_on_arm = call_on_arm
        self.call_on_disarm = call_on_disarm
        self.armed = None
        self.locked = False

    def messageReceived(self, message):
        if (message._header.msgId, message._header.srcSystem, message._header.srcComponent) != (mavlink.MAVLINK_MSG_ID_HEARTBEAT, 1, 1):
            return

        armed = bool(message.base_mode & mavlink.MAV_MODE_FLAG_SAFETY_ARMED)

        if not self.locked:
            self.locked = True

            def _unlock(x):
                self.locked = False
                return x

            return defer.maybeDeferred(self.change_state, armed).addBoth(_unlock)

    def change_state(self, armed):
        if armed == self.armed:
            return

        self.armed = armed
        cmd = None

        if armed:
            print('State change: ARMED')
            cmd = self.call_on_arm
        else:
            print('State change: DISARMED')
            cmd = self.call_on_disarm

        def on_err(f):
            log.msg('Command exec failed: %s' % (f.value,), isError=1)

            if f.value.stdout:
                log.msg(f.value.stdout, isError=1)

            if f.value.stderr:
                log.msg(f.value.stderr, isError=1)

        if cmd is not None:
            return call_and_check_rc(cmd).addErrback(on_err)

