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

from . import call_and_check_rc, ExecError
from .mavlink import MAV_MODE_FLAG_SAFETY_ARMED, MAVLINK_MSG_ID_HEARTBEAT

from zope.interface import implementer
from twisted.python import log
from twisted.internet import reactor, defer, utils, interfaces
from twisted.internet.protocol import Protocol, DatagramProtocol, Factory


def parse_mavlink_l2_v1(msg):
    plen, seq, sys_id, comp_id, msg_id = struct.unpack('<BBBBB', msg[1:6])
    return ((seq, sys_id, comp_id, msg_id), bytes(msg[6:6 + plen]))


def parse_mavlink_l2_v2(msg):
    plen, iflags, cflags, seq, sys_id, comp_id, msg_id_low, msg_id_high = struct.unpack('<BBBBBBHB', msg[1:10])
    return ((seq, sys_id, comp_id, msg_id_low + (msg_id_high << 16)), bytes(msg[10:10 + plen]))


def mavlink_parser_gen(parse_l2=False):
    buffer = bytearray()
    mlist = []
    skip = 0
    bad = 0
    parse_map = { 0xfe: parse_mavlink_l2_v1,
                  0xfd: parse_mavlink_l2_v2 }

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

            if parse_l2:
                mlist.append(parse_map[version](buffer[skip: skip + mlen]))
            else:
                mlist.append(bytes(buffer[skip: skip + mlen]))

            skip += mlen



class MavlinkARMProtocol(object):
    def __init__(self, call_on_arm, call_on_disarm):
        self.call_on_arm = call_on_arm
        self.call_on_disarm = call_on_disarm
        self.armed = None
        self.locked = False
        self.mavlink_fsm = mavlink_parser_gen(parse_l2=True)
        self.mavlink_fsm.send(None)

    def dataReceived(self, data):
        for l2_headers, m in self.mavlink_fsm.send(data):
            self.messageReceived(l2_headers, m)

    def messageReceived(self, l2_headers, message):
        seq, sys_id, comp_id, msg_id = l2_headers

        if (sys_id, comp_id, msg_id) != (1, 1, MAVLINK_MSG_ID_HEARTBEAT):
            return

        armed = bool(message[6] & MAV_MODE_FLAG_SAFETY_ARMED)

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
            log.msg('State change: ARMED')
            cmd = self.call_on_arm
        else:
            log.msg('State change: DISARMED')
            cmd = self.call_on_disarm

        def on_err(f):
            log.msg('Command exec failed: %s' % (f.value,), isError=1)

            if f.value.stdout:
                log.msg(f.value.stdout, isError=1)

            if f.value.stderr:
                log.msg(f.value.stderr, isError=1)

        if cmd is not None:
            return call_and_check_rc(cmd).addErrback(on_err)


@implementer(interfaces.IPushProducer)
class MavlinkTCPProtocol(Protocol):
    def connectionMade(self):
        log.msg('New connection from %s' % (self.transport.getPeer(),))
        self.mavlink_fsm = mavlink_parser_gen()
        self.mavlink_fsm.send(None)
        self.factory.sessions.append(self)

        # setup push producer
        self.paused = False
        self.transport.registerProducer(self, True)

    def dataReceived(self, data):
        for m in self.mavlink_fsm.send(data):
            self.factory.messageReceived(m)

    def connectionLost(self, reason):
        log.msg('Connection closed %s' % (self.transport.getPeer(),))
        self.transport.unregisterProducer()
        self.factory.sessions.remove(self)
        self.mavlink_fsm.close()
        self.mavlink_fsm = None

    def send(self, data):
        if self.transport is not None and not self.paused:
            self.transport.write(data)

    def pauseProducing(self):
        self.paused = True
        log.msg('Pause mavlink stream to %s' % (self.transport.getPeer(),))

    def resumeProducing(self):
        self.paused = False
        log.msg('Resume mavlink stream to %s' % (self.transport.getPeer(),))

    def stopProducing(self):
        self.paused = True


class MavlinkTCPFactory(Factory):
    noisy = False
    protocol = MavlinkTCPProtocol

    def __init__(self, peer):
        self.sessions = []
        self.peer = peer

    def messageReceived(self, m):
        self.peer.write(m)

    def write(self, data):
        for s in self.sessions:
            try:
                s.send(data)
            except Exception as v:
                log.err(v)
