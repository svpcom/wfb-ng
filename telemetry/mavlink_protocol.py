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

from . import mavlink
from twisted.python import log
from twisted.internet import reactor, defer
from twisted.internet.protocol import Protocol, DatagramProtocol


class MAVLinkProtocol(Protocol):
    def __init__(self, src_system, src_component):
        self.mav = mavlink.MAVLink(self, srcSystem=src_system, srcComponent=src_component)

    def write(self, msg):
        raise NotImplementedError

    def messageReceived(self, message):
        raise NotImplementedError

    def dataReceived(self, data):
        try:
            m_list = self.mav.parse_buffer(data)
        except mavlink.MAVError as e:
            log.msg('Mavlink error: %s' % (e,))
            return

        if m_list is not None:
            for m in m_list:
                self.messageReceived(m)


class MAVLinkUDPProtocol(MAVLinkProtocol, DatagramProtocol):
    def __init__(self, src_system, src_component, peer=None):
        MAVLinkProtocol.__init__(self, src_system, src_component)
        self.reply_addr = peer

    def write(self, msg):
        if self.transport is not None and self.reply_addr is not None:
            self.transport.write(msg, self.reply_addr)

    def datagramReceived(self, data, addr):
        self.reply_addr = addr
        self.dataReceived(data)


class MAVLinkSerialProtocol(MAVLinkProtocol):
    def write(self, msg):
        if self.transport is not None:
            self.transport.write(msg)
