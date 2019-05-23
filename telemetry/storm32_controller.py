#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import absolute_import
from __future__ import unicode_literals
from __future__ import print_function
from __future__ import division

from future import standard_library
standard_library.install_aliases()

from builtins import *

import sys
import time
import os
import struct
import random
from math import fabs

from twisted.python import log
from twisted.internet import reactor, defer, utils
from twisted.internet.protocol import ReconnectingClientFactory
from twisted.protocols.basic import LineReceiver
from twisted.internet.error import ReactorNotRunning

from telemetry.common import abort_on_crash, exit_status
from telemetry.proxy import UDPProxyProtocol

from . import mavlink
from .mavlink_protocol import MAVLinkSerialProtocol
from telemetry.conf import settings


class ST32Message(mavlink.MAVLink_command_long_message):
    fieldnames = ['target_system', 'target_component', 'roll', 'pitch', 'yaw']

    def __init__(self, target_system, target_component, pitch, roll, yaw):
        """ Pitch, roll, yaw in degrees """
        mavlink.MAVLink_message.__init__(self, ST32Message.id, ST32Message.name)
        self._fieldnames = ST32Message.fieldnames
        self.target_system = target_system
        self.target_component = target_component
        self.roll = roll
        self.pitch = pitch
        self.yaw = yaw

    def pack(self, mav, force_mavlink1=False):
        hdr = b'\xfa\x0e\x11' + struct.pack('<fffBB', self.pitch, self.roll, self.yaw, 7, 0)
        msg = [ hdr, b'\0' * ( 28 - len(hdr)), struct.pack('<HBBB', 1235, self.target_system, self.target_component, 0)]
        return mavlink.MAVLink_message.pack(self, mav, self.crc_extra, b''.join(msg), force_mavlink1=True)


class ST32Protocol(MAVLinkSerialProtocol):
    def messageReceived(self, message):
        if message.id != mavlink.MAVLINK_MSG_ID_RC_CHANNELS:
            return

        pitch = (message.chan6_raw - 1500.0) / 500.0 * 90.0
        yaw = (message.chan7_raw - 1500.0) / 500.0 * 90.0
        pitch = max(min(pitch, 90.0), -90.0)
        yaw = max(min(yaw, 90.0), -90.0)
        is_fpv = message.chan8_raw < 1500

        if is_fpv:
            pitch = 0.0
            yaw = 0.0

        # Ignore changes less than one degree
        if self.pitch is None or fabs(pitch - self.pitch) > 1:
            self.pitch = pitch

        if self.yaw is None or fabs(yaw - self.yaw) > 1:
            self.yaw = yaw

        self.mav.send(ST32Message(1, 154, self.pitch, 0, self.yaw))

    def connectionMade(self):
        self.pitch = None
        self.yaw = None
        print('connection made')


class MAVLinkClientFactory(ReconnectingClientFactory):
    maxDelay = 1
    sysid = 1
    compid = mavlink.MAV_COMP_ID_PERIPHERAL

    def buildProtocol(self, addr):
        p = ST32Protocol(self.sysid, self.compid)
        p.factory = self
        return p


def main():
    log.startLogging(sys.stdout)
    reactor.connectTCP('127.0.0.1', 5760, MAVLinkClientFactory())
    reactor.run()

    rc = exit_status()
    log.msg('Exiting with code %d' % rc)
    sys.exit(rc)


if __name__ == '__main__':
    main()
