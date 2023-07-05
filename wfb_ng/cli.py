#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (C) 2018-2022 Vasily Evseenko <svpcom@p2ptech.org>

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
import curses
import curses.textpad
import json
import tempfile

from twisted.python import log
from twisted.internet import reactor, defer
from twisted.internet.protocol import ReconnectingClientFactory
from twisted.protocols.basic import LineReceiver
from .server import parse_services
from .common import abort_on_crash, exit_status
from .conf import settings


class AntennaStat(LineReceiver):
    delimiter = b'\n'

    def lineReceived(self, line):
        attrs = json.loads(line)
        p = attrs['packets']
        rssi_d = attrs['rssi']
        tx_ant = attrs.get('tx_ant')
        rx_id = attrs['id']

        window = self.factory.windows.get(rx_id)
        if window is None:
            return

        window.erase()
        window.addstr(0, 0, '[RX] pkt/s pkt')

        msg_l = (('recv  %4d %d' % tuple(p['all']),     0),
                 ('fec_r %4d %d' % tuple(p['fec_rec']), curses.A_REVERSE if p['fec_rec'][0] else 0),
                 ('lost  %4d %d' % tuple(p['lost']),    curses.A_REVERSE if p['lost'][0] else 0),
                 ('d_err %4d %d' % tuple(p['dec_err']), curses.A_REVERSE if p['dec_err'][0] else 0),
                 ('bad   %4d %d' % tuple(p['bad']),     curses.A_REVERSE if p['bad'][0] else 0))

        ymax = window.getmaxyx()[0]
        for y, (msg, attr) in enumerate(msg_l, 1):
            if y < ymax:
                window.addstr(y, 0, msg, attr)

        if rssi_d:
            window.addstr(0, 25, '[ANT] pkt/s        RSSI')
            for y, (k, v) in enumerate(sorted(rssi_d.items()), 1):
                pkt_s, rssi_min, rssi_avg, rssi_max = v
                if y < ymax:
                    active_tx = '*' if (int(k, 16) >> 8) == tx_ant else ' '
                    window.addstr(y, 24, '%s%04x:  %4d  %3d < %3d < %3d' % (active_tx, int(k, 16), pkt_s, rssi_min, rssi_avg, rssi_max))
        else:
            window.addstr(0, 25, '[Link lost]', curses.A_REVERSE)

        window.refresh()



class AntennaStatClientFactory(ReconnectingClientFactory):
    noisy = False
    maxDelay  = 1.0

    def __init__(self, windows):
        self.windows = windows

    def startedConnecting(self, connector):
        log.msg('Connecting to %s:%d ...' % (connector.host, connector.port))

        for window in self.windows.values():
            window.erase()
            window.addstr(0, 0, 'Connecting...')
            window.refresh()

    def buildProtocol(self, addr):
        log.msg('Connected to %s' % (addr,))

        for window in self.windows.values():
            window.erase()
            window.addstr(0, 0, 'Waiting for data...')
            window.refresh()

        self.resetDelay()
        p = AntennaStat()
        p.factory = self
        return p

    def clientConnectionLost(self, connector, reason):
        log.msg('Connection lost: %s' % (reason.value,))

        for window in self.windows.values():
            window.erase()
            window.addstr(0, 0, 'Connection lost: %s' % (reason.value,))
            window.refresh()

        ReconnectingClientFactory.clientConnectionLost(self, connector, reason)

    def clientConnectionFailed(self, connector, reason):
        log.msg('Connection failed: %s' % (reason.value,))

        for window in self.windows.values():
            window.erase()
            window.addstr(0, 0, 'Connection failed: %s' % (reason.value,))
            window.refresh()

        ReconnectingClientFactory.clientConnectionFailed(self, connector, reason)


def init(stdscr, profile):
    service_list = list((s_name, cfg.show_stats) for s_name, _, cfg in  parse_services(profile))

    height, width = stdscr.getmaxyx()
    height -= 1

    if not service_list:
        curses.textpad.rectangle(stdscr, 0, 0, height - 1, width - 1)
        stdscr.addstr(0, 3, '[%s not configured]' % (profile,), curses.A_REVERSE)
        stdscr.refresh()
        return

    wh_list = [height // len(service_list)] * (len(service_list) - 1)
    wh_list.append(height - sum(wh_list))
    hoff = 0

    windows = {}
    for (name, show_stats), wh in zip(service_list, wh_list):
        window = stdscr.subpad(wh - 2, width - 2, hoff + 1, 1)
        window.idlok(1)
        window.scrollok(1)

        curses.textpad.rectangle(stdscr, hoff, 0, hoff + wh - 1, width - 1)
        stdscr.addstr(hoff, 3, '[%s %s]' % (profile, name))

        if show_stats:
            windows['%s rx' % name] = window
        else:
            window.addstr(0, 0, '[statistics disabled]', curses.A_REVERSE)
            window.refresh()

        hoff += wh

    stats_port = getattr(settings, profile).stats_port
    reactor.connectTCP('127.0.0.1', stats_port, AntennaStatClientFactory(windows))
    stdscr.refresh()

def main():
    stderr = sys.stderr

    if len(sys.argv) != 2:
        print("Usage: %s <profile>" % (sys.argv[0],), file=stderr)
        sys.exit(1)

    fd = tempfile.TemporaryFile(mode='w+', encoding='utf-8')
    log.startLogging(fd)

    stdscr = curses.initscr()
    try:
        curses.noecho()
        curses.cbreak()
        curses.curs_set(0)
        stdscr.keypad(True)
        reactor.callWhenRunning(lambda: defer.maybeDeferred(init, stdscr, sys.argv[1])\
                            .addErrback(abort_on_crash))
        reactor.run()
    finally:
        curses.endwin()

    rc = exit_status()

    if rc:
        log.msg('Exiting with code %d' % rc)
        fd.seek(0)
        for l in fd:
            stderr.write(l)

    sys.exit(rc)


if __name__ == '__main__':
    main()
