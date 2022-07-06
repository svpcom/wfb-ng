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
from .common import abort_on_crash, exit_status
from .conf import settings


class AntennaStat(LineReceiver):
    delimiter = b'\n'

    def lineReceived(self, line):
        attrs = json.loads(line)
        p = attrs['packets']
        rssi_d = attrs['rssi']
        tx_ant = attrs['tx_ant'] if self.factory.has_tx else None

        self.factory.window.erase()
        self.factory.window.addstr(0, 0, '[RX] pkt/s pkt')

        msg_l = (('recv  %4d %d' % tuple(p['all']),     0),
                 ('fec_r %4d %d' % tuple(p['fec_rec']), curses.A_REVERSE if p['fec_rec'][0] else 0),
                 ('lost  %4d %d' % tuple(p['lost']),    curses.A_REVERSE if p['lost'][0] else 0),
                 ('d_err %4d %d' % tuple(p['dec_err']), curses.A_REVERSE if p['dec_err'][0] else 0),
                 ('bad   %4d %d' % tuple(p['bad']),     curses.A_REVERSE if p['bad'][0] else 0))

        ymax = self.factory.window.getmaxyx()[0]
        for y, (msg, attr) in enumerate(msg_l, 1):
            if y < ymax:
                self.factory.window.addstr(y, 0, msg, attr)

        if rssi_d:
            self.factory.window.addstr(0, 25, '[ANT] pkt/s        RSSI')
            for y, (k, v) in enumerate(sorted(rssi_d.items()), 1):
                pkt_s, rssi_min, rssi_avg, rssi_max = v
                if y < ymax:
                    active_tx = '*' if (int(k, 16) >> 8) == tx_ant else ' '
                    self.factory.window.addstr(y, 24, '%s%04x:  %4d  %3d < %3d < %3d' % (active_tx, int(k, 16), pkt_s, rssi_min, rssi_avg, rssi_max))
        else:
            self.factory.window.addstr(0, 25, '[Link lost]', curses.A_REVERSE)

        self.factory.window.refresh()



class AntennaStatClientFactory(ReconnectingClientFactory):
    noisy = False
    maxDelay  = 1.0

    def __init__(self, window, has_tx):
        self.window = window
        self.has_tx = has_tx

    def startedConnecting(self, connector):
        log.msg('Connecting to %s:%d ...' % (connector.host, connector.port))
        self.window.erase()
        self.window.addstr(0, 0, 'Connecting...')
        self.window.refresh()

    def buildProtocol(self, addr):
        log.msg('Connected to %s' % (addr,))
        self.window.erase()
        self.window.addstr(0, 0, 'Waiting for data...')
        self.window.refresh()
        self.resetDelay()
        p = AntennaStat()
        p.factory = self
        return p

    def clientConnectionLost(self, connector, reason):
        log.msg('Connection lost: %s' % (reason.value,))
        self.window.erase()
        self.window.addstr(0, 0, 'Connection lost: %s' % (reason.value,))
        self.window.refresh()
        ReconnectingClientFactory.clientConnectionLost(self, connector, reason)

    def clientConnectionFailed(self, connector, reason):
        log.msg('Connection failed: %s' % (reason.value,))
        self.window.erase()
        self.window.addstr(0, 0, 'Connection failed: %s' % (reason.value,))
        self.window.refresh()
        ReconnectingClientFactory.clientConnectionFailed(self, connector, reason)


def init(stdscr, profile):
    cfg_video = getattr(settings, '%s_video' % (profile,))
    cfg_telem = getattr(settings, '%s_mavlink' % (profile,))
    cfg_tunnel = getattr(settings, '%s_tunnel' % (profile,))

    height, width = stdscr.getmaxyx()
    height -= 1
    w1h = height // 3
    w1w = width
    w2h = height // 3
    w2w = width
    w3h = height - w1h - w2h
    w3w = width
    status_win1 = stdscr.subpad(w1h - 2, w1w - 2, 1, 1)
    status_win2 = stdscr.subpad(w2h - 2, w2w - 2, w1h + 1, 1)
    status_win3 = stdscr.subpad(w3h - 2, w3w - 2, w1h + w2h + 1, 1)

    curses.textpad.rectangle(stdscr, 0, 0, w1h - 1, w1w - 1)
    curses.textpad.rectangle(stdscr, w1h, 0, w1h + w2h - 1, w2w - 1)
    curses.textpad.rectangle(stdscr, w1h + w2h, 0, w1h + w2h + w3h - 1, w3w - 1)
    stdscr.addstr(0, 3, '[video]')
    stdscr.addstr(w1h, 3, '[telem]')
    stdscr.addstr(w1h + w2h, 3, '[tunnel]')
    stdscr.refresh()

    for i in (status_win1, status_win2, status_win3):
        i.idlok(1)
        i.scrollok(1)

    if cfg_video.stats_port is not None:
        reactor.connectTCP('127.0.0.1', cfg_video.stats_port, AntennaStatClientFactory(status_win1, cfg_video.peer.startswith('listen:')))
    else:
        status_win1.addstr(0, 0, '[statistics disabled]', curses.A_REVERSE)
        status_win1.refresh()

    if cfg_telem.stats_port is not None:
        reactor.connectTCP('127.0.0.1', cfg_telem.stats_port, AntennaStatClientFactory(status_win2, True))
    else:
        status_win2.addstr(0, 0, '[statistics disabled]', curses.A_REVERSE)
        status_win2.refresh()

    if cfg_tunnel.stats_port is not None:
        reactor.connectTCP('127.0.0.1', cfg_tunnel.stats_port, AntennaStatClientFactory(status_win3, True))
    else:
        status_win3.addstr(0, 0, '[statistics disabled]', curses.A_REVERSE)
        status_win3.refresh()


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
