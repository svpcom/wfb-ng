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

import sys
import curses
import msgpack
import tempfile
import signal
import termios
import struct
import fcntl

from twisted.python import log
from twisted.internet import reactor, defer
from twisted.internet.protocol import ReconnectingClientFactory
from twisted.protocols.basic import Int32StringReceiver
from .server import parse_services
from .common import abort_on_crash, exit_status
from .conf import settings

_orig_stdout = sys.stdout

def set_window_title(s):
    print("\033]2;%s\007" % (s,), file=_orig_stdout)

# Workarond for ncurses bug that show error on output to the last position on the screen

def ignore_curses_err(f, *args, **kwargs):
    try:
        return f(*args, **kwargs)
    except curses.error:
        pass

def addcstr(window, s, attrs=0):
    h, w = window.getmaxyx()
    addstr(window, h // 2, max((w - len(s)) // 2, 0), s, attrs)


def rectangle(win, uly, ulx, lry, lrx):
    """Draw a rectangle with corners at the provided upper-left
    and lower-right coordinates.
    """
    win.vline(uly+1, ulx, curses.ACS_VLINE, lry - uly - 1)
    win.hline(uly, ulx+1, curses.ACS_HLINE, lrx - ulx - 1)
    win.hline(lry, ulx+1, curses.ACS_HLINE, lrx - ulx - 1)
    win.vline(uly+1, lrx, curses.ACS_VLINE, lry - uly - 1)
    win.addch(uly, ulx, curses.ACS_ULCORNER)
    win.addch(uly, lrx, curses.ACS_URCORNER)
    ignore_curses_err(win.addch, lry, lrx, curses.ACS_LRCORNER)
    win.addch(lry, ulx, curses.ACS_LLCORNER)


def addstr(window, y, x, s, *attrs):
    try:
        for i, c in enumerate(s, x):
            window.addch(y, i, c, *attrs)
    except curses.error:
        pass



def human_rate(r):
    rate = r * 8

    if rate > 1024 * 1024:
        rate = rate / 1024 / 1024
        mod = 'mbit/s'
    else:
        rate = rate / 1024
        mod = 'kbit/s'

    if rate < 10:
        return '%0.1f %s' % (rate, mod)
    else:
        return '%3d %s' % (rate, mod)


class AntennaStat(Int32StringReceiver):
    MAX_LENGTH = 1024 * 1024

    def stringReceived(self, string):
        attrs = msgpack.unpackb(string, strict_map_key=False, use_list=False)

        if attrs['type'] == 'rx':
            self.draw_rx(attrs)
        elif attrs['type'] == 'tx':
            self.draw_tx(attrs)
        elif attrs['type'] == 'cli_title':
            set_window_title(attrs['cli_title'])

    def draw_rx(self, attrs):
        p = attrs['packets']
        session_d = attrs['session']
        stats_d = attrs['rx_ant_stats']
        tx_ant = attrs.get('tx_ant')
        rx_id = attrs['id']

        window = self.factory.windows.get(rx_id)
        if window is None:
            return

        window.erase()
        addstr(window, 0, 0, '     pkt/s pkt')

        msg_l = (('recv  %4d %d' % tuple(p['all']),     0),
                 #('recvb %4d %d' % tuple(p['all_bytes']),     0),
                 ('udp   %4d %d' % tuple(p['out']),     0),
                 #('udpb  %4d %d' % tuple(p['out_bytes']),     0),
                 ('fec_r %4d %d' % tuple(p['fec_rec']), curses.A_REVERSE if p['fec_rec'][0] else 0),
                 ('lost  %4d %d' % tuple(p['lost']),    curses.A_REVERSE if p['lost'][0] else 0),
                 ('d_err %4d %d' % tuple(p['dec_err']), curses.A_REVERSE if p['dec_err'][0] else 0),
                 ('bad   %4d %d' % tuple(p['bad']),     curses.A_REVERSE if p['bad'][0] else 0))

        ymax = window.getmaxyx()[0]
        for y, (msg, attr) in enumerate(msg_l, 1):
            if y < ymax:
                addstr(window, y, 0, msg, attr)

        session = ''
        if session_d:
            session = ', FEC: %(fec_k)d/%(fec_n)d' % (session_d)

        addstr(window, 0, 20, 'Flow: %s -> %s%s' % \
               (human_rate(p['all_bytes'][0]),
                human_rate(p['out_bytes'][0]),
                session))

        if stats_d:
            addstr(window, 2, 20, 'Freq MCS BW [ANT] pkt/s     RSSI [dBm]        SNR [dB]')
            for y, (((freq, mcs_index, bandwith), ant_id), v) in enumerate(sorted(stats_d.items()), 3):
                pkt_s, rssi_min, rssi_avg, rssi_max, snr_min, snr_avg, snr_max = v
                if y < ymax:
                    active_tx = '*' if (ant_id >> 8) == tx_ant else ' '
                    addstr(window, y, 20, '%04d %3d %2d %s%04x  %4d  %3d < %3d < %3d  %3d < %3d < %3d' % \
                           (freq, mcs_index, bandwith, active_tx, ant_id, pkt_s,
                            rssi_min, rssi_avg, rssi_max,
                            snr_min, snr_avg, snr_max))
        else:
            addstr(window, 2, 20, '[No data]', curses.A_REVERSE)

        window.refresh()

    def draw_tx(self, attrs):
        p = attrs['packets']
        latency_d = attrs['latency']
        tx_id = attrs['id']

        window = self.factory.windows.get(tx_id)
        if window is None:
            return

        window.erase()
        addstr(window, 0, 0, '     pkt/s pkt')

        msg_l = (('sent  %4d %d' % tuple(p['injected']),     0),
                 #('sentb %4d %d' % tuple(p['injected_bytes']),     0),
                 ('udp   %4d %d' % tuple(p['incoming']),     0),
                 #('udpb  %4d %d' % tuple(p['incoming_bytes']),     0),
                 ('fec_t %4d %d' % tuple(p['fec_timeouts']), 0),
                 ('drop  %4d %d' % tuple(p['dropped']),    curses.A_REVERSE if p['dropped'][0] else 0),
                 ('trunc %4d %d' % tuple(p['truncated']), curses.A_REVERSE if p['truncated'][0] else 0))

        ymax = window.getmaxyx()[0]
        for y, (msg, attr) in enumerate(msg_l, 1):
            if y < ymax:
                addstr(window, y, 0, msg, attr)

        addstr(window, 0, 20, 'Flow: %s -> %s' % \
               (human_rate(p['incoming_bytes'][0]),
                human_rate(p['injected_bytes'][0])))

        if latency_d:
            addstr(window, 2, 20, '[ANT] pkt/s     Injection [us]')
            for y, (k, v) in enumerate(sorted(latency_d.items()), 3):
                k = int(k) # json doesn't support int keys
                injected, dropped, lat_min, lat_avg, lat_max = v
                if y < ymax:
                    addstr(window, y, 20, '%04x:  %4d  %4d < %4d < %4d' % (k, injected, lat_min, lat_avg, lat_max))
        else:
            addstr(window, 2, 20, '[No data]', curses.A_REVERSE)


        window.refresh()


class AntennaStatClientFactory(ReconnectingClientFactory):
    noisy = False
    maxDelay  = 1.0

    def __init__(self, stdscr, profile):
        self.stdscr = stdscr
        self.profile = profile
        self.windows = {}
        self.init_windows()

    def init_windows(self):
        self.windows.clear()
        # python < 3.11 doesn't have termios.tcgetwinsize
        height, width = struct.unpack('hh', fcntl.ioctl(1, termios.TIOCGWINSZ, b' ' * 4))
        curses.resize_term(height, width)
        self.stdscr.clear()

        service_list = list((s_name, cfg.stream_rx is not None, cfg.stream_tx is not None) for s_name, _, cfg in  parse_services(self.profile))

        if not service_list:
            rectangle(self.stdscr, 0, 0, height - 1, width - 1)
            addstr(self.stdscr, 0, 3, '[%s not configured]' % (self.profile,), curses.A_REVERSE)
            self.stdscr.refresh()
            return

        n_exp = 0
        h_exp = height
        h_fixed = 3

        for _, show_rx_stats, show_tx_stats in service_list:
            if show_rx_stats or show_tx_stats:
                n_exp += 1
            else:
                h_exp -= h_fixed

        if n_exp > 0:
            h_exp = h_exp / n_exp

        hoff_int = 0
        hoff_float = 0

        for name, show_rx_stats, show_tx_stats in service_list:
            if show_rx_stats or show_tx_stats:
                hoff_float += h_exp
            else:
                hoff_float += h_fixed

            whl = []
            for ww, xoff, txrx, show_stats in [((width * 4 // 7 - 1), 0, 'rx', show_rx_stats),
                                               ((width - width * 4 // 7 - 1), width * 4 // 7, 'tx', show_tx_stats)]:
                if not show_stats:
                    whl.append(0)
                    continue

                err = round(hoff_float) - (hoff_int + int(h_exp))
                wh = int(h_exp) + err
                if wh < h_fixed:
                    raise Exception('Terminal height is too small')

                window = self.stdscr.subpad(wh - 2, ww - 2, hoff_int + 1, xoff + 1)
                window.idlok(1)
                window.scrollok(1)

                rectangle(self.stdscr, hoff_int, xoff, hoff_int + wh - 1, xoff + ww)
                addstr(self.stdscr, hoff_int, 3 + xoff, '[%s: %s %s]' % (txrx.upper(), self.profile, name))

                self.windows['%s %s' % (name, txrx)] = window
                whl.append(wh)

            hoff_int += max(whl)
        self.stdscr.refresh()

    def startedConnecting(self, connector):
        set_window_title('Connecting to %s:%d ...' % (connector.host, connector.port))

        for window in self.windows.values():
            window.erase()
            addcstr(window, 'Connecting...')
            window.refresh()

    def buildProtocol(self, addr):
        set_window_title('Connected to %s' % (addr,))

        for window in self.windows.values():
            window.erase()
            addcstr(window, 'Waiting for data...')
            window.refresh()

        self.resetDelay()
        p = AntennaStat()
        p.factory = self
        return p

    def clientConnectionLost(self, connector, reason):
        set_window_title('Connection lost: %s' % (reason.value,))

        for window in self.windows.values():
            window.erase()
            addcstr(window, '[Connection lost]', curses.A_REVERSE)
            window.refresh()

        ReconnectingClientFactory.clientConnectionLost(self, connector, reason)

    def clientConnectionFailed(self, connector, reason):
        set_window_title('Connection failed: %s' % (reason.value,))

        for window in self.windows.values():
            window.erase()
            addcstr(window, '[Connection failed]', curses.A_REVERSE)
            window.refresh()

        ReconnectingClientFactory.clientConnectionFailed(self, connector, reason)


def init(stdscr, profile):
    stats_port = getattr(settings, profile).stats_port
    f = AntennaStatClientFactory(stdscr, profile)

    # Resize windows on terminal size change
    def sigwinch_handler(signum, sigstack):
        reactor.callFromThread(lambda: defer.maybeDeferred(f.init_windows).addErrback(abort_on_crash))

    signal.signal(signal.SIGWINCH, sigwinch_handler)
    reactor.connectTCP('127.0.0.1', stats_port, f)



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
