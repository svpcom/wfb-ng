#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (C) 2018-2026 Vasily Evseenko <svpcom@p2ptech.org>

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

from twisted.trial import unittest
from ..cli import AntennaStat


class FakeWindow(object):
    def __init__(self):
        self.chars = {}

    def erase(self):
        self.chars.clear()

    def refresh(self):
        pass

    def getmaxyx(self):
        return (24, 120)

    def addch(self, y, x, c, attrs=0):
        self.chars[(y, x)] = c

    def lines(self):
        rows = {}
        for (y, x), c in sorted(self.chars.items()):
            rows.setdefault(y, []).append(c)
        return [''.join(r) for _, r in sorted(rows.items())]


class FakeFactory(object):
    def __init__(self, window):
        self.windows = {'video rx': window}


class DrawRXTestCase(unittest.TestCase):
    def setUp(self):
        self.window = FakeWindow()
        self.p = AntennaStat()
        self.p.factory = FakeFactory(self.window)
        self.p.log_interval = 1000
        self.p.is_cluster = False
        self.attrs = dict(id='video rx', tx_wlan=0, session=dict(fec_k=8, fec_n=12),
                          rx_ant_stats={((5825, 1, 20), 0): (100, -50, -45, -40, 20, 25, 30)})

    def test_stats_of_a_25_01_server(self):
        # 25.01 has dec_ok in place of session, data and uniq
        self.attrs['packets'] = dict((k, (100, 1000)) for k in ('all', 'all_bytes', 'dec_err', 'dec_ok', 'fec_rec',
                                                                  'lost', 'bad', 'out', 'out_bytes'))
        self.p.draw_rx(self.attrs)
        self.assertTrue(any('-45' in l for l in self.window.lines()))
