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
from twisted.internet import defer, error
from ..protocols import RXAntennaProtocol, SSHClientProtocol, TXProtocol
from ..services import make_ant_sel_cb


class SSHClientProtocolTestCase(unittest.TestCase):
    def test_ssh_port_is_passed_to_ssh(self):
        p = SSHClientProtocol('10.0.0.5', 'root', 'true', port=2222)
        args = p.ssh_args()
        self.assertEqual(args[0], 'ssh')
        self.assertIn(('-p', '2222'), list(zip(args, args[1:])))
        self.assertEqual(args[-2:], ['root@10.0.0.5', 'true'])


class TXProtocolTestCase(unittest.TestCase):
    @defer.inlineCallbacks
    def test_spawn_failure_releases_waiters(self):
        ports_df = defer.Deferred()
        control_port_df = defer.Deferred()
        p = TXProtocol(None, ['/nonexistent/wfb_tx'], 'test tx', ports_df, control_port_df)
        # posix_spawn based Twisted fails synchronously, fork based one reports exec failure via processEnded
        yield self.assertFailure(p.start(), FileNotFoundError, error.ProcessTerminated)
        yield self.assertFailure(ports_df, defer.CancelledError)
        yield self.assertFailure(control_port_df, defer.CancelledError)

    test_spawn_failure_releases_waiters.timeout = 2


class Peer:
    peer = None


class AntSelCallbackTestCase(unittest.TestCase):
    def test_unknown_wlan_keeps_current_peer(self):
        p_in = Peer()
        cb = make_ant_sel_cb('test', p_in, {1: 'tx1', 2: 'tx2'})
        cb(None)
        self.assertEqual(p_in.peer, 'tx1')
        cb(2)
        self.assertEqual(p_in.peer, 'tx2')
        cb(3)
        self.assertEqual(p_in.peer, 'tx2')


class RXAntennaProtocolTestCase(unittest.TestCase):
    def test_pkt_counters_with_the_fragments_of_the_blocks(self):
        # the fragments of the blocks done, data and FEC, and those of them lost
        got = []
        cb = type('CB', (), dict(update_rx_stats=lambda self, rx_id, stats, ant, session: got.append(stats)))()
        p = RXAntennaProtocol(cb, 'video rx')
        p.lineReceived(b'1000\tPKT\t30:39000:0:1:29:29:3:1:0:20:26000:24:8\n')
        p.lineReceived(b'2000\tPKT\t30:39000:0:1:29:29:3:1:0:20:26000:24:8\n')
        self.assertEqual((got[-1]['out'], got[-1]['frags'], got[-1]['frags_lost']), ((20, 40), (24, 48), (8, 16)))

