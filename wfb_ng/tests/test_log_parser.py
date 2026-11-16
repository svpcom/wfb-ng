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

import io
import gzip
import zlib
import struct
import msgpack
from unittest import mock

from twisted.trial import unittest
from .. import log_parser


def records(version):
    return b''.join(struct.pack('!I', len(m)) + m
                    for m in [msgpack.packb(dict(timestamp=1.0, type='init', version=version))])


class LogParserTestCase(unittest.TestCase):
    def test_a_log_without_the_gzip_trailer_is_read_and_the_next_file_too(self):
        # a log of a drone that lost power: flushed, never closed
        unclosed, closed = self.mktemp(), self.mktemp()
        c = zlib.compressobj(6, zlib.DEFLATED, 31)
        with open(unclosed, 'wb') as fd:
            fd.write(c.compress(records('first')) + c.flush(zlib.Z_SYNC_FLUSH))
        with gzip.open(closed, 'wb') as fd:
            fd.write(records('second'))

        out = io.StringIO()
        with mock.patch('sys.argv', ['wfb-log-parser', unclosed, closed]), mock.patch('sys.stdout', out):
            log_parser.main()

        self.assertIn('first', out.getvalue())
        self.assertIn('second', out.getvalue())
