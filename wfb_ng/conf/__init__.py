#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (C) 2022-2026 Vasily Evseenko <svpcom@p2ptech.org>

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

import os
import sys
from .. import config_parser

wfb_ng_cfg = os.getenv('WIFIBROADCAST_CFG', '/etc/wifibroadcast.cfg')

_cfg_files = [ 'master.cfg', 'site.cfg', wfb_ng_cfg, 'local.cfg' ]   # local.cfg is for debug only


def _parse_config(wfb_ng_cfg=None):
    return config_parser.parse_config(os.path.join(os.getcwd(), os.path.dirname(__file__)), wfb_ng_cfg or _cfg_files)


settings, cfg_files = _parse_config()
