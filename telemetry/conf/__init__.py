#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
from telemetry import config_parser

wifibroadcast_cfg = os.getenv('WIFIBROADCAST_CFG', '/etc/wifibroadcast.cfg')

_cfg_files = [ 'master.cfg', 'site.cfg', wifibroadcast_cfg, 'local.cfg' ]   # local.cfg is for debug only


def _parse_config(telemetry_cfg=None):
    return config_parser.parse_config(os.path.join(os.getcwd(), os.path.dirname(__file__)), telemetry_cfg or _cfg_files)


settings, cfg_files = _parse_config()
