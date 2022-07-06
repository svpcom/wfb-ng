#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
from .. import config_parser

wfb_ng_cfg = os.getenv('WIFIBROADCAST_CFG', '/etc/wifibroadcast.cfg')

_cfg_files = [ 'master.cfg', 'site.cfg', wfb_ng_cfg, 'local.cfg' ]   # local.cfg is for debug only


def _parse_config(wfb_ng_cfg=None):
    return config_parser.parse_config(os.path.join(os.getcwd(), os.path.dirname(__file__)), wfb_ng_cfg or _cfg_files)


settings, cfg_files = _parse_config()
