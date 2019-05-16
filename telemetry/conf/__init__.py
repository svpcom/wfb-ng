#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function
from __future__ import unicode_literals
from __future__ import division
from __future__ import absolute_import

from future import standard_library
standard_library.install_aliases()

from builtins import *

import os
import sys
from telemetry import config_parser

_cfg_files = [ 'master.cfg', 'site.cfg', '/etc/wifibroadcast.cfg', 'local.cfg' ]   # local.cfg is for debug only


def _parse_config(telemetry_cfg=None):
    return config_parser.parse_config(os.path.join(os.getcwd(), os.path.dirname(__file__)), telemetry_cfg or _cfg_files)


settings, cfg_files = _parse_config()
