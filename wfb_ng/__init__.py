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
import os
import queue
import threading
import atexit
import time

# Patch twisted to enable monotonic clock in the reactor
# This is a bit fragile, but no other ways to do it without patching twisted sources
from twisted.python import runtime
runtime.seconds = time.monotonic
runtime.Platform.seconds = staticmethod(time.monotonic)

# This is only needed for unit-tests because trial imports it early before we patch clock source
from importlib import reload
from twisted.internet import base as twisted_internet_base
reload(twisted_internet_base)

from twisted.internet import utils, reactor
from logging import currentframe
from twisted.python import log
from twisted.python.logfile import LogFile

version_msg = """\
WFB-ng version %(common.version)s
Copyright (C) 2018-2024 Vasily Evseenko <svpcom@p2ptech.org>
License GPLv3: GNU GPL version 3 <http://gnu.org/licenses/gpl.html>

This is free software; you are free to change and redistribute it.
There is NO warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
"""

__orig_msg = log.msg
_srcfile = os.path.splitext(os.path.normcase(__file__))[0] + '.py'

# Returns escape codes from format codes
esc = lambda *x: '\033[' + ';'.join(x) + 'm'

# The initial list of escape codes
escape_codes = {
    'reset': esc('39', '49', '0'),
    'bold': esc('01'),
}

# The color names
colors = [
    'black',
    'red',
    'green',
    'yellow',
    'blue',
    'purple',
    'cyan',
    'white'
]

# Create foreground and background colors...
for lcode, lname in [('3', ''), ('4', 'bg_')]:
    # ...with the list of colors...
    for code, name in enumerate(colors):
        code = str(code)
        # ...and both normal and bold versions of each color
        escape_codes[lname + name] = esc(lcode + code)
        escape_codes[lname + "bold_" + name] = esc(lcode + code, "01")


def color_str(arg, c, bold=False):
    return '%s%s%s%s' % (escape_codes[c], escape_codes['bold'] if bold else '', arg, escape_codes['reset'])


class ConsoleObserver(object):
    def emit(self, eventDict):
        print('[%s] %s' % (eventDict['system'], eventDict['log_text']))
        sys.stdout.flush()


def __findCaller():
    """
    Find the stack frame of the caller so that we can note the source
    file name, line number and function name.
    """
    f = currentframe()

    #On some versions of IronPython, currentframe() returns None if
    #IronPython isn't run with -X:Frames.

    if f is not None:
        f = f.f_back

    rv = "(unknown file)", 0, "(unknown class)", "(unknown function)"

    while hasattr(f, "f_code"):
        co = f.f_code
        filename = os.path.normcase(co.co_filename)
        if filename == _srcfile:
            f = f.f_back
            continue

        try:
            if 'self' in f.f_locals:
                klass = f.f_locals['self'].__class__.__name__
            else:
                klass = ''
        except:
            klass = '<undef>'

        rv = (co.co_filename, f.f_lineno, klass, co.co_name)
        break
    return rv


class LogLevel(object):
    """Log levels"""
    DEBUG = 1
    INFO = 2
    NOTICE = 3
    WARNING = 4
    ERROR = 5
    ALERT = 6
    FATAL = 7


log_level_map = { LogLevel.DEBUG : 'debug',
                  LogLevel.INFO : 'info',
                  LogLevel.NOTICE : 'notice',
                  LogLevel.WARNING : 'warning',
                  LogLevel.ERROR : 'error',
                  LogLevel.ALERT : 'alert',
                  LogLevel.FATAL : 'fatal_error'}


def _log_msg(*args, **kwargs):
    def _stub():
        return __findCaller()

    level = kwargs.get('level', None)

    if level not in set(LogLevel.__dict__.values()):
        level = LogLevel.ERROR if kwargs.get('isError') else LogLevel.INFO
        kwargs['level'] = level

    error = (level >= LogLevel.ERROR)
    kwargs['isError'] = 1 if error else 0

    if 'why' in kwargs:  # handle call from log.err
        path, line, klass, func = __findCaller()
    else:
        path, line, klass, func = _stub()

    filename = os.path.basename(path)
    module = os.path.splitext(filename)[0]

    tmp = [color_str(module, 'red' if error else 'blue')]

    if klass:
        tmp.append(color_str(klass, 'red' if error else 'blue'))

    tmp.append(color_str(func, 'red' if error else 'green'))
    kwargs['system'] = '%s #%s' % ('.'.join(tmp), log_level_map[level])

    return __orig_msg(*args, **kwargs)


class ExecError(Exception):
    pass


def call_and_check_rc(cmd, *args, **kwargs):
    def _check_rc(_args):
        (stdout, stderr, rc) = _args
        if rc != 0:
            err = ExecError('RC %d: %s %s' % (rc, cmd, ' '.join(args)))
            err.stdout = stdout.strip()
            err.stderr = stderr.strip()
            raise err

        log.msg('# %s' % (' '.join((cmd,) + args),))

        if stdout and kwargs.get('log_stdout', True):
            log.msg(stdout)

        return stdout

    def _got_signal(f):
        f.trap(tuple)
        stdout, stderr, signum = f.value
        err = ExecError('Got signal %d: %s %s' % (signum, cmd, ' '.join(args)))
        err.stdout = stdout.strip()
        err.stderr = stderr.strip()
        raise err

    return utils.getProcessOutputAndValue(cmd, args, env=os.environ).addCallbacks(_check_rc, _got_signal)



def close_if_failed(f):
    def _f(self, *args, **kwargs):
        try:
            return f(self, *args, **kwargs)
        except Exception as v:
            if self.twisted_logger:
                # Don't use logger due to infinite loop
                print('Unable to write to log file: %s' % (v,), file=self.stderr)
            else:
                reactor.callFromThread(log.err, v, 'Unable to write to: %s(%s, %s)' % (self.log_cls, self.args, self.kwargs))

            if self.logfile is not None:
                self.logfile.close()
                self.logfile = None
    return _f


class ErrorSafeLogFile(object):
    stderr = sys.stderr
    log_cls = LogFile
    log_max = 1000
    binary = False
    twisted_logger = True
    flush_delay = 0

    def __init__(self, *args, **kwargs):
        cleanup_at_exit = kwargs.pop('cleanup_at_exit', True)
        self.logfile = None
        self.args = args
        self.kwargs = kwargs
        self.need_stop = threading.Event()
        self.lock = threading.RLock()
        self.log_queue_overflow = 0
        self.log_queue = queue.Queue(self.log_max)
        self.thread = threading.Thread(target=self._log_thread_loop, name='logging thread')
        self.thread.daemon = True
        self.thread.start()

        if cleanup_at_exit:
            atexit.register(self._cleanup)

    def _cleanup(self):
        self.log_queue.join()
        self.need_stop.set()
        self.thread.join()

        if self.logfile is not None:
            self.logfile.close()
            self.logfile = None

    def _log_thread_loop(self):
        flush_ts = 0

        while not self.need_stop.is_set():
            now = time.time()

            if self.flush_delay > 0 and now > flush_ts:
                flush_ts = now + self.flush_delay
                self._flush()

            try:
                data = self.log_queue.get(timeout=1)
            except queue.Empty:
                continue

            overflow = 0
            with self.lock:
                if self.log_queue_overflow:
                    overflow = self.log_queue_overflow
                    self.log_queue_overflow = 0

            if overflow and not self.binary:
                self._write('--- Dropped %d log items due to log queue overflow\n' % (overflow,))

            self._write(data)
            self.log_queue.task_done()

    @close_if_failed
    def _write(self, data):
        if self.logfile is None:
            self.logfile = self.log_cls(*self.args, **self.kwargs)

        self.logfile.write(data)

        if self.flush_delay == 0:
            self.logfile.flush()

    @close_if_failed
    def _flush(self):
        if self.logfile is not None:
            self.logfile.flush()

    def write(self, data):
        try:
            self.log_queue.put_nowait(data)
        except queue.Full:
            with self.lock:
                self.log_queue_overflow += 1

    def flush(self):
        pass
