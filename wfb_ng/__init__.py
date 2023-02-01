import sys
import os
from twisted.internet import utils
from logging import currentframe
from twisted.python import log

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
