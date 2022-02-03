#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import time
import datetime


def main():
    # last commit timestamp + branch name
    ttuple = time.gmtime(int(sys.argv[1]))
    branch = sys.argv[2]

    if branch.startswith('release-'):
        release = [int(i) for i in branch.split('-')[1].split('.')]
        delta = datetime.datetime(*ttuple[:6]) - datetime.datetime(2000 + release[0], release[1], 1)

        print('%d.%d.%s.%d' % (release[0], release[1], '0.%d' % (999 + delta.days,) if delta.days < 0 else (delta.days + 1),
                               ttuple.tm_hour * 3600 + ttuple.tm_min * 60 + ttuple.tm_sec))
    else:
        print('%d.%d.%d.%d' % (ttuple.tm_year - 2000, ttuple.tm_mon, ttuple.tm_mday,
                               ttuple.tm_hour * 3600 + ttuple.tm_min * 60 + ttuple.tm_sec))


if __name__ == '__main__':
    main()
