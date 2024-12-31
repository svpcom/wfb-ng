from twisted.trial import unittest
from twisted.python import log
from twisted.internet import reactor, task, defer
import msgpack
import time
import math

class ClockTestCase(unittest.TestCase):
    def test_reactor_has_monitonic_clock(self):
        self.assertLess(reactor.seconds(), 1000000000)

    def test_msgpack(self):
        a = ({(1, '2') : (b'spam', 'eggs')},)
        b = msgpack.unpackb(msgpack.packb(a, use_bin_type=True), raw=False, strict_map_key=False, use_list=False)
        self.assertEqual(a, b)


    @defer.inlineCallbacks
    def test_timer_resolution(self):
        delay = 2e-3
        iters = 500

        sum = 0
        sqsum = 0

        for i in range(iters):
            ts = time.time_ns()
            yield task.deferLater(reactor, delay, lambda: None)
            latency = time.time_ns() - ts - delay * 1e9
            sum += latency
            sqsum += latency**2

        lat_mean = sum / iters
        lat_stdmean = 3 * math.sqrt(sqsum / ( iters * (iters - 1)))

        log.msg('Twisted timer resolution: %.2f +- %.2f ms' % (lat_mean / 1e6, lat_stdmean / 1e6))
