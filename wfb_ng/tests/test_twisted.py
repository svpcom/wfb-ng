from twisted.trial import unittest
from twisted.internet import reactor
import msgpack

class ClockTestCase(unittest.TestCase):
    def test_reactor_has_monitonic_clock(self):
        self.assertLess(reactor.seconds(), 1000000000)

    def test_msgpack(self):
        a = ({(1, '2') : (b'spam', 'eggs')},)
        b = msgpack.unpackb(msgpack.packb(a, use_bin_type=True), raw=False, strict_map_key=False, use_list=False)
        self.assertEqual(a, b)
