from twisted.trial import unittest
from twisted.internet import reactor


class ClockTestCase(unittest.TestCase):
    def test_reactor_has_monitonic_clock(self):
        self.assertLess(reactor.seconds(), 1000000000)
