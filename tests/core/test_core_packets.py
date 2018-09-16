from __future__ import division
from builtins import zip
from builtins import str
from builtins import range
from past.utils import old_div
import unittest
import coverage
import sys
import os

sys.path.append('..')
from tests.BaseTest import EmpireTestCase
from lib.common import packets


class TestCorePacketsModel(EmpireTestCase):
    _src_coverage = '*/lib/common/encryption.py'

    _conn = None

    def setUp(self):
        """Setup stuff."""
        pass

    def tearDown(self):
        # Test teardown
        pass

    def test_routing_packet(self):
        ' def build_routing_packet(stagingKey, sessionID, language, meta="NONE", additional="NONE", encData=''):'
        ' parse_routing_packet(stagingKey, data):'
        _key = os.urandom(12)
        _sessID = "00000000"
        _lang = "python"

        p = packets.build_routing_packet(_key, _sessID, _lang)
        self.assertIsNotNone(p)
        res = packets.parse_routing_packet(_key, p)
        self.assertIsNotNone(res)
        


        # _data = [
        #     "TestOne",
        #     "TestTwo",
        #     "TestThree"
        # ]

        # for d in _data:
        #     cT = encryption.rc4(_rc4_iv+_rc4_key, d)
        #     pT = encryption.rc4(_rc4_iv+_rc4_key, cT)

        #     self.assertNotEqual(cT, d)
        #     self.assertEqual(pT, d)
