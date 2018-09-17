from __future__ import division
from builtins import zip
from builtins import str
from builtins import range
from past.utils import old_div
import unittest
import coverage
import sys
import os
import binascii

sys.path.append('..')
from tests.BaseTest import EmpireTestCase
from lib.common import encryption


class TestCoreEncryptionModel(EmpireTestCase):
    _src_coverage = '*/lib/common/encryption.py'

    _conn = None

    def setUp(self):
        """Setup stuff."""
        pass

    def tearDown(self):
        # Test teardown
        pass

    def test_01_rc4(self):
        _rc4_iv = os.urandom(4)
        _rc4_key = os.urandom(16)
        _data = [
            "TestOne",
            "TestTwo",
            "TestThree"
        ]

        for d in _data:
            cT = encryption.rc4(_rc4_iv+_rc4_key, d)
            cT2 = encryption.rc4_enc(_rc4_iv+_rc4_key, d)
            pT = encryption.rc4(_rc4_iv+_rc4_key, cT)
            pT2 = encryption.rc4_dec(_rc4_iv+_rc4_key, cT2)
            pT3 = encryption.rc4_dec(_rc4_iv+_rc4_key, bytearray(cT, 'iso-8859-1'))
            pT4 = encryption.rc4(_rc4_iv+_rc4_key, cT2.decode('iso-8859-1'))

            self.assertNotEqual(cT, d)
            self.assertNotEqual(cT2, d)
            self.assertEqual(pT, d)
            self.assertEqual(pT2, d)
            self.assertEqual(pT3, d)
            self.assertEqual(pT4, d)
