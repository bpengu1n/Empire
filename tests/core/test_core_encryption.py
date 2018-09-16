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
            cT2 = encryption.rc4_encrypt(_rc4_iv+_rc4_key, d)
            pT = encryption.rc4(_rc4_iv+_rc4_key, cT)
            pT2 = encryption.rc4_decrypt(_rc4_iv+_rc4_key, cT2)

            print((cT, cT2))

            self.assertNotEqual(cT, d)
            self.assertNotEqual(cT2, d)
            self.assertEqual(pT, d)
            self.assertEqual(pT2.decode('utf-8'), d)
        # Test case 1
        # key = 'Key'
        # plaintext = 'Plaintext'
        # ciphertext = 'c2bbc3b316c3a8c39940c2af0ac393'
        pT = 'Plaintext'
        cT = encryption.rc4(b'Key', pT)
        
        self.assertEqual(binascii.hexlify(bytes(cT, 'utf-8')), 
                            b'c2bbc3b316c3a8c39940c2af0ac393')
        r = encryption.rc4(b'Key', cT)

        self.assertEqual(r, pT)

        # Test case 2
        # key = 'Wiki' # '57696b69'in hex
        # plaintext = 'pedia'
        # ciphertext should be 1021BF0420
        # assert(encrypt('Wiki', 'pedia')) == '1021BF0420'
        # assert(decrypt('Wiki', '1021BF0420')) == 'pedia'
