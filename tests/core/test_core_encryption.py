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
import random
import string

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

    def test_02_rc4_b(self):
        """Testing RC4 with known plaintext/ciphertext"""
        from binascii import hexlify, unhexlify
        pt_data = unhexlify(b'4834504d3538324b020600002a000000') #DevSkim: ignore DS173237 
        key = b'34393432' + unhexlify(b'696d747847615b637a77645776513e4479456741213765732628255566503b5d') #DevSkim: ignore DS173237,DS117838 
        ct_data = unhexlify(b'6a53af2a77ad010a10017b79d21d7553') #DevSkim: ignore DS173237 
    


    def test_02_aes_hmac(self):
        punctuation = '!#%&()*+,-./:;<=>?@[]^_{|}~'
        _staging_key = ''.join(random.sample(string.ascii_letters + string.digits + punctuation, 32))
        _staging_key = bytes(_staging_key, 'utf-8')
        _data = [
            "TestOne",
            "TestTwo",
            "TestThree"
        ]

        for d in _data:
            cT = encryption.aes_encrypt(_staging_key, d)
            cT2 = encryption.aes_encrypt(_staging_key, d)
            hmac_cT = encryption.aes_encrypt_then_hmac(_staging_key, d)
            hmac_verified = encryption.verify_hmac(_staging_key, hmac_cT)
            pT = encryption.aes_decrypt(_staging_key, cT).decode('utf-8')
            pT2 = encryption.aes_decrypt(_staging_key, cT2).decode('utf-8')
            hmac_pT = encryption.aes_decrypt_and_verify(_staging_key, hmac_cT).decode('utf-8')

            self.assertNotEqual(cT, d)
            self.assertNotEqual(cT, cT2)
            self.assertEqual(pT, d)
            self.assertEqual(pT2, d)
            self.assertTrue(hmac_verified, msg="HMAC verification failed.")
            self.assertEqual(hmac_pT, d)

    def test_03_dhe(self):
        alice = encryption.DiffieHellman()
        bob = encryption.DiffieHellman()
        alice.genKey(bob.publicKey)
        bob.genKey(alice.publicKey)

        self.assertTrue(alice.getKey() == bob.getKey())