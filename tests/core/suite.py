from __future__ import absolute_import
import unittest
from .test_core_helpers import TestCoreHelpersModel
from .test_core_encryption import TestCoreEncryptionModel
from .test_core_packets import TestCorePacketsModel

def suite():
	classes = [
		TestCoreEncryptionModel,
		TestCorePacketsModel,
		# Add test case models here
	]
	suites = []
	for c in classes:
		suites.append(unittest.TestLoader().loadTestsFromTestCase(c))
	
	return unittest.TestSuite(suites)
