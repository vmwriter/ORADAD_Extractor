import unittest
import os
from datetime import datetime
from oradad_extractor import OradadExtractor, OradadParsingError
import xml.etree.ElementTree as ET
import tempfile

class TestOradadExtractor(unittest.TestCase):
    def setUp(self):
        # Create a temporary MLA file for testing
        self.test_mla_content = '''<?xml version="1.0" encoding="utf-8"?>
        <oradad>
            <domain name="test.local">
                <entry>
                    <objectClass>user</objectClass>
                    <sAMAccountName>testuser</sAMAccountName>
                    <userAccountControl>512</userAccountControl>
                    <whenCreated>20240101000000.0Z</whenCreated>
                    <lastLogon>20240301000000.0Z</lastLogon>
                </entry>
                <entry>
                    <objectClass>computer</objectClass>
                    <sAMAccountName>TESTPC$</sAMAccountName>
                    <dNSHostName>testpc.test.local</dNSHostName>
                    <operatingSystem>Windows Server 2019</operatingSystem>
                </entry>
            </domain>
        </oradad>
        '''
        self.temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.mla')
        with open(self.temp_file.name, 'w') as f:
            f.write(self.test_mla_content)
        
        self.extractor = OradadExtractor(self.temp_file.name)

    def tearDown(self):
        os.unlink(self.temp_file.name)

    def test_parse_file(self):
        self.extractor.parse_file()
        self.assertEqual(len(self.extractor.users), 1)
        self.assertEqual(len(self.extractor.computers), 1)
        
        # Test user parsing
        user = self.extractor.users[0]
        self.assertEqual(user.sam_account_name, 'testuser')
        self.assertTrue(user.enabled)
        
        # Test computer parsing
        computer = self.extractor.computers[0]
        self.assertEqual(computer.name, 'TESTPC')
        self.assertEqual(computer.operating_system, 'Windows Server 2019')

    def test_invalid_file(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix='.mla') as temp:
            temp.write(b'invalid content')
        
        extractor = OradadExtractor(temp.name)
        with self.assertRaises(OradadParsingError):
            extractor.parse_file()
        
        os.unlink(temp.name)

    def test_compressed_file(self):
        import gzip
        # Create compressed test file
        gz_file = tempfile.NamedTemporaryFile(delete=False, suffix='.mla.gz')
        with gzip.open(gz_file.name, 'wt') as f:
            f.write(self.test_mla_content)
        
        extractor = OradadExtractor(gz_file.name)
        extractor.parse_file()
        
        self.assertEqual(len(extractor.users), 1)
        self.assertEqual(len(extractor.computers), 1)
        
        os.unlink(gz_file.name)

if __name__ == '__main__':
    unittest.main() 