import unittest
import sys
import os

# Ensure the test script finds advcsv properly
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from advcsv import advcsv

class TestAdvCsv(unittest.TestCase):
    def test_compress_decompress(self):
        data = [["Alice", "admin"], ["Bob", "user"]]
        headers = ["name", "role"]
        compressed = advcsv.compress_csv(data, headers)
        decompressed = advcsv.decompress_csv(compressed)
        self.assertEqual(data, decompressed[1:])  # Ignore headers

    def test_encrypt_decrypt(self):
        data = [["Charlie", "editor"]]
        headers = ["name", "role"]
        key = advcsv.generate_key()
        encrypted = advcsv.encrypt_csv(data, headers, key)
        decrypted = advcsv.decrypt_csv(encrypted, key)
        self.assertEqual(data, decrypted[1:])  # Ignore headers

    def test_validate_csv(self):
        data = [["David", "admin"]]
        headers = ["name", "role"]
        schema = {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "role": {"type": "string"}
                }
            }
        }
        self.assertTrue(advcsv.validate_csv(data, headers, schema))

    def test_multi_threaded_compression(self):
        data_list = [
            [["name", "role"], ["Alice", "admin"]],
            [["name", "role"], ["Bob", "user"]]
        ]
        headers = ["name", "role"]
        compressed_list = advcsv.multi_threaded_compression(data_list, headers)
        self.assertEqual(len(compressed_list), 2)

if __name__ == "__main__":
    unittest.main()
