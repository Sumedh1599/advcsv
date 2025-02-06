import csv
import gzip
import base64
import os
from cryptography.fernet import Fernet
import threading
import jsonschema
import io

class advcsv:
    """Advanced CSV handling with encryption, compression, and validation."""

    @staticmethod
    def compress_csv(data: list, headers: list) -> str:
        """Compress CSV using Gzip and return base64 string."""
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(headers)
        writer.writerows(data)
        return base64.b64encode(gzip.compress(output.getvalue().encode())).decode()

    @staticmethod
    def decompress_csv(compressed_data: str) -> list:
        """Decompress base64 Gzip CSV string back to list of rows."""
        csv_content = gzip.decompress(base64.b64decode(compressed_data)).decode()
        reader = csv.reader(io.StringIO(csv_content))
        return [row for row in reader]

    @staticmethod
    def generate_key() -> str:
        """Generate a secure encryption key."""
        return Fernet.generate_key().decode()

    @staticmethod
    def encrypt_csv(data: list, headers: list, key: str) -> str:
        """Encrypt CSV data using AES encryption."""
        cipher = Fernet(key.encode())
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(headers)
        writer.writerows(data)
        return cipher.encrypt(output.getvalue().encode()).decode()

    @staticmethod
    def decrypt_csv(encrypted_data: str, key: str) -> list:
        """Decrypt AES encrypted CSV data."""
        cipher = Fernet(key.encode())
        decrypted_bytes = cipher.decrypt(encrypted_data.encode()).decode()
        reader = csv.reader(io.StringIO(decrypted_bytes))
        return [row for row in reader]

    @staticmethod
    def validate_csv(data: list, headers: list, schema: dict) -> bool:
        """Validate CSV data against a JSON schema."""
        json_data = [dict(zip(headers, row)) for row in data]
        try:
            jsonschema.validate(instance=json_data, schema=schema)
            return True
        except jsonschema.exceptions.ValidationError:
            return False

    @staticmethod
    def multi_threaded_compression(data_list: list, headers: list) -> list:
        """Perform multi-threaded CSV compression."""
        results = []
        lock = threading.Lock()

        def worker(data):
            compressed_value = advcsv.compress_csv(data, headers)
            with lock:
                results.append(compressed_value)

        threads = [threading.Thread(target=worker, args=(data,)) for data in data_list]
        for t in threads: t.start()
        for t in threads: t.join()

        return results

if __name__ == "__main__":
    sample_data = [["Brewlock", "admin"], ["User1", "viewer"]]
    headers = ["user", "role"]
    key = advcsv.generate_key()

    print("Testing advcsv...")
    compressed = advcsv.compress_csv(sample_data, headers)
    print("Compressed CSV:", compressed)
    print("Decompressed CSV:", advcsv.decompress_csv(compressed))

    encrypted = advcsv.encrypt_csv(sample_data, headers, key)
    print("Encrypted CSV:", encrypted)
    print("Decrypted CSV:", advcsv.decrypt_csv(encrypted, key))

    schema = {"type": "array", "items": {"type": "object", "properties": {"user": {"type": "string"}, "role": {"type": "string"}}}}
    print("CSV Schema Valid:", advcsv.validate_csv(sample_data, headers, schema))
