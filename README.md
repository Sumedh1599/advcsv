# advcsv

`advcsv` provides secure and optimized CSV handling with **AES encryption, Gzip compression, schema validation, and multi-threading**.

## Features

- **Gzip compression for efficient storage**
- **AES encryption for secure CSV storage**
- **CSV schema validation**
- **Multi-threaded CSV compression**
- **Automatic key generation**

## Installation

```bash
pip install advcsv

USAGE:
from advcsv import advcsv

data = [["Alice", "admin"], ["Bob", "user"]]
headers = ["name", "role"]
key = advcsv.generate_key()

compressed = advcsv.compress_csv(data, headers)
decompressed = advcsv.decompress_csv(compressed)

encrypted = advcsv.encrypt_csv(data, headers, key)
decrypted = advcsv.decrypt_csv(encrypted, key)

schema = {"type": "array", "items": {"type": "object", "properties": {"name": {"type": "string"}, "role": {"type": "string"}}}}
is_valid = advcsv.validate_csv(data, headers, schema)
```
