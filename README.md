# D-DES (Dynamic Data Encryption Standard)

> **⚠️ Security Disclaimer:** This is an experimental cryptographic tool for research and educational purposes. It is not intended for securing sensitive production data.

D-DES is a custom implementation of the classic DES (Data Encryption Standard) block cipher, modified to feature a **Dynamic S-Box**. 

## Requirements
- **Python 3.8+**: This library leverages Python type hinting and bit-manipulation features. Ensure you are running Python 3.8 or higher.

## Features
- Standard 64-bit block size and 56-bit effective key.
- 16 Feistel rounds with standard permutation tables (IP, IP-1, E, P, PC-1, PC-2).
- **Dynamic S-Box**: Replaces the 8 static S-boxes with a single, dynamically generated $6 \times 4$ S-box completely seeded by the encryption key.
- **CBC Mode Support**: Prevents repeating data blocks by utilizing an Initialization Vector (IV).
- **PKCS#7 Padding**: Safely encrypts and decrypts files of any arbitrary size.
- **CLI Utility**: Built-in command line interface to seamlessly encrypt/decrypt any file on your computer.
- **Operational Logger**: Automatically and securely logs operation metadata to a `logs.json` file without leaking secrets or plaintext.

## Installation

You can install the package directly from PyPI. In your terminal, run:
```bash
pip install ddes-dua-crypto
```

## CLI Usage

The package installs a globally available `ddes-cli` tool. 

**To encrypt a file (CBC mode):**
```bash
ddes-cli encrypt -k "8bytekey" -m CBC --iv "8byte_iv" -i plaintext.txt -o encrypted.bin
```

**To decrypt a file:**
```bash
ddes-cli decrypt -k "8bytekey" -m CBC --iv "8byte_iv" -i encrypted.bin -o decrypted.txt
```

## Python API Usage

You can also use the cipher directly inside your own Python projects.

```python
from ddes import DDESCipher

# 8-byte key and IV
key = b'8bytekey'
iv = b'8byte_iv'

# Initialize in CBC mode
cipher = DDESCipher(key, mode='CBC', iv=iv)

# Encrypt
plaintext = b'Hello World! This is D-DES.'
ciphertext = cipher.encrypt(plaintext)
print(f"Ciphertext (Hex): {ciphertext.hex()}")

# Decrypt
decrypted = cipher.decrypt(ciphertext)
print(f"Decrypted: {decrypted.decode('utf-8')}")
```

## Operational Logger
All CLI encryption and decryption commands automatically append an audit trail to `logs.json`. The logger securely stores the timestamp, operation type, mode, and success status. **It never stores keys or file contents.**

**Example Audit Log (`logs.json`):**
```json
[
    {
        "timestamp": "2026-05-08T19:02:15.123456",
        "operation": "Encrypt",
        "mode": "CBC",
        "status": "Success"
    }
]
```
