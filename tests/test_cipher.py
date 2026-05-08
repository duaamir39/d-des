import unittest
from ddes.cipher import DDESCipher

class TestDDES(unittest.TestCase):
    def test_encryption_decryption_ecb(self):
        key = b'secret!!'
        cipher = DDESCipher(key, mode='ECB')
        
        plaintext = b'Cryptography is fascinating!'
        ciphertext = cipher.encrypt(plaintext)
        
        self.assertNotEqual(plaintext, ciphertext)
        
        decrypted = cipher.decrypt(ciphertext)
        self.assertEqual(plaintext, decrypted)

    def test_encryption_decryption_cbc(self):
        key = b'secret!!'
        iv = b'init_vec'
        cipher = DDESCipher(key, mode='CBC', iv=iv)
        
        plaintext = b'Cryptography is fascinating! CBC mode is secure.'
        ciphertext = cipher.encrypt(plaintext)
        
        self.assertNotEqual(plaintext, ciphertext)
        
        decrypted = cipher.decrypt(ciphertext)
        self.assertEqual(plaintext, decrypted)
        
    def test_different_keys_different_sboxes(self):
        key1 = b'key_one!'
        key2 = b'key_two!'
        
        cipher1 = DDESCipher(key1)
        cipher2 = DDESCipher(key2)
        
        # Since the keys are different, their seeds are different,
        # and therefore the shuffled S-boxes should be highly likely to differ.
        self.assertNotEqual(cipher1.sbox, cipher2.sbox)

if __name__ == '__main__':
    unittest.main()
