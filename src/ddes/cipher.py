import hashlib
import random
from typing import List

from . import tables
from . import utils

class DDESCipher:
    def __init__(self, key: bytes, mode: str = 'ECB', iv: bytes = None):
        """
        Initializes the D-DES cipher with a given 8-byte key.
        """
        if len(key) != 8:
            raise ValueError("Key must be exactly 8 bytes (64 bits)")
        if mode not in ('ECB', 'CBC'):
            raise ValueError("Mode must be 'ECB' or 'CBC'")
        if mode == 'CBC':
            if iv is None or len(iv) != 8:
                raise ValueError("CBC mode requires exactly an 8-byte IV")
            self.iv = iv
        else:
            self.iv = None
            
        self.mode = mode
        self.key_int = int.from_bytes(key, byteorder='big')
        self.subkeys = self._generate_subkeys()
        self.sbox = self._generate_dynamic_sbox(key)

    def _generate_dynamic_sbox(self, key: bytes) -> List[int]:
        """
        Generate one single 6x4 S-box (64 entries total, values 0-15) based on the key.
        """
        # Derive a seed from the key using SHA-256
        seed = int(hashlib.sha256(key).hexdigest(), 16)
        
        # We need a 64-entry S-box with values 0-15.
        # A typical S-box has 4 rows of 16 columns. 
        # For our dynamic S-box, we'll create an array of 64 elements,
        # consisting of exactly four 0s, four 1s, ..., four 15s.
        sbox = [i % 16 for i in range(64)]
        
        # Shuffle the S-box deterministically using the derived seed
        r = random.Random(seed)
        r.shuffle(sbox)
        
        return sbox

    def _generate_subkeys(self) -> List[int]:
        """
        Generate the 16 48-bit subkeys using the standard DES key schedule.
        """
        subkeys = []
        
        # Apply PC-1 to the 64-bit key
        pc1_out = utils.permute(self.key_int, tables.PC_1, 64, 56)
        
        # Split into two 28-bit halves
        c, d = utils.split_half(pc1_out, 56)
        
        for shift in tables.SHIFTS:
            # Circular left shift each half
            c = utils.left_shift(c, shift, 28)
            d = utils.left_shift(d, shift, 28)
            
            # Merge halves
            cd = utils.merge_half(c, d, 28)
            
            # Apply PC-2
            subkey = utils.permute(cd, tables.PC_2, 56, 48)
            subkeys.append(subkey)
            
        return subkeys

    def _feistel(self, right_half: int, subkey: int) -> int:
        """
        The core Feistel function f(R, K).
        """
        # 1. Expansion P-box
        expanded = utils.permute(right_half, tables.E, 32, 48)
        
        # 2. Key mixing
        xored = expanded ^ subkey
        
        # 3. Dynamic S-box substitution
        # Split 48 bits into 8 6-bit blocks, pass each through the same single S-box
        sbox_out = 0
        for i in range(8):
            # Extract 6 bits from left to right
            shift_amount = 48 - 6 * (i + 1)
            six_bit_block = (xored >> shift_amount) & 0x3F
            
            # Use the 6 bits as an index into our 64-entry dynamic S-box
            four_bit_out = self.sbox[six_bit_block]
            
            # Append to the 32-bit output
            sbox_out |= (four_bit_out << (32 - 4 * (i + 1)))
            
        # 4. Permutation
        return utils.permute(sbox_out, tables.P, 32, 32)

    def _process_block(self, block: bytes, decrypt: bool = False) -> bytes:
        """
        Encrypts or decrypts a single 64-bit block.
        """
        if len(block) != 8:
            raise ValueError("Block must be exactly 8 bytes (64 bits)")
            
        block_int = int.from_bytes(block, byteorder='big')
        
        # Initial Permutation (IP)
        ip_out = utils.permute(block_int, tables.IP, 64, 64)
        
        # Split into 32-bit halves
        left, right = utils.split_half(ip_out, 64)
        
        # 16 Feistel rounds
        # Decryption uses subkeys in reverse order (K16 to K1)
        subkeys = self.subkeys[::-1] if decrypt else self.subkeys
        
        for subkey in subkeys:
            next_left = right
            next_right = left ^ self._feistel(right, subkey)
            left, right = next_left, next_right
            
        # Swap halves after the 16th round (before final permutation)
        pre_output = utils.merge_half(right, left, 32)
        
        # Final Permutation (IP-1)
        final_out = utils.permute(pre_output, tables.IP_INV, 64, 64)
        
        return final_out.to_bytes(8, byteorder='big')

    def encrypt(self, data: bytes) -> bytes:
        """
        Encrypt data using D-DES (ECB or CBC mode with PKCS#7 padding).
        """
        # PKCS7 padding
        pad_len = 8 - (len(data) % 8)
        padded_data = data + bytes([pad_len] * pad_len)
        
        ciphertext = bytearray()
        prev_block = self.iv
        
        for i in range(0, len(padded_data), 8):
            block = padded_data[i:i+8]
            
            if self.mode == 'CBC':
                # XOR plaintext block with previous ciphertext block (or IV)
                block = bytes(a ^ b for a, b in zip(block, prev_block))
                
            enc_block = self._process_block(block, decrypt=False)
            ciphertext.extend(enc_block)
            prev_block = enc_block
            
        return bytes(ciphertext)

    def decrypt(self, data: bytes) -> bytes:
        """
        Decrypt data using D-DES (ECB or CBC mode with PKCS#7 unpadding).
        """
        if len(data) % 8 != 0:
            raise ValueError("Ciphertext length must be a multiple of 8 bytes")
            
        plaintext = bytearray()
        prev_block = self.iv
        
        for i in range(0, len(data), 8):
            block = data[i:i+8]
            dec_block = self._process_block(block, decrypt=True)
            
            if self.mode == 'CBC':
                # XOR decrypted block with previous ciphertext block (or IV)
                dec_block = bytes(a ^ b for a, b in zip(dec_block, prev_block))
                prev_block = block
                
            plaintext.extend(dec_block)
            
        # PKCS7 unpadding
        pad_len = plaintext[-1]
        if pad_len < 1 or pad_len > 8:
            raise ValueError("Invalid padding detected during decryption.")
            
        return bytes(plaintext[:-pad_len])
