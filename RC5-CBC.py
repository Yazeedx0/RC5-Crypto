import base64
import os
from io import BytesIO


class RC5(object):
    def __init__(self, key):
        self.mode = 'CBC'  # "ECB" or "CBC"
        self.blocksize = 32 # 32, 64 , 128
        self.rounds = 12
        self.iv = os.urandom(self.blocksize // 8)
        self._key = key.encode('utf-8')

    @staticmethod
    def _rotate_left(val, r_bits, max_bits):
        v1 = (val << r_bits % max_bits) & (2 ** max_bits - 1)
        v2 = ((val & (2 ** max_bits - 1)) >> (max_bits - (r_bits % max_bits)))
        return v1 | v2

    @staticmethod
    def _rotate_right(val, r_bits, max_bits):
        v1 = ((val & (2 ** max_bits - 1)) >> r_bits % max_bits)
        v2 = (val << (max_bits - (r_bits % max_bits)) & (2 ** max_bits - 1))

        return v1 | v2

    @staticmethod
    def _expand_key(key, wordsize, rounds):
        # Pads _key so that it is aligned with the word size, then splits it into words
        def _align_key(key, align_val):
            while len(key) % (align_val):
                key += b'\x00'  # Add 0 bytes until the _key length is aligned to the block size

            L = []
            for i in range(0, len(key), align_val):
                L.append(int.from_bytes(key[i:i + align_val], byteorder='little'))

            return L

        # generation function of the constants for the extend step
        def _const(w):
            if w == 16:
                return (0xB7E1, 0x9E37)  # Returns the value of P and Q
            elif w == 32:
                return (0xB7E15163, 0x9E3779B9)
            elif w == 64:
                return (0xB7E151628AED2A6B, 0x9E3779B97F4A7C15)

        # Generate pseudo-random list S
        def _extend_key(w, r):
            P, Q = _const(w)
            S = [P]
            t = 2 * (r + 1)
            for i in range(1, t):
                S.append((S[i - 1] + Q) % 2 ** w)

            return S

        def _mix(L, S, r, w, c):
            t = 2 * (r + 1)
            m = max(c, t)
            A = B = i = j = 0

            for k in range(3 * m):
                A = S[i] = RC5._rotate_left(S[i] + A + B, 3, w)
                B = L[j] = RC5._rotate_left(L[j] + A + B, A + B, w)

                i = (i + 1) % t
                j = (j + 1) % c

            return S

        aligned = _align_key(key, wordsize // 8)
        extended = _extend_key(wordsize, rounds)

        S = _mix(aligned, extended, rounds, wordsize, len(aligned))

        return S

    @staticmethod
    def _encrypt_block(data, expanded_key, blocksize, rounds):
        w = blocksize // 2
        b = blocksize // 8
        mod = 2 ** w

        A = int.from_bytes(data[:b // 2], byteorder='little')
        B = int.from_bytes(data[b // 2:], byteorder='little')

        A = (A + expanded_key[0]) % mod
        B = (B + expanded_key[1]) % mod

        for i in range(1, rounds + 1):
            A = (RC5._rotate_left((A ^ B), B, w) + expanded_key[2 * i]) % mod
            B = (RC5._rotate_left((A ^ B), A, w) + expanded_key[2 * i + 1]) % mod

        res = A.to_bytes(b // 2, byteorder='little') + B.to_bytes(b // 2, byteorder='little')
        return res

    @staticmethod
    def _decrypt_block(data, expanded_key, blocksize, rounds):
        w = blocksize // 2
        b = blocksize // 8
        mod = 2 ** w

        A = int.from_bytes(data[:b // 2], byteorder='little')
        B = int.from_bytes(data[b // 2:], byteorder='little')

        for i in range(rounds, 0, -1):
            B = RC5._rotate_right(B - expanded_key[2 * i + 1], A, w) ^ A
            A = RC5._rotate_right((A - expanded_key[2 * i]), B, w) ^ B

        B = (B - expanded_key[1]) % mod
        A = (A - expanded_key[0]) % mod

        res = A.to_bytes(b // 2, byteorder='little') + B.to_bytes(b // 2, byteorder='little')
        return res

    def encrypt_text(self, input_text):
        w = self.blocksize // 2
        b = self.blocksize // 8

        if self.mode == 'CBC':
            last_v = self.iv

        expanded_key = RC5._expand_key(self._key, w, self.rounds)

        encrypted_text = []
        input_text = input_text.encode('utf-8')  # Encode the input text to bytes

        # Read in chunks of blocksize bytes
        for i in range(0, len(input_text), b):
            chunk = input_text[i:i + b]
            chunk = chunk.ljust(b, b'\x00') 
            if self.mode == 'CBC':
                chunk = bytes([a ^ b for a, b in zip(last_v, chunk)])

            encrypted_chunk = RC5._encrypt_block(chunk, expanded_key, self.blocksize, self.rounds)
            encrypted_text.append(encrypted_chunk)

            last_v = encrypted_chunk  # Update IV in CBC mode

        return base64.urlsafe_b64encode(b''.join(encrypted_text)).decode('utf-8')

    def decrypt_text(self, encrypted_text):
        w = self.blocksize // 2
        b = self.blocksize // 8

        encrypted_bytes = base64.urlsafe_b64decode(encrypted_text)

        if self.mode == 'CBC':
            last_v = self.iv

        expanded_key = RC5._expand_key(self._key, w, self.rounds)

        decrypted_text = []
        for i in range(0, len(encrypted_bytes), b):
            chunk = encrypted_bytes[i:i + b]
            decrypted_chunk = RC5._decrypt_block(chunk, expanded_key, self.blocksize, self.rounds)
            if self.mode == 'CBC':
                decrypted_chunk = bytes([a ^ b for a, b in zip(last_v, decrypted_chunk)])
                last_v = chunk

            decrypted_text.append(decrypted_chunk)

        decrypted_bytes = b''.join(decrypted_text)
        return decrypted_bytes.rstrip(b'\x00').decode('utf-8')  

# Example usage:
key = "rwrefewre23"  
rc5 = RC5(key)

# Encrypt and decrypt text
input_text = "Hello, this is a test message!"

encrypted_text = rc5.encrypt_text(input_text)
print(f"Encrypted text: {encrypted_text}")

decrypted_text = rc5.decrypt_text(encrypted_text)
print(f"Decrypted text: {decrypted_text}")
