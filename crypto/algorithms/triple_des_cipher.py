import base64
from Crypto.Cipher import DES3
from Crypto.Random import get_random_bytes
from crypto.algorithms.common import TRIPLE_DES_BLOCK_SIZE, pkcs7_pad, pkcs7_unpad

class TripleDESCipher:
    name = "3DES"

    def _prepare_key(self, key: str) -> bytes:
        key_bytes = key.encode("utf-8")
        if len(key_bytes) not in (16, 24):
            raise ValueError("3DES için anahtar uzunluğu 16 veya 24 byte olmalı.")
        return DES3.adjust_key_parity(key_bytes)

    def encrypt(self, plaintext: str, key: str) -> str:
        k = self._prepare_key(key)
        iv = get_random_bytes(TRIPLE_DES_BLOCK_SIZE)
        cipher = DES3.new(k, DES3.MODE_CBC, iv=iv)
        padded = pkcs7_pad(plaintext.encode("utf-8"), TRIPLE_DES_BLOCK_SIZE)
        ct = cipher.encrypt(padded)
        return base64.b64encode(iv + ct).decode("utf-8")

    def decrypt(self, ciphertext_b64: str, key: str) -> str:
        k = self._prepare_key(key)
        raw = base64.b64decode(ciphertext_b64)
        iv = raw[:TRIPLE_DES_BLOCK_SIZE]
        ct = raw[TRIPLE_DES_BLOCK_SIZE:]
        cipher = DES3.new(k, DES3.MODE_CBC, iv=iv)
        padded = cipher.decrypt(ct)
        plain = pkcs7_unpad(padded, TRIPLE_DES_BLOCK_SIZE)
        return plain.decode("utf-8")
