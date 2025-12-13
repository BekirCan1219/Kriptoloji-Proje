import base64
from Crypto.Cipher import ARC2
from Crypto.Random import get_random_bytes
from crypto.algorithms.common import RC2_BLOCK_SIZE, pkcs7_pad, pkcs7_unpad

class RC2Cipher:
    name = "RC2"

    def _prepare_key(self, key: str) -> bytes:
        key_bytes = key.encode("utf-8")
        if not (5 <= len(key_bytes) <= 16):
            raise ValueError("RC2 anahtarı 5 ile 16 byte arasında olmalı.")
        return key_bytes

    def encrypt(self, plaintext: str, key: str) -> str:
        k = self._prepare_key(key)
        iv = get_random_bytes(RC2_BLOCK_SIZE)
        cipher = ARC2.new(k, ARC2.MODE_CBC, iv=iv)
        padded = pkcs7_pad(plaintext.encode("utf-8"), RC2_BLOCK_SIZE)
        ct = cipher.encrypt(padded)
        return base64.b64encode(iv + ct).decode("utf-8")

    def decrypt(self, ciphertext_b64: str, key: str) -> str:
        k = self._prepare_key(key)
        raw = base64.b64decode(ciphertext_b64)
        iv = raw[:RC2_BLOCK_SIZE]
        ct = raw[RC2_BLOCK_SIZE:]
        cipher = ARC2.new(k, ARC2.MODE_CBC, iv=iv)
        padded = cipher.decrypt(ct)
        plain = pkcs7_unpad(padded, RC2_BLOCK_SIZE)
        return plain.decode("utf-8")
