import base64
from Crypto.Cipher import Blowfish
from Crypto.Random import get_random_bytes
from crypto.algorithms.common import BLOWFISH_BLOCK_SIZE, pkcs7_pad, pkcs7_unpad

class BlowfishCipher:
    name = "BLOWFISH"

    def _prepare_key(self, key: str) -> bytes:
        key_bytes = key.encode("utf-8")
        if not (4 <= len(key_bytes) <= 56):
            raise ValueError("Blowfish anahtarı 4 ile 56 byte arasında olmalı.")
        return key_bytes

    def encrypt(self, plaintext: str, key: str) -> str:
        k = self._prepare_key(key)
        iv = get_random_bytes(BLOWFISH_BLOCK_SIZE)
        cipher = Blowfish.new(k, Blowfish.MODE_CBC, iv=iv)
        padded = pkcs7_pad(plaintext.encode("utf-8"), BLOWFISH_BLOCK_SIZE)
        ct = cipher.encrypt(padded)
        return base64.b64encode(iv + ct).decode("utf-8")

    def decrypt(self, ciphertext_b64: str, key: str) -> str:
        k = self._prepare_key(key)
        raw = base64.b64decode(ciphertext_b64)
        iv = raw[:BLOWFISH_BLOCK_SIZE]
        ct = raw[BLOWFISH_BLOCK_SIZE:]
        cipher = Blowfish.new(k, Blowfish.MODE_CBC, iv=iv)
        padded = cipher.decrypt(ct)
        plain = pkcs7_unpad(padded, BLOWFISH_BLOCK_SIZE)
        return plain.decode("utf-8")
