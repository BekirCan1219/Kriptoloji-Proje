from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes
import base64

from crypto.algorithms.common import DES_BLOCK_SIZE, pkcs7_pad, pkcs7_unpad


class DESCipher:
    """
    DES CBC için basit sarmalayıcı sınıf.
    key: 8 byte (8 karakter) olmalı.
    """

    name = "des"

    def encrypt(self, plaintext: str, key: str) -> str:
        key_bytes = key.encode("utf-8")
        if len(key_bytes) != 8:
            raise ValueError("DES için anahtar uzunluğu 8 byte (8 karakter) olmalı.")

        iv = get_random_bytes(DES_BLOCK_SIZE)
        cipher = DES.new(key_bytes, DES.MODE_CBC, iv=iv)

        padded = pkcs7_pad(plaintext.encode("utf-8"), DES_BLOCK_SIZE)
        ct = cipher.encrypt(padded)

        data = iv + ct
        return base64.b64encode(data).decode("utf-8")

    def decrypt(self, ciphertext_b64: str, key: str) -> str:
        key_bytes = key.encode("utf-8")
        if len(key_bytes) != 8:
            raise ValueError("DES için anahtar uzunluğu 8 byte (8 karakter) olmalı.")

        raw = base64.b64decode(ciphertext_b64)
        iv = raw[:DES_BLOCK_SIZE]
        ct = raw[DES_BLOCK_SIZE:]

        cipher = DES.new(key_bytes, DES.MODE_CBC, iv=iv)
        padded_plain = cipher.decrypt(ct)
        plain = pkcs7_unpad(padded_plain, DES_BLOCK_SIZE)
        return plain.decode("utf-8")
