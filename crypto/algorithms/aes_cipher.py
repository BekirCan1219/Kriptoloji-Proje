from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

from crypto.algorithms.common import AES_BLOCK_SIZE, pkcs7_pad, pkcs7_unpad


class AESCipher:


    name = "aes"

    def encrypt(self, plaintext: str, key: str) -> str:
        key_bytes = key.encode("utf-8")
        if len(key_bytes) != 16:
            raise ValueError("AES-128 için anahtar uzunluğu 16 byte olmalı (16 karakter).")

        iv = get_random_bytes(AES_BLOCK_SIZE)
        cipher = AES.new(key_bytes, AES.MODE_CBC, iv=iv)

        padded = pkcs7_pad(plaintext.encode("utf-8"), AES_BLOCK_SIZE)
        ct = cipher.encrypt(padded)

        data = iv + ct
        return base64.b64encode(data).decode("utf-8")

    def decrypt(self, ciphertext_b64: str, key: str) -> str:
        key_bytes = key.encode("utf-8")
        if len(key_bytes) != 16:
            raise ValueError("AES-128 için anahtar uzunluğu 16 byte olmalı (16 karakter).")

        raw = base64.b64decode(ciphertext_b64)
        iv = raw[:AES_BLOCK_SIZE]
        ct = raw[AES_BLOCK_SIZE:]

        cipher = AES.new(key_bytes, AES.MODE_CBC, iv=iv)
        padded_plain = cipher.decrypt(ct)
        plain = pkcs7_unpad(padded_plain, AES_BLOCK_SIZE)
        return plain.decode("utf-8")
