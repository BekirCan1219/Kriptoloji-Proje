from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

class RSACipher:
    def __init__(self):
        self._key_pair = RSA.generate(2048)
        self._public_key = self._key_pair.publickey()
        self._private_cipher = PKCS1_OAEP.new(self._key_pair)
        self._public_cipher = PKCS1_OAEP.new(self._public_key)

    def get_public_key_pem(self):
        return self._public_key.export_key().decode("utf-8")

    def encrypt(self, plaintext: str, key=None):
        data = plaintext.encode("utf-8")
        ct = self._public_cipher.encrypt(data)
        return base64.b64encode(ct).decode("utf-8")

    def decrypt(self, ciphertext_b64: str, key=None):
        raw = base64.b64decode(ciphertext_b64)
        pt = self._private_cipher.decrypt(raw)
        return pt.decode("utf-8")
