from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

key_pair = RSA.generate(2048)
public_key = key_pair.publickey()

_private_cipher = PKCS1_OAEP.new(key_pair)
_public_cipher = PKCS1_OAEP.new(public_key)


def rsa_encrypt(plaintext: str) -> str:
    """
    RSA Public Key ile şifreleme
    """
    data = plaintext.encode("utf-8")
    ct = _public_cipher.encrypt(data)
    return base64.b64encode(ct).decode("utf-8")


def rsa_decrypt(ciphertext_b64: str) -> str:
    """
    RSA Private Key ile çözme
    """
    raw = base64.b64decode(ciphertext_b64)
    pt = _private_cipher.decrypt(raw)
    return pt.decode("utf-8")
