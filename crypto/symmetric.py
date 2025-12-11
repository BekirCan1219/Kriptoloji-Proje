from Crypto.Cipher import AES, DES
from Crypto.Random import get_random_bytes
import base64


AES_BLOCK_SIZE = 16
DES_BLOCK_SIZE = 8

def _pkcs7_pad(data: bytes, block_size: int = AES_BLOCK_SIZE) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len


def _pkcs7_unpad(data: bytes, block_size: int = AES_BLOCK_SIZE) -> bytes:
    pad_len = data[-1]
    if pad_len < 1 or pad_len > block_size:
        raise ValueError("Geçersiz padding")
    return data[:-pad_len]


def aes_encrypt(plaintext: str, key: str) -> str:

    key_bytes = key.encode("utf-8")
    if len(key_bytes) != 16:
        raise ValueError("AES-128 için anahtar uzunluğu 16 byte olmalı (16 karakter).")

    iv = get_random_bytes(AES_BLOCK_SIZE)
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv=iv)

    padded = _pkcs7_pad(plaintext.encode("utf-8"), AES_BLOCK_SIZE)
    ct = cipher.encrypt(padded)

    data = iv + ct
    return base64.b64encode(data).decode("utf-8")


def aes_decrypt(ciphertext_b64: str, key: str) -> str:

    key_bytes = key.encode("utf-8")
    if len(key_bytes) != 16:
        raise ValueError("AES-128 için anahtar uzunluğu 16 byte olmalı (16 karakter).")

    raw = base64.b64decode(ciphertext_b64)
    iv = raw[:AES_BLOCK_SIZE]
    ct = raw[AES_BLOCK_SIZE:]

    cipher = AES.new(key_bytes, AES.MODE_CBC, iv=iv)
    padded_plain = cipher.decrypt(ct)
    plain = _pkcs7_unpad(padded_plain, AES_BLOCK_SIZE)
    return plain.decode("utf-8")


def des_encrypt(plaintext: str, key: str) -> str:

    key_bytes = key.encode("utf-8")
    if len(key_bytes) != 8:
        raise ValueError("DES için anahtar uzunluğu 8 byte (8 karakter) olmalı.")

    iv = get_random_bytes(DES_BLOCK_SIZE)
    cipher = DES.new(key_bytes, DES.MODE_CBC, iv=iv)

    padded = _pkcs7_pad(plaintext.encode("utf-8"), DES_BLOCK_SIZE)
    ct = cipher.encrypt(padded)

    data = iv + ct
    return base64.b64encode(data).decode("utf-8")


def des_decrypt(ciphertext_b64: str, key: str) -> str:
    key_bytes = key.encode("utf-8")
    if len(key_bytes) != 8:
        raise ValueError("DES için anahtar uzunluğu 8 byte (8 karakter) olmalı.")

    raw = base64.b64decode(ciphertext_b64)
    iv = raw[:DES_BLOCK_SIZE]
    ct = raw[DES_BLOCK_SIZE:]

    cipher = DES.new(key_bytes, DES.MODE_CBC, iv=iv)
    padded_plain = cipher.decrypt(ct)
    plain = _pkcs7_unpad(padded_plain, DES_BLOCK_SIZE)
    return plain.decode("utf-8")