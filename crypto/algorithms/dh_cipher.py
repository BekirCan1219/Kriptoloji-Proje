# crypto/algorithms/dh_cipher.py

import base64
import hashlib

# RFC 3526'dan kısaltılmış 1024-bit MODP grup (demo için)
P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF",
    16,
)
G = 2

# Sunucu tarafının sabit private key'i (sadece ortak sırrı üretmek için)
B_PRIV = 0x123456789ABCDEF123456789ABCDEF123456789
B_PUB = pow(G, B_PRIV, P)


def _derive_private(key: str) -> int:
    h = hashlib.sha256(key.encode("utf-8")).digest()
    a = int.from_bytes(h, "big") % (P - 2) + 1
    return a


def _derive_shared(a: int) -> int:
    # paylaşılan sır: (g^b)^a mod p
    return pow(B_PUB, a, P)


def _keystream_from_int(shared: int, length: int) -> bytes:
    if shared == 0:
        shared = 1
    s_bytes = shared.to_bytes((shared.bit_length() + 7) // 8 or 1, "big")
    out = b""
    counter = 0
    while len(out) < length:
        out += hashlib.sha256(s_bytes + counter.to_bytes(4, "big")).digest()
        counter += 1
    return out[:length]


class DHCipher:
    name = "DH"

    def encrypt(self, plaintext: str, key: str) -> str:
        """
        DH tabanlı ortak sır + XOR stream cipher.
        """
        if not plaintext:
            return ""

        a = _derive_private(key)
        shared = _derive_shared(a)

        pt = plaintext.encode("utf-8")
        ks = _keystream_from_int(shared, len(pt))
        ct = bytes(p ^ k for p, k in zip(pt, ks))

        return base64.b64encode(ct).decode("utf-8")

    def decrypt(self, ciphertext: str, key: str) -> str:
        """
        Aynı ortak sır ile XOR geri al.
        """
        if not ciphertext:
            return ""

        try:
            ct = base64.b64decode(ciphertext.encode("utf-8"))
        except Exception as ex:
            raise ValueError("Geçersiz DH şifreli metin.") from ex

        a = _derive_private(key)
        shared = _derive_shared(a)

        ks = _keystream_from_int(shared, len(ct))
        pt = bytes(c ^ k for c, k in zip(ct, ks))

        try:
            return pt.decode("utf-8")
        except UnicodeDecodeError:
            raise ValueError("DH çözümlemesinde UTF-8 hatası. Anahtarı kontrol edin.")
