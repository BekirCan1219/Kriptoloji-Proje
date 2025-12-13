# crypto/algorithms/ecc_cipher.py

import base64
import hashlib

# secp256k1 parametreleri
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
A = 0
B = 7
Gx = 55066263022277343669578718895168534326250603453777594175500187360389116729240
Gy = 32670510020758816978083085130507043184471273380659243275938904335757337482424
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141  # G'nin mertebesi

INFINITY = None  # Sonsuz nokta


def _inv_mod(x: int, p: int) -> int:
    return pow(x, p - 2, p)


def _point_add(P1, P2):
    if P1 is INFINITY:
        return P2
    if P2 is INFINITY:
        return P1

    x1, y1 = P1
    x2, y2 = P2

    if x1 == x2 and (y1 != y2 or y1 == 0):
        return INFINITY

    if P1 == P2:
        # doubling
        l = (3 * x1 * x1 + A) * _inv_mod(2 * y1 % P, P) % P
    else:
        l = (y2 - y1) * _inv_mod((x2 - x1) % P, P) % P

    x3 = (l * l - x1 - x2) % P
    y3 = (l * (x1 - x3) - y1) % P
    return (x3, y3)


def _scalar_mult(k: int, Pnt):
    result = INFINITY
    addend = Pnt

    while k > 0:
        if k & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        k >>= 1
    return result


def _derive_private(key: str) -> int:
    h = hashlib.sha256(key.encode("utf-8")).digest()
    d = int.from_bytes(h, "big") % (N - 1) + 1
    return d


def _derive_shared(d: int) -> int:
    # paylaşılan sır: d * G (ECDH'de karşı tarafın public'i olurdu)
    P_shared = _scalar_mult(d, (Gx, Gy))
    if P_shared is INFINITY:
        raise ValueError("ECC paylaşılan nokta sonsuz nokta oldu.")
    x_shared, _ = P_shared
    return x_shared


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


class ECCCipher:
    name = "ECC"

    def encrypt(self, plaintext: str, key: str) -> str:
        """
        ECC (secp256k1) tabanlı ortak sır + XOR stream cipher.
        """
        if not plaintext:
            return ""

        d = _derive_private(key)
        shared = _derive_shared(d)

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
            raise ValueError("Geçersiz ECC şifreli metni.") from ex

        d = _derive_private(key)
        shared = _derive_shared(d)

        ks = _keystream_from_int(shared, len(ct))
        pt = bytes(c ^ k for c, k in zip(ct, ks))

        try:
            return pt.decode("utf-8")
        except UnicodeDecodeError:
            raise ValueError("ECC çözümlemesinde UTF-8 hatası. Anahtarı kontrol edin.")
