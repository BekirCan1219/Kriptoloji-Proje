import base64
import hashlib
from Crypto.Util import number

PREFIX = b"MSG:"  # doğru çözümü seçmek için imza


def _bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, "big")


def _int_to_bytes(x: int) -> bytes:
    length = (x.bit_length() + 7) // 8
    return x.to_bytes(length, "big")


def _find_prime_3mod4(seed_bytes: bytes, bits: int = 128) -> int:
    """
    seed'den deterministik p ≡ 3 (mod 4) asal üret
    """
    x = int.from_bytes(seed_bytes, "big")
    x |= (1 << (bits - 1))  # bit sayısını sabitle, MSB = 1
    if x % 2 == 0:
        x += 1

    while True:
        if x % 4 == 3 and number.isPrime(x):
            return x
        x += 2  # tek sayılar


def _derive_primes_from_key(key: str):
    """
    Kullanıcı key'inden p ve q üret (ikisi de 3 mod 4).
    """
    base = hashlib.sha256(key.encode("utf-8")).digest()

    h1 = hashlib.sha256(base + b"p").digest()
    h2 = hashlib.sha256(base + b"q").digest()

    p = _find_prime_3mod4(h1, bits=128)
    q = _find_prime_3mod4(h2, bits=128)

    if p == q:
        # Çok nadir durum için ikinciyi farklılaştır
        h2b = hashlib.sha256(h2 + b"extra").digest()
        q = _find_prime_3mod4(h2b, bits=128)

    return p, q


class RabinCipher:
    name = "RABIN"

    def encrypt(self, plaintext: str, key: str) -> str:
        """
        Rabin şifreleme.
        Dönen değer: base64( str(c) ), yani string.
        """
        if not plaintext:
            return ""

        p, q = _derive_primes_from_key(key)
        n = p * q

        m_bytes = PREFIX + plaintext.encode("utf-8")
        m = _bytes_to_int(m_bytes)

        if m >= n:
            raise ValueError("Mesaj çok uzun. Daha kısa bir metin deneyin.")

        # c = m^2 mod n
        c = pow(m, 2, n)

        # Çok basit format: base64( str(c).encode() )
        c_str = str(c).encode("utf-8")
        return base64.b64encode(c_str).decode("utf-8")

    def decrypt(self, ciphertext: str, key: str) -> str:
        """
        Rabin çözme.
        ciphertext: encrypt'ten dönen base64 string.
        """
        if not ciphertext:
            return ""

        try:
            c_bytes = base64.b64decode(ciphertext.encode("utf-8"))
            c = int(c_bytes.decode("utf-8"))
        except Exception as ex:
            raise ValueError("Geçersiz Rabin şifreli metni.") from ex

        p, q = _derive_primes_from_key(key)
        n = p * q

        # mp = c^((p+1)/4) mod p
        mp = pow(c, (p + 1) // 4, p)
        # mq = c^((q+1)/4) mod q
        mq = pow(c, (q + 1) // 4, q)

        yp = number.inverse(p, q)
        yq = number.inverse(q, p)

        r1 = (yp * p * mq + yq * q * mp) % n
        r2 = n - r1
        r3 = (yp * p * mq - yq * q * mp) % n
        r4 = n - r3

        candidates = [r1, r2, r3, r4]

        for r in candidates:
            m_bytes = _int_to_bytes(r)
            if m_bytes.startswith(PREFIX):
                msg_bytes = m_bytes[len(PREFIX):]
                try:
                    return msg_bytes.decode("utf-8")
                except UnicodeDecodeError:
                    continue

        raise ValueError("Rabin çözme başarısız. Anahtarı veya metni kontrol et.")
