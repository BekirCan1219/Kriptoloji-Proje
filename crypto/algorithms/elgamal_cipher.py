import base64
import json
import hashlib

from Crypto.Util import number
from Crypto.Random import get_random_bytes


# Sabit büyük bir asal (örnek amaçlı, gerçek hayatta daha da büyük seçilir)
P = int(
    "208351617316091241234326746312124448251235562226470491514186331217050270460481"
)
G = 2  # üreteç


def _derive_private_key(key_str: str) -> int:
    """
    Kullanıcının girdiği string key'den deterministik şekilde
    özel anahtar (x) üretir.
    """
    h = hashlib.sha256(key_str.encode("utf-8")).digest()
    x = int.from_bytes(h, "big") % (P - 2) + 1
    return x


class ElGamalCipher:
    name = "ELGAMAL"

    def encrypt(self, plaintext: str, key: str) -> str:
        """
        El-Gamal ile şifreleme.
        plaintext: normal metin (str)
        key: kullanıcı anahtarı (str)
        return: base64(JSON(c1, c2)) şeklinde string
        """
        if not plaintext:
            return ""

        # Mesajı integer'a çevir
        m_bytes = plaintext.encode("utf-8")
        m = int.from_bytes(m_bytes, "big")

        if m >= P:
            raise ValueError(
                "Mesaj çok uzun. ElGamal için daha kısa bir metin deneyin."
            )

        # Özel ve açık anahtar
        x = _derive_private_key(key)
        y = pow(G, x, P)  # public key

        # Rastgele k seç
        k = number.getRandomRange(1, P - 1)

        # c1 = g^k mod p
        c1 = pow(G, k, P)
        # s = y^k mod p
        s = pow(y, k, P)
        # c2 = m * s mod p
        c2 = (m * s) % P

        cipher_obj = {"c1": str(c1), "c2": str(c2)}
        cipher_json = json.dumps(cipher_obj).encode("utf-8")
        cipher_b64 = base64.b64encode(cipher_json).decode("utf-8")
        return cipher_b64

    def decrypt(self, ciphertext: str, key: str) -> str:
        """
        El-Gamal ile çözme.
        ciphertext: encrypt'ten dönen base64(JSON(c1,c2)) string'i
        key: kullanıcı anahtarı (str)
        return: çözümlenmiş plaintext (str)
        """
        if not ciphertext:
            return ""

        try:
            cipher_json = base64.b64decode(ciphertext.encode("utf-8"))
            cipher_obj = json.loads(cipher_json.decode("utf-8"))
            c1 = int(cipher_obj["c1"])
            c2 = int(cipher_obj["c2"])
        except Exception as ex:
            raise ValueError("Geçersiz ElGamal şifreli metni.") from ex

        x = _derive_private_key(key)

        # s = c1^x mod p
        s = pow(c1, x, P)
        # s^-1 mod p
        s_inv = number.inverse(s, P)

        # m = c2 * s^-1 mod p
        m = (c2 * s_inv) % P

        # integer -> bytes -> str
        m_len = (m.bit_length() + 7) // 8
        m_bytes = m.to_bytes(m_len, "big")
        try:
            plaintext = m_bytes.decode("utf-8")
        except UnicodeDecodeError:
            raise ValueError("ElGamal çözümlemesinde UTF-8 hatası (yanlış anahtar?).")

        return plaintext
