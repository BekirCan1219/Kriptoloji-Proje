import base64
import json
import hashlib
from Crypto.Util import number

# Küçük bir örnek DSA domain parametresi (eğitim amaçlı)
P = 20361301855847825643451976956702431131989244915039
Q = 925513720720355711065998952577383233272238405229
G = 4194304  # g^Q mod P = 1 olacak şekilde seçilmiş


def _derive_private_key(key: str) -> int:
    """
    Kullanıcı key'inden deterministik DSA private key (x) üret.
    1 <= x <= Q-1
    """
    h = hashlib.sha256(key.encode("utf-8")).digest()
    x = int.from_bytes(h, "big") % (Q - 1) + 1
    return x


def _derive_k(key: str, message: str) -> int:
    """
    Deterministik k üret (her mesaj için). Gerçekte rastgele olmalı ama
    derste ve demo için deterministik yapıyoruz.
    """
    h = hashlib.sha256((key + "|k|" + message).encode("utf-8")).digest()
    k = int.from_bytes(h, "big") % (Q - 1) + 1
    # gcd(k, Q) = 1 olmasını sağla
    while number.GCD(k, Q) != 1:
        k = (k + 1) % (Q - 1)
        if k == 0:
            k = 1
    return k


class DSACipher:
    name = "DSA"

    def encrypt(self, plaintext: str, key: str) -> str:
        """
        DSA ile "imzalama" yapıyoruz. Ciphertext içinde:
        - m: mesaj (plaintext)
        - r, s: DSA imza bileşenleri

        Dönen değer: base64(JSON) string
        """
        if not plaintext:
            return ""

        x = _derive_private_key(key)
        y = pow(G, x, P)  # public key (istemesek de hesaplıyoruz)

        # Mesajın hash'i
        h_m = hashlib.sha256(plaintext.encode("utf-8")).digest()
        h_int = int.from_bytes(h_m, "big") % Q

        k = _derive_k(key, plaintext)
        r = pow(G, k, P) % Q
        k_inv = number.inverse(k, Q)
        s = (k_inv * (h_int + x * r)) % Q

        obj = {
            "m": plaintext,
            "r": str(r),
            "s": str(s)
        }
        data = json.dumps(obj).encode("utf-8")
        return base64.b64encode(data).decode("utf-8")

    def decrypt(self, ciphertext: str, key: str) -> str:
        """
        Ciphertext içindeki imzayı doğrular. Geçerliyse mesajı döner,
        geçersizse hata fırlatır.
        """
        if not ciphertext:
            return ""

        try:
            data = base64.b64decode(ciphertext.encode("utf-8"))
            obj = json.loads(data.decode("utf-8"))
            m = obj["m"]
            r = int(obj["r"])
            s = int(obj["s"])
        except Exception as ex:
            raise ValueError("Geçersiz DSA verisi.") from ex

        if not (0 < r < Q and 0 < s < Q):
            raise ValueError("Geçersiz DSA imzası (r,s aralık dışında).")

        x = _derive_private_key(key)
        y = pow(G, x, P)

        h_m = hashlib.sha256(m.encode("utf-8")).digest()
        h_int = int.from_bytes(h_m, "big") % Q

        w = number.inverse(s, Q)
        u1 = (h_int * w) % Q
        u2 = (r * w) % Q

        v = (pow(G, u1, P) * pow(y, u2, P)) % P
        v = v % Q

        if v != r:
            raise ValueError("DSA imza doğrulaması başarısız. Anahtar veya veri hatalı.")

        return m
