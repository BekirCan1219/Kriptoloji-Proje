import base64
import json
import hashlib
from Crypto.Util import number


def _derive_private_params(key: str):

    h = hashlib.sha256(key.encode("utf-8")).digest()

    w = []
    total = 0
    for i in range(8):
        # 1–8 arasında küçük bir ekstra ekleyelim ki 0 olmasın
        extra = (h[i] % 8) + 1
        if i == 0:
            wi = extra
        else:
            wi = total + extra  # süper artan: wi > sum(öncekiler)
        w.append(wi)
        total += wi

    # q, sum(w)'den büyük olsun
    q = total + (h[8] % 10) + 10

    # r, 1 < r < q ve gcd(r, q) = 1
    candidate = 2 + (h[9] % (q - 2))
    while number.GCD(candidate, q) != 1:
        candidate += 1
        if candidate >= q:
            candidate = 2
    r = candidate

    return w, q, r


def _public_key(w, q, r):
    return [(wi * r) % q for wi in w]


class KnapsackCipher:
    name = "KNAPSACK"

    def encrypt(self, plaintext: str, key: str) -> str:

        if not plaintext:
            return ""

        w, q, r = _derive_private_params(key)
        b = _public_key(w, q, r)  # public key

        data = plaintext.encode("utf-8")
        cipher_nums = []

        for byte in data:
            s = 0
            # 8 bitlik knapsack: bit 0 en küçük weight'e bağlı
            for i in range(8):
                if (byte >> i) & 1:
                    s += b[i]
            cipher_nums.append(s)

        obj = {"c": cipher_nums}
        json_bytes = json.dumps(obj).encode("utf-8")
        return base64.b64encode(json_bytes).decode("utf-8")

    def decrypt(self, ciphertext: str, key: str) -> str:

        if not ciphertext:
            return ""

        try:
            json_bytes = base64.b64decode(ciphertext.encode("utf-8"))
            obj = json.loads(json_bytes.decode("utf-8"))
            cipher_nums = obj["c"]
        except Exception as ex:
            raise ValueError("Geçersiz Knapsack şifreli metni.") from ex

        w, q, r = _derive_private_params(key)
        r_inv = number.inverse(r, q)

        decoded_bytes = bytearray()

        for s in cipher_nums:
            # s' = s * r^-1 (mod q)
            s_prime = (s * r_inv) % q

            # Süper artan w ile greedy çözüm
            bits = [0] * 8
            remaining = s_prime

            # En büyük weight'ten başla
            for i in reversed(range(8)):
                if w[i] <= remaining:
                    bits[i] = 1
                    remaining -= w[i]

            # Bits -> byte
            val = 0
            for i in range(8):
                if bits[i]:
                    val |= (1 << i)

            decoded_bytes.append(val)

        try:
            return decoded_bytes.decode("utf-8")
        except UnicodeDecodeError:
            raise ValueError("Knapsack çözme sırasında UTF-8 hatası. Anahtarı kontrol edin.")
