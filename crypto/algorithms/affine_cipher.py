from math import gcd

class AffineCipher:
    name = "AFFINE"

    def _mod_inverse(self, a, m):
        a = a % m
        for x in range(1, m):
            if (a * x) % m == 1:
                return x
        raise ValueError("a için mod 26 ters yok. a ve 26 aralarında asal olmalı.")

    def encrypt(self, plaintext: str, key: str):
        try:
            a_str, b_str = key.split(",")
            a = int(a_str)
            b = int(b_str)
        except:
            raise ValueError("Affine anahtarı 'a,b' formatında olmalı. Örn: 5,8")

        if gcd(a, 26) != 1:
            raise ValueError("a ile 26 aralarında asal olmalı.")

        result = []
        for ch in plaintext:
            if 'a' <= ch <= 'z':
                base = ord('a')
                x = ord(ch) - base
                e = (a * x + b) % 26
                result.append(chr(e + base))
            elif 'A' <= ch <= 'Z':
                base = ord('A')
                x = ord(ch) - base
                e = (a * x + b) % 26
                result.append(chr(e + base))
            else:
                result.append(ch)

        return "".join(result)

    def decrypt(self, ciphertext: str, key: str):
        try:
            a_str, b_str = key.split(",")
            a = int(a_str)
            b = int(b_str)
        except:
            raise ValueError("Affine anahtarı 'a,b' formatında olmalı. Örn: 5,8")

        if gcd(a, 26) != 1:
            raise ValueError("a ile 26 aralarında asal olmalı.")

        a_inv = self._mod_inverse(a, 26)

        result = []
        for ch in ciphertext:
            if 'a' <= ch <= 'z':
                base = ord('a')
                x = ord(ch) - base
                d = (a_inv * (x - b)) % 26
                result.append(chr(d + base))
            elif 'A' <= ch <= 'Z':
                base = ord('A')
                x = ord(ch) - base
                d = (a_inv * (x - b)) % 26
                result.append(chr(d + base))
            else:
                result.append(ch)

        return "".join(result)
