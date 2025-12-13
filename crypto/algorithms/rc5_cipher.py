import base64
from crypto.algorithms.common import RC5_BLOCK_SIZE, pkcs7_pad, pkcs7_unpad

class RC5Cipher:
    name = "RC5"

    def __init__(self, rounds=12):
        self.w = 32
        self.r = rounds
        self.b = 16
        self.mod = 2 ** self.w
        self.P = 0xb7e15163
        self.Q = 0x9e3779b9

    def _rotl(self, x, y):
        return ((x << (y & 31)) | (x >> (32 - (y & 31)))) % self.mod

    def _rotr(self, x, y):
        return ((x >> (y & 31)) | (x << (32 - (y & 31)))) % self.mod

    def _key_schedule(self, key: bytes):
        if len(key) == 0:
            raise ValueError("RC5 anahtarı boş olamaz.")
        b = len(key)
        u = self.w // 8
        c = (b + u - 1) // u
        L = [0] * c
        for i in range(b - 1, -1, -1):
            L[i // u] = ((L[i // u] << 8) + key[i]) % self.mod
        t = 2 * (self.r + 1)
        S = [0] * t
        S[0] = self.P
        for i in range(1, t):
            S[i] = (S[i - 1] + self.Q) % self.mod
        i = j = 0
        A = B = 0
        n = 3 * max(t, c)
        for _ in range(n):
            A = S[i] = self._rotl((S[i] + A + B) % self.mod, 3)
            B = L[j] = self._rotl((L[j] + A + B) % self.mod, (A + B) % 32)
            i = (i + 1) % t
            j = (j + 1) % c
        return S

    def _encrypt_block(self, block: bytes, S):
        A = int.from_bytes(block[:4], "little")
        B = int.from_bytes(block[4:], "little")
        A = (A + S[0]) % self.mod
        B = (B + S[1]) % self.mod
        for i in range(1, self.r + 1):
            A = (self._rotl(A ^ B, B) + S[2 * i]) % self.mod
            B = (self._rotl(B ^ A, A) + S[2 * i + 1]) % self.mod
        return A.to_bytes(4, "little") + B.to_bytes(4, "little")

    def _decrypt_block(self, block: bytes, S):
        A = int.from_bytes(block[:4], "little")
        B = int.from_bytes(block[4:], "little")
        for i in range(self.r, 0, -1):
            B = self._rotr((B - S[2 * i + 1]) % self.mod, A) ^ A
            A = self._rotr((A - S[2 * i]) % self.mod, B) ^ B
        B = (B - S[1]) % self.mod
        A = (A - S[0]) % self.mod
        return A.to_bytes(4, "little") + B.to_bytes(4, "little")

    def encrypt(self, plaintext: str, key: str) -> str:
        key_bytes = key.encode("utf-8")
        S = self._key_schedule(key_bytes)
        data = pkcs7_pad(plaintext.encode("utf-8"), RC5_BLOCK_SIZE)
        out = bytearray()
        for i in range(0, len(data), RC5_BLOCK_SIZE):
            block = data[i:i + RC5_BLOCK_SIZE]
            out.extend(self._encrypt_block(block, S))
        return base64.b64encode(bytes(out)).decode("utf-8")

    def decrypt(self, ciphertext_b64: str, key: str) -> str:
        key_bytes = key.encode("utf-8")
        S = self._key_schedule(key_bytes)
        raw = base64.b64decode(ciphertext_b64)
        out = bytearray()
        for i in range(0, len(raw), RC5_BLOCK_SIZE):
            block = raw[i:i + RC5_BLOCK_SIZE]
            out.extend(self._decrypt_block(block, S))
        plain_padded = bytes(out)
        plain = pkcs7_unpad(plain_padded, RC5_BLOCK_SIZE)
        return plain.decode("utf-8")
