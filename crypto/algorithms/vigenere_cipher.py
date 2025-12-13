class VigenereCipher:
    name = "VIGENERE"

    def _shift(self, k):
        if 'a' <= k <= 'z':
            return ord(k) - ord('a')
        if 'A' <= k <= 'Z':
            return ord(k) - ord('A')
        raise ValueError("Vigenere anahtarı sadece harf içermelidir.")

    def encrypt(self, plaintext: str, key: str):
        if not key.isalpha():
            raise ValueError("Vigenere anahtarı yalnızca harflerden oluşmalıdır.")

        key = key.upper()
        result = []
        key_index = 0

        for ch in plaintext:
            if 'a' <= ch <= 'z':
                base = ord('a')
                shift = self._shift(key[key_index % len(key)])
                result.append(chr((ord(ch) - base + shift) % 26 + base))
                key_index += 1

            elif 'A' <= ch <= 'Z':
                base = ord('A')
                shift = self._shift(key[key_index % len(key)])
                result.append(chr((ord(ch) - base + shift) % 26 + base))
                key_index += 1

            else:
                result.append(ch)

        return "".join(result)

    def decrypt(self, ciphertext: str, key: str):
        if not key.isalpha():
            raise ValueError("Vigenere anahtarı yalnızca harflerden oluşmalıdır.")

        key = key.upper()
        result = []
        key_index = 0

        for ch in ciphertext:
            if 'a' <= ch <= 'z':
                base = ord('a')
                shift = self._shift(key[key_index % len(key)])
                result.append(chr((ord(ch) - base - shift) % 26 + base))
                key_index += 1

            elif 'A' <= ch <= 'Z':
                base = ord('A')
                shift = self._shift(key[key_index % len(key)])
                result.append(chr((ord(ch) - base - shift) % 26 + base))
                key_index += 1

            else:
                result.append(ch)

        return "".join(result)
