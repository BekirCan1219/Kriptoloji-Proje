class CaesarCipher:
    name = "CAESAR"

    def encrypt(self, plaintext: str, key: str):
        try:
            shift = int(key) % 26
        except:
            raise ValueError("Caesar anahtarı sayı olmalıdır.")

        result = []
        for ch in plaintext:
            if 'a' <= ch <= 'z':
                base = ord('a')
                result.append(chr((ord(ch) - base + shift) % 26 + base))
            elif 'A' <= ch <= 'Z':
                base = ord('A')
                result.append(chr((ord(ch) - base + shift) % 26 + base))
            else:
                result.append(ch)
        return "".join(result)

    def decrypt(self, ciphertext: str, key: str):
        try:
            shift = int(key) % 26
        except:
            raise ValueError("Caesar anahtarı sayı olmalıdır.")

        result = []
        for ch in ciphertext:
            if 'a' <= ch <= 'z':
                base = ord('a')
                result.append(chr((ord(ch) - base - shift) % 26 + base))
            elif 'A' <= ch <= 'Z':
                base = ord('A')
                result.append(chr((ord(ch) - base - shift) % 26 + base))
            else:
                result.append(ch)
        return "".join(result)
