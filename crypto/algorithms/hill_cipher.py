import numpy as np

class HillCipher:
    name = "HILL"

    def _create_matrix(self, key_str: str, size: int):
        parts = key_str.split(",")
        if len(parts) != size * size:
            raise ValueError(f"Anahtar {size}x{size} matris için {size*size} sayı içermelidir. Örn: '3,10,20,5'")

        nums = [int(x) % 26 for x in parts]
        matrix = np.array(nums).reshape(size, size)

        det = int(round(np.linalg.det(matrix)))
        det_mod = det % 26

        if np.gcd(det_mod, 26) != 1:
            raise ValueError("Matrisin determinantı 26 ile aralarında asal olmalı. Decrypt edilemez.")

        return matrix

    def _mod_inverse_matrix(self, matrix, size):
        det = int(round(np.linalg.det(matrix)))
        det_mod = det % 26

        for x in range(26):
            if (det_mod * x) % 26 == 1:
                det_inv = x
                break
        else:
            raise ValueError("Determinant mod 26 terslenemiyor.")

        adj = np.round(det * np.linalg.inv(matrix)).astype(int) % 26
        return (det_inv * adj) % 26

    def _text_to_vectors(self, text: str, size: int):
        nums = []
        for ch in text:
            if 'a' <= ch <= 'z':
                nums.append(ord(ch) - ord('a'))
            elif 'A' <= ch <= 'Z':
                nums.append(ord(ch) - ord('A'))
            else:
                nums.append(None)

        clean_nums = [n for n in nums if n is not None]

        while len(clean_nums) % size != 0:
            clean_nums.append(0)

        vectors = np.array(clean_nums).reshape(-1, size)
        return vectors, nums

    def _vectors_to_text(self, vectors, original_format: list):
        result = []
        flat = vectors.flatten().tolist()
        i = 0
        for orig in original_format:
            if orig is None:
                result.append(" ")
            else:
                result.append(chr(flat[i] + ord('a')))
                i += 1
        return "".join(result)

    def encrypt(self, plaintext: str, key: str, size: int):
        M = self._create_matrix(key, size)
        vectors, original_format = self._text_to_vectors(plaintext, size)
        encrypted = (vectors.dot(M) % 26)
        return self._vectors_to_text(encrypted, original_format)

    def decrypt(self, ciphertext: str, key: str, size: int):
        M = self._create_matrix(key, size)
        M_inv = self._mod_inverse_matrix(M, size)
        vectors, original_format = self._text_to_vectors(ciphertext, size)
        decrypted = (vectors.dot(M_inv) % 26)
        return self._vectors_to_text(decrypted, original_format)
