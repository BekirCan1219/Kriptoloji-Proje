from crypto.manual_aes import manual_aes_encrypt, manual_aes_decrypt

class ManualAESCipher:
    name = "MANUAL_AES"

    def encrypt(self, plaintext: str, key: str):
        return manual_aes_encrypt(plaintext, key)

    def decrypt(self, ciphertext: str, key: str):
        return manual_aes_decrypt(ciphertext, key)
