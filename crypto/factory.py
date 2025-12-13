from crypto.algorithms.aes_cipher import AESCipher
from crypto.algorithms.des_cipher import DESCipher
from crypto.algorithms.rsa_cipher import RSACipher
from crypto.algorithms.manual_aes_cipher import ManualAESCipher
from crypto.algorithms.caesar_cipher import CaesarCipher
from crypto.algorithms.affine_cipher import AffineCipher
from crypto.algorithms.vigenere_cipher import VigenereCipher
from crypto.algorithms.hill_cipher import HillCipher
from crypto.algorithms.triple_des_cipher import TripleDESCipher
from crypto.algorithms.blowfish_cipher import BlowfishCipher
from crypto.algorithms.rc2_cipher import RC2Cipher
from crypto.algorithms.rc5_cipher import RC5Cipher
from crypto.algorithms.elgamal_cipher import ElGamalCipher
from crypto.algorithms.rabin_cipher import RabinCipher
from crypto.algorithms.knapsack_cipher import KnapsackCipher
from crypto.algorithms.dsa_cipher import DSACipher
from crypto.algorithms.dh_cipher import DHCipher
from crypto.algorithms.ecc_cipher import ECCCipher



cipher_map = {
    "AES": AESCipher(),
    "DES": DESCipher(),
    "RSA": RSACipher(),
    "MANUAL_AES": ManualAESCipher(),
    "CAESAR": CaesarCipher(),
    "AFFINE": AffineCipher(),
    "VIGENERE": VigenereCipher(),
    "HILL": HillCipher(),
    "3DES": TripleDESCipher(),
    "BLOWFISH": BlowfishCipher(),
    "RC2": RC2Cipher(),
    "RC5": RC5Cipher(),
    "ELGAMAL": ElGamalCipher(),
    "RABIN": RabinCipher(),
    "KNAPSACK": KnapsackCipher(),
    "DSA": DSACipher(),
    "DH": DHCipher(),
    "ECC": ECCCipher(),
}

def get_cipher(name: str):
    cipher = cipher_map.get(name)
    if cipher is None:
        raise ValueError(f"Desteklenmeyen algoritma: {name}")
    return cipher
