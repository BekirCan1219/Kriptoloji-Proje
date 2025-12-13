AES_BLOCK_SIZE = 16
DES_BLOCK_SIZE = 8
BLOWFISH_BLOCK_SIZE = 8
TRIPLE_DES_BLOCK_SIZE = 8
RC2_BLOCK_SIZE = 8
RC5_BLOCK_SIZE = 8

def pkcs7_pad(data: bytes, block_size: int) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len

def pkcs7_unpad(data: bytes, block_size: int) -> bytes:
    pad_len = data[-1]
    if pad_len < 1 or pad_len > block_size:
        raise ValueError("Geçersiz padding")
    return data[:-pad_len]
