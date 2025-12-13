BLOCK_SIZE = 4
def _pkcs7_pad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len


def _pkcs7_unpad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    if not data:
        raise ValueError("Boş veri unpad edilemez.")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > block_size:
        raise ValueError("Geçersiz padding.")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Padding formatı bozuk.")
    return data[:-pad_len]


def _normalize_key(key: str) -> bytes:

    key_bytes = key.encode("utf-8")
    if len(key_bytes) == 0:
        raise ValueError("Manual AES için anahtar boş olamaz.")
    if len(key_bytes) >= BLOCK_SIZE:
        return key_bytes[:BLOCK_SIZE]
    # kısa ise 0 ile pad
    return key_bytes.ljust(BLOCK_SIZE, b"\x00")


def _sbox_byte(b: int) -> int:

    return ((b ^ 0xAA) + 0x11) % 256


def _inv_sbox_byte(b: int) -> int:

    return ((b - 0x11) % 256) ^ 0xAA


def sub_bytes(state):
    return [_sbox_byte(b) for b in state]


def inv_sub_bytes(state):
    return [_inv_sbox_byte(b) for b in state]



def shift_rows(state):

    if len(state) != 4:
        raise ValueError("ShiftRows için blok boyutu 4 olmalı.")
    b0, b1, b2, b3 = state
    return [b0, b2, b3, b1]


def inv_shift_rows(state):

    if len(state) != 4:
        raise ValueError("ShiftRows için blok boyutu 4 olmalı.")
    b0, b2, b3, b1 = state
    return [b0, b1, b2, b3]



def add_round_key(state, key_bytes):
    return [b ^ k for b, k in zip(state, key_bytes)]



def _encrypt_block(block: bytes, key_bytes: bytes) -> bytes:

    if len(block) != BLOCK_SIZE:
        raise ValueError("Blok boyutu 4 olmalı.")
    state = list(block)

    # Round 1
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, key_bytes)

    # Round 2
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, key_bytes)

    return bytes(state)


def _decrypt_block(block: bytes, key_bytes: bytes) -> bytes:

    if len(block) != BLOCK_SIZE:
        raise ValueError("Blok boyutu 4 olmalı.")
    state = list(block)

    # Round 2 ters
    state = add_round_key(state, key_bytes)
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)

    # Round 1 ters
    state = add_round_key(state, key_bytes)
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)

    return bytes(state)


def manual_aes_encrypt(plaintext: str, key: str) -> str:

    key_bytes = _normalize_key(key)
    data = plaintext.encode("utf-8")
    padded = _pkcs7_pad(data, BLOCK_SIZE)

    cipher_bytes = bytearray()
    for i in range(0, len(padded), BLOCK_SIZE):
        block = padded[i:i + BLOCK_SIZE]
        cipher_bytes.extend(_encrypt_block(block, key_bytes))

    # DB ve ağda rahat taşımak için hex string döndürüyoruz
    return cipher_bytes.hex()


def manual_aes_decrypt(cipher_hex: str, key: str) -> str:

    key_bytes = _normalize_key(key)

    try:
        cipher_bytes = bytes.fromhex(cipher_hex)
    except ValueError:
        raise ValueError("Cipher hex formatında olmalı.")

    if len(cipher_bytes) % BLOCK_SIZE != 0:
        raise ValueError("Cipher uzunluğu blok boyutuna tam bölünmüyor.")

    plain_padded = bytearray()
    for i in range(0, len(cipher_bytes), BLOCK_SIZE):
        block = cipher_bytes[i:i + BLOCK_SIZE]
        plain_padded.extend(_decrypt_block(block, key_bytes))

    plain = _pkcs7_unpad(plain_padded, BLOCK_SIZE)
    return plain.decode("utf-8")
