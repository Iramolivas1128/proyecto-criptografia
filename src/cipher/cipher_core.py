"""
- Bloque: 16 bytes (128 bits)
- Clave maestra: 32 bytes (256 bits)
- Rondas: 4
"""
from typing import List
import hashlib
import hmac


BLOCK_SIZE = 16 
KEY_SIZE = 32    
ROUNDS = 4

# Permutación fija P 
P = [0,5,10,15,4,9,14,3,8,13,2,7,12,1,6,11]

def _inverse_permutation(perm: List[int]) -> List[int]:
    inv = [0] * len(perm)
    for i, v in enumerate(perm):
        inv[v] = i
    return inv

INV_P = _inverse_permutation(P)

def _permute_bytes(data: bytes, perm: List[int]) -> bytes:
    out = bytearray(len(data))
    for i, b in enumerate(data):
        out[perm[i]] = b
    return bytes(out)

def generate_sbox_from_key(key: bytes) -> (List[int], List[int]):
    
    if len(key) != KEY_SIZE:
        raise ValueError("La clave maestra debe tener 32 bytes (256 bits).")
    seed = int(hashlib.sha256(key).hexdigest(), 16)
    lst = list(range(256))
    # LCG params (constantes)
    a = 1664525
    c = 1013904223
    m = 2**32
    state = seed & 0xffffffff
    for i in range(255, 0, -1):
        state = (a * state + c) % m
        j = state % (i + 1)
        lst[i], lst[j] = lst[j], lst[i]
    sbox = lst
    inv = [0]*256
    for i, v in enumerate(sbox):
        inv[v] = i
    return sbox, inv

def key_schedule(master_key: bytes) -> List[bytes]:
   
    subs = []
    for i in range(0, ROUNDS + 2):
        h = hashlib.sha256(master_key + bytes([i])).digest()
        subs.append(h[:BLOCK_SIZE])
    return subs

# ------------------ Operaciones de bloque ------------------
def _sub_bytes(state: bytearray, sbox: List[int]) -> bytearray:
    for i in range(len(state)):
        state[i] = sbox[state[i]]
    return state

def _inv_sub_bytes(state: bytearray, inv_sbox: List[int]) -> bytearray:
    for i in range(len(state)):
        state[i] = inv_sbox[state[i]]
    return state

def enc_block(master_key: bytes, block: bytes) -> bytes:
    """
    Cifra un bloque de 16 bytes 
    """
    if len(block) != BLOCK_SIZE:
        raise ValueError("Bloque debe ser de 16 bytes")
    sbox, _ = generate_sbox_from_key(master_key)
    ks = key_schedule(master_key)
    state = bytearray(b ^ k for b, k in zip(block, ks[0]))  
    for r in range(1, ROUNDS + 1):
        state = _sub_bytes(state, sbox)
        state = bytearray(_permute_bytes(bytes(state), P))
        state = bytearray(b ^ k for b, k in zip(state, ks[r]))
    state = bytearray(b ^ k for b, k in zip(state, ks[ROUNDS + 1]))  
    return bytes(state)

def dec_block(master_key: bytes, block: bytes) -> bytes:
    """
    Descifra un bloque de 16 bytes 
    """
    if len(block) != BLOCK_SIZE:
        raise ValueError("Bloque debe ser de 16 bytes")
    _, inv_sbox = generate_sbox_from_key(master_key)
    ks = key_schedule(master_key)
    state = bytearray(b ^ k for b, k in zip(block, ks[ROUNDS + 1]))
    for r in range(ROUNDS, 0, -1):
        state = bytearray(b ^ k for b, k in zip(state, ks[r]))
        state = bytearray(_permute_bytes(bytes(state), INV_P))
        state = _inv_sub_bytes(state, inv_sbox)
    state = bytearray(b ^ k for b, k in zip(state, ks[0]))
    return bytes(state)

def pad_pkcs7(data: bytes) -> bytes:
    pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([pad_len]) * pad_len

def unpad_pkcs7(data: bytes) -> bytes:
    if not data or len(data) % BLOCK_SIZE != 0:
        raise ValueError("Padding inválido")
    pad = data[-1]
    if pad < 1 or pad > BLOCK_SIZE:
        raise ValueError("Padding inválido")
    if data[-pad:] != bytes([pad]) * pad:
        raise ValueError("Padding inválido")
    return data[:-pad]

# ------------------ Modos de operación (CBC simple) ------------------
def encrypt_cbc(master_key: bytes, plaintext: bytes, iv: bytes) -> bytes:
  
    if len(iv) != BLOCK_SIZE:
        raise ValueError("IV debe medir 16 bytes")
    pt = pad_pkcs7(plaintext)
    out = bytearray()
    prev = iv
    for i in range(0, len(pt), BLOCK_SIZE):
        block = bytes(x ^ y for x, y in zip(pt[i:i+BLOCK_SIZE], prev))
        cipher_block = enc_block(master_key, block)
        out.extend(cipher_block)
        prev = cipher_block
    return bytes(out)

def decrypt_cbc(master_key: bytes, ciphertext: bytes, iv: bytes) -> bytes:
    if len(iv) != BLOCK_SIZE:
        raise ValueError("IV inválido")
    if len(ciphertext) % BLOCK_SIZE != 0:
        raise ValueError("Ciphertext inválido")
    out = bytearray()
    prev = iv
    for i in range(0, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[i:i+BLOCK_SIZE]
        plain_block = dec_block(master_key, block)
        out.extend(bytes(x ^ y for x, y in zip(plain_block, prev)))
        prev = block
    return unpad_pkcs7(bytes(out))

# -------------------------- HMAC ---------------------------------


def wrap_with_hmac(hmac_key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    mac = hmac.new(hmac_key, iv + ciphertext, hashlib.sha256).digest()
    return iv + ciphertext + mac

def unwrap_with_hmac(hmac_key: bytes, blob: bytes) -> (bytes, bytes):
    if len(blob) < 16 + 32:
        raise ValueError("Blob too small")
    iv = blob[:16]
    mac = blob[-32:]
    ct = blob[16:-32]
    expected = hmac.new(hmac_key, iv + ct, hashlib.sha256).digest()
    if not hmac.compare_digest(mac, expected):
        raise ValueError("HMAC mismatch: integrity check failed")
    return iv, ct
