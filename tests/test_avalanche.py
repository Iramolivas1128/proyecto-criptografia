import secrets
import statistics
from src.cipher.cipher_core import encrypt_cbc, KEY_SIZE
from src.metrics import avalanche_test

def test_avalanche_statistical():
    key = secrets.token_bytes(KEY_SIZE)
    msg = b"A" * 256
    def cfn(k,m):
        iv = b'\x00' * 16  # IV fijo 
        return encrypt_cbc(k, m, iv)
    results = avalanche_test(cfn, key, msg, flips=256)  # 256 flips
    mean = statistics.mean(results)
    stdev = statistics.pstdev(results)
    assert abs(mean - 0.5) < 0.06, f"Avalanche mean outside tolerance: {mean}"
    assert 0.1 < stdev < 0.3, f"Unexpected stdev: {stdev}"

