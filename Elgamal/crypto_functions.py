import random

def is_prime(n, k=40):
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False
    
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    
    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_prime(bits=512):
    while True:
        q = random.getrandbits(bits)
        q |= (1 << bits - 1) | 1
        if is_prime(q):
            return q

def key_generation():
    q = generate_prime(512)
    alpha = 2
    Xa = random.randint(2, q - 2)
    Ya = pow(alpha, Xa, q)
    return q, alpha, Xa, Ya

def encrypt(message, q, alpha, Ya):
    M = int.from_bytes(message.encode(), 'big')
    k = random.randint(2, q - 2)
    K = pow(Ya, k, q)
    C1 = pow(alpha, k, q)
    C2 = (K * M) % q
    return k, K, C1, C2

def decrypt(C1, C2, q, Xa):
    K_dec = pow(C1, Xa, q)
    M_dec = (C2 * pow(K_dec, -1, q)) % q
    message_bytes = M_dec.to_bytes((M_dec.bit_length() + 7) // 8, 'big')
    return K_dec, M_dec, message_bytes.decode()