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

def generate_private_key(q):
    return random.randint(2, q - 2)

def compute_public_key(alpha, private_key, q):
    return pow(alpha, private_key, q)

def compute_shared_key(public_key, private_key, q):
    return pow(public_key, private_key, q)

def encrypt_message(message, key):
    encrypted = ""
    key_str = str(key)
    for i, char in enumerate(message):
        shift = int(key_str[i % len(key_str)])
        encrypted += chr(ord(char) + shift)
    return encrypted

def decrypt_message(encrypted, key):
    decrypted = ""
    key_str = str(key)
    for i, char in enumerate(encrypted):
        shift = int(key_str[i % len(key_str)])
        decrypted += chr(ord(char) - shift)
    return decrypted