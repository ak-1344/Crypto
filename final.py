# ═══════════════════════════════════════════════════════════════════════════════
#  Single file. No crypto libraries. Server-client socket architecture.
#  Usage: python crypto_master.py
#  Imports allowed: socket, threading, struct, math, random, string, os, time
#
#  ALGORITHMS COVERED:
#    1.  S-DES           port 5001  (from repo: sdes/)
#    2.  DES (16-round)  port 5002  (NOT in repo — written from scratch)
#    3.  AES-128         port 5003  (NOT in repo — written from scratch)
#    4.  RSA (1024-bit)  port 5004  (NOT in repo — includes primitive root)
#    5.  ElGamal         port 5005  (from repo: Elgamal/)
#    6.  DH + MITM       port 5006/5007  (from repo: MIMT/)
#    7.  MD5             standalone     (from repo: hashing.py)
#    8.  SHA-512         standalone     (NOT in repo — written from scratch)
#    9.  DSS             port 5009  (NOT in repo — written from scratch)
#   10.  Classical       port 5010  (from repo: Ex1a/1b/1c)
#
#  EXAM NOTES:
#    - MD5 was in midterm: hex conversion, padding blocks, Round 2 with given A,B,C,D
#    - RSA: primitive root must be found via algorithm (NOT assumed)
#    - DH MITM: same — primitive root computed, not assumed
#    - DES: intermediate results in HEX. Final step: swap R+L before IP_INV
#    - AES: Round 10 has NO MixColumns
#    - DSS: Sender signs → socket → Receiver verifies
# ═══════════════════════════════════════════════════════════════════════════════

import socket, struct, math, random, string, threading, time

HOST = "127.0.0.1"

# ═══════════════════════════════════════════════════════════════════════════════
#  SHARED MATH UTILITIES (used by RSA, ElGamal, DH, DSS)
# ═══════════════════════════════════════════════════════════════════════════════

def miller_rabin(n, k=40):
    """Probabilistic primality test. k=40 gives astronomically low error rate."""
    if n < 2: return False
    if n in (2, 3): return True
    if n % 2 == 0: return False
    r, d = 0, n - 1
    while d % 2 == 0: r += 1; d //= 2
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)                   # Python's pow(a,b,n) = a^b mod n (fast)
        if x in (1, n - 1): continue
        for _ in range(r - 1):
            x = x * x % n
            if x == n - 1: break
        else: return False
    return True

def gen_prime(bits):
    """Generate a random prime of given bit length using Miller-Rabin."""
    while True:
        p = random.getrandbits(bits) | (1 << bits - 1) | 1  # Ensure odd and full bit-length
        if miller_rabin(p): return p

def ext_gcd(a, b):
    """Extended Euclidean Algorithm. Returns (gcd, x, y) where ax + by = gcd."""
    if a == 0: return b, 0, 1
    g, x, y = ext_gcd(b % a, a)
    return g, y - (b // a) * x, x

def mod_inv(e, phi):
    """Modular inverse of e mod phi using extended GCD. Used for RSA d, DSS."""
    g, x, _ = ext_gcd(e % phi, phi)
    if g != 1: raise ValueError("No modular inverse exists")
    return x % phi

def prime_factors(n):
    """Return set of all prime factors of n. Used in primitive root computation."""
    f = set(); d = 2
    while d * d <= n:
        while n % d == 0: f.add(d); n //= d
        d += 1
    if n > 1: f.add(n)
    return f

def find_prim_root(p):
    """
    Find smallest primitive root g of prime p.
    DEFINITION: g is a primitive root of p if g^((p-1)/q) != 1 (mod p)
                for EVERY prime factor q of (p-1).
    This MUST be computed via algorithm — cannot assume g=2 in exam.
    """
    phi = p - 1
    factors = prime_factors(phi)
    for g in range(2, p):
        if all(pow(g, phi // q, p) != 1 for q in factors):
            return g
    return None

# Socket helpers — newline-delimited string protocol
def sock_send(conn, data): conn.sendall((str(data) + "\n").encode())
def sock_recv(conn):
    buf = b""
    while not buf.endswith(b"\n"): buf += conn.recv(4096)
    return buf.decode().strip()


# ═══════════════════════════════════════════════════════════════════════════════
#  1. S-DES (Simplified DES)  ─  port 5001
#  10-bit key, 8-bit plaintext/ciphertext, 2 rounds, binary I/O
#  SERVER = Receiver (decrypts). CLIENT = Sender (encrypts).
# ═══════════════════════════════════════════════════════════════════════════════

# S-DES permutation tables
_P10    = [3,5,2,7,4,10,1,9,8,6]
_P8     = [6,3,7,4,8,5,10,9]
_SDES_IP  = [2,6,3,1,4,8,5,7]
_SDES_IPI = [4,1,3,5,7,2,8,6]
_EP     = [4,1,2,3,2,3,4,1]
_P4     = [2,4,3,1]
_S0 = [[1,0,3,2],[3,2,1,0],[0,2,1,3],[3,1,3,2]]
_S1 = [[0,1,2,3],[2,0,1,3],[3,0,1,0],[2,1,0,3]]

def _sperm(b, t): return ''.join(b[i-1] for i in t)
def _sxor(a, b):  return ''.join('0' if x==y else '1' for x,y in zip(a,b))
def _ssbox(b, bx): return format(bx[int(b[0]+b[3],2)][int(b[1]+b[2],2)], '02b')

def _sdes_subkeys(key):
    p = _sperm(key, _P10); l, r = p[:5], p[5:]
    l1, r1 = l[1:]+l[:1], r[1:]+r[:1]             # Shift by 1
    k1 = _sperm(l1+r1, _P8)
    l2, r2 = l1[2:]+l1[:2], r1[2:]+r1[:2]         # Shift by 2 more (total 3 from original)
    k2 = _sperm(l2+r2, _P8)
    return k1, k2

def _sdes_fk(bits, key):
    l, r = bits[:4], bits[4:]
    x = _sxor(_sperm(r, _EP), key)                 # Expand R (4→8 bits), XOR with key
    p4 = _sperm(_ssbox(x[:4], _S0) + _ssbox(x[4:], _S1), _P4)
    return _sxor(l, p4) + r

def sdes_encrypt(pt, key):
    k1, k2 = _sdes_subkeys(key)
    print(f"Subkeys: K1={k1}  K2={k2}")
    ip = _sperm(pt, _SDES_IP);     print(f"After IP  : {ip}")
    r1 = _sdes_fk(ip, k1);         print(f"Round 1   : {r1}")
    sw = r1[4:] + r1[:4]           # SWAP halves between rounds
    r2 = _sdes_fk(sw, k2);         print(f"Round 2   : {r2}")
    ct = _sperm(r2, _SDES_IPI);    print(f"Ciphertext: {ct}")
    return ct

def sdes_decrypt(ct, key):
    k1, k2 = _sdes_subkeys(key)
    print(f"Subkeys: K1={k1}  K2={k2}")
    ip = _sperm(ct, _SDES_IP);     print(f"After IP  : {ip}")
    r1 = _sdes_fk(ip, k2);         print(f"Round 1   : {r1}")  # Note: K2 first for decryption
    r2 = _sdes_fk(r1[4:]+r1[:4], k1); print(f"Round 2   : {r2}")
    pt = _sperm(r2, _SDES_IPI);    print(f"Plaintext : {pt}")
    return pt

def run_sdes(mode):
    PORT = 5001
    key = input("Key (10-bit binary e.g. 1100011110): ").strip()
    if mode == "server":
        s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT)); s.listen(1); print("Waiting for sender (client)...")
        conn, _ = s.accept()
        ct = sock_recv(conn); print(f"\n[Receiver] Ciphertext: {ct}")
        print("=== DECRYPTION ==="); sdes_decrypt(ct, key)
        conn.close(); s.close()
    else:
        pt = input("Plaintext (8-bit binary e.g. 10011101): ").strip()
        c = socket.socket(); c.connect((HOST, PORT))
        print("=== ENCRYPTION ==="); ct = sdes_encrypt(pt, key)
        sock_send(c, ct); print(f"Sent ciphertext: {ct}"); c.close()


# ═══════════════════════════════════════════════════════════════════════════════
#  2. DES — Full 16-round Feistel Cipher  ─  port 5002
#  64-bit key (56 effective + 8 parity), 64-bit block, intermediate results in HEX
#  Plaintext/Key: ASCII string (padded to 8 bytes with \x00)
#  SERVER = Receiver (decrypts). CLIENT = Sender (encrypts).
#
#  KEY POINTS FOR EXAM:
#    - Shift schedule: rounds 1,2,9,16 shift by 1; all others by 2
#    - S-box lookup: row = bits[0]+bits[5] (outer), col = bits[1..4] (inner 4)
#    - Final combine: R16 + L16 (SWAP!) before IP_INV
#    - Decryption: SAME algorithm with REVERSED subkeys (K16..K1)
# ═══════════════════════════════════════════════════════════════════════════════

_DES_IP  = [58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,62,54,46,38,30,22,14,6,
            64,56,48,40,32,24,16,8,57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,
            61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7]
_DES_IPI = [40,8,48,16,56,24,64,32,39,7,47,15,55,23,63,31,38,6,46,14,54,22,62,30,
            37,5,45,13,53,21,61,29,36,4,44,12,52,20,60,28,35,3,43,11,51,19,59,27,
            34,2,42,10,50,18,58,26,33,1,41,9,49,17,57,25]
_PC1 = [57,49,41,33,25,17,9,1,58,50,42,34,26,18,10,2,59,51,43,35,27,19,11,3,60,52,44,36,
        63,55,47,39,31,23,15,7,62,54,46,38,30,22,14,6,61,53,45,37,29,21,13,5,28,20,12,4]
_PC2 = [14,17,11,24,1,5,3,28,15,6,21,10,23,19,12,4,26,8,16,7,27,20,13,2,
        41,52,31,37,47,55,30,40,51,45,33,48,44,49,39,56,34,53,46,42,50,36,29,32]
_DES_E = [32,1,2,3,4,5,4,5,6,7,8,9,8,9,10,11,12,13,12,13,14,15,16,17,
          16,17,18,19,20,21,20,21,22,23,24,25,24,25,26,27,28,29,28,29,30,31,32,1]
_DES_P = [16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25]
_DES_SHIFTS = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]  # Shift by 1 at rounds 1,2,9,16
_DES_S = [
    [[14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7],[0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8],
     [4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0],[15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13]],
    [[15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10],[3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5],
     [0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15],[13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9]],
    [[10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8],[13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1],
     [13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7],[1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12]],
    [[7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15],[13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9],
     [10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4],[3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14]],
    [[2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9],[14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6],
     [4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14],[11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3]],
    [[12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11],[10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8],
     [9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6],[4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13]],
    [[4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1],[13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6],
     [1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2],[6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12]],
    [[13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7],[1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2],
     [7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8],[2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11]]
]

def _des_perm(bits, tbl): return [bits[i-1] for i in tbl]
def _des_b2h(bits): return ''.join(f'{bits[i]*8+bits[i+1]*4+bits[i+2]*2+bits[i+3]:X}' for i in range(0,len(bits),4))
def _des_t2b(text): return [(ord(c)>>(7-i))&1 for c in text for i in range(8)]

def _des_subkeys(key_str):
    """Generate all 16 × 48-bit DES subkeys from 64-bit key string."""
    key_str = (key_str + '\x00'*8)[:8]              # Pad/trim to 8 bytes
    key_bits = _des_t2b(key_str)
    k56 = _des_perm(key_bits, _PC1)                 # 64 → 56 bits (drops parity bits)
    C, D = k56[:28], k56[28:]                       # Split into two 28-bit halves
    ks = []
    for sh in _DES_SHIFTS:
        C = C[sh:]+C[:sh]; D = D[sh:]+D[:sh]        # Left circular shift
        ks.append(_des_perm(C+D, _PC2))             # 56 → 48 bit subkey
    return ks

def _des_F(R, K):
    """DES F-function: Expand R (32→48), XOR with K, S-box (48→32), P-permute."""
    ex = _des_perm(R, _DES_E)                       # 32 → 48 bit expansion
    xd = [a^b for a,b in zip(ex, K)]               # XOR with subkey
    sub = []
    for i in range(8):
        ch = xd[i*6:(i+1)*6]
        row = (ch[0]<<1)|ch[5]                      # Outer bits (b1 b6) = row
        col = (ch[1]<<3)|(ch[2]<<2)|(ch[3]<<1)|ch[4]  # Inner bits (b2 b3 b4 b5) = col
        v = _DES_S[i][row][col]
        sub += [(v>>(3-j))&1 for j in range(4)]    # 6 → 4 bits via S-box
    return _des_perm(sub, _DES_P)                   # Final P-permutation

def _des_block(b64, ks):
    """Process one 64-bit DES block through 16 Feistel rounds."""
    p = _des_perm(b64, _DES_IP)
    L, R = p[:32], p[32:]
    print(f"  After IP: L={_des_b2h(L)} R={_des_b2h(R)}")
    for i, Ki in enumerate(ks):
        L, R = R, [a^b for a,b in zip(L, _des_F(R, Ki))]
        print(f"  Round {i+1:2d}: L={_des_b2h(L)} R={_des_b2h(R)}")
    # CRITICAL: swap R+L (not L+R) before final permutation
    return _des_perm(R+L, _DES_IPI)

def des_encrypt(pt, key):
    ks = _des_subkeys(key)
    pad = (-len(pt)) % 8; pt += '\x00' * pad        # Pad to multiple of 8 bytes
    out = []
    for i in range(0, len(pt), 8):
        out += _des_block(_des_t2b(pt[i:i+8]), ks)
    return _des_b2h(out)

def des_decrypt(ct_hex, key):
    ks = _des_subkeys(key)[::-1]                    # REVERSED subkeys for decryption
    bits = []
    for i in range(0, len(ct_hex), 2):
        b = int(ct_hex[i:i+2], 16)
        bits += [(b>>(7-j))&1 for j in range(8)]
    out = []
    for i in range(0, len(bits), 64):
        out += _des_block(bits[i:i+64], ks)
    return ''.join(chr(sum(out[i+j]<<(7-j) for j in range(8))) for i in range(0,len(out),8) if sum(out[i:i+8]))

def run_des(mode):
    PORT = 5002
    if mode == "server":
        key = input("Key (e.g. Security): ").strip()
        s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT)); s.listen(1); print("Waiting for sender...")
        conn, _ = s.accept()
        ct = sock_recv(conn); print(f"\n=== RECEIVER: DECRYPTION ===\nCiphertext (HEX): {ct}")
        dt = des_decrypt(ct, key); print(f"Decrypted text: {dt}")
        conn.close(); s.close()
    else:
        key = input("Key (e.g. Security): ").strip()
        pt  = input("Plaintext (e.g. Cryptography): ").strip()
        c = socket.socket(); c.connect((HOST, PORT))
        print(f"\n=== SENDER: ENCRYPTION ===\nPlaintext: {pt}  Key: {key}")
        ct = des_encrypt(pt, key)
        print(f"Ciphertext (HEX): {ct}"); sock_send(c, ct); c.close()


# ═══════════════════════════════════════════════════════════════════════════════
#  3. AES-128  ─  port 5003
#  128-bit key & block, 10 rounds, SPN structure (vs DES Feistel)
#  Rounds 1-9: SubBytes → ShiftRows → MixColumns → AddRoundKey
#  Round 10:   SubBytes → ShiftRows → AddRoundKey  (NO MixColumns!)
#  SERVER = Receiver (decrypts). CLIENT = Sender (encrypts).
# ═══════════════════════════════════════════════════════════════════════════════

_AES_SBOX = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
]
_AES_ISBOX = [0]*256
for _i, _v in enumerate(_AES_SBOX): _AES_ISBOX[_v] = _i
_AES_RCON = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36]

def _gmul(a, b):
    """GF(2^8) multiplication with irreducible polynomial x^8+x^4+x^3+x+1 (0x11b)."""
    p = 0
    for _ in range(8):
        if b & 1: p ^= a
        hi = a & 0x80; a = (a << 1) & 0xff
        if hi: a ^= 0x1b       # Reduce mod 0x11b
        b >>= 1
    return p

def _aes_key_expand(key):
    """AES-128 key expansion: 16-byte key → 11 round keys (44 words of 4 bytes each)."""
    W = [list(key[i:i+4]) for i in range(0, 16, 4)]
    for i in range(4, 44):
        t = W[i-1][:]
        if i % 4 == 0:
            t = [_AES_SBOX[b] for b in t[1:]+t[:1]]  # RotWord then SubWord
            t[0] ^= _AES_RCON[i//4 - 1]
        W.append([a^b for a,b in zip(W[i-4], t)])
    return [[W[i*4+j] for j in range(4)] for i in range(11)]

def _add_rk(s, rk): return [[s[r][c]^rk[c][r] for c in range(4)] for r in range(4)]
def _sub(s):   return [[_AES_SBOX[s[r][c]] for c in range(4)] for r in range(4)]
def _isub(s):  return [[_AES_ISBOX[s[r][c]] for c in range(4)] for r in range(4)]
def _shift(s): return [[(s[r][(c+r)%4]) for c in range(4)] for r in range(4)]  # Row r shifts left by r
def _ishift(s):return [[(s[r][(c-r)%4]) for c in range(4)] for r in range(4)]  # Inverse shift

def _mix(s):
    """MixColumns: each column multiplied by fixed matrix in GF(2^8)."""
    n = [[0]*4 for _ in range(4)]
    for c in range(4):
        col = [s[r][c] for r in range(4)]
        n[0][c] = _gmul(2,col[0])^_gmul(3,col[1])^col[2]^col[3]
        n[1][c] = col[0]^_gmul(2,col[1])^_gmul(3,col[2])^col[3]
        n[2][c] = col[0]^col[1]^_gmul(2,col[2])^_gmul(3,col[3])
        n[3][c] = _gmul(3,col[0])^col[1]^col[2]^_gmul(2,col[3])
    return n

def _imix(s):
    """Inverse MixColumns for decryption."""
    n = [[0]*4 for _ in range(4)]
    for c in range(4):
        col = [s[r][c] for r in range(4)]
        n[0][c] = _gmul(0xe,col[0])^_gmul(0xb,col[1])^_gmul(0xd,col[2])^_gmul(0x9,col[3])
        n[1][c] = _gmul(0x9,col[0])^_gmul(0xe,col[1])^_gmul(0xb,col[2])^_gmul(0xd,col[3])
        n[2][c] = _gmul(0xd,col[0])^_gmul(0x9,col[1])^_gmul(0xe,col[2])^_gmul(0xb,col[3])
        n[3][c] = _gmul(0xb,col[0])^_gmul(0xd,col[1])^_gmul(0x9,col[2])^_gmul(0xe,col[3])
    return n

# State is column-major: bytes fill down each column first
def _b2state(b): return [[b[r+4*c] for c in range(4)] for r in range(4)]
def _state2b(s): return bytes([s[r][c] for c in range(4) for r in range(4)])
def _shex(s): return ' '.join(f'{s[r][c]:02X}' for c in range(4) for r in range(4))

def aes_encrypt(pt, key):
    if isinstance(pt, str): pt = pt.encode()
    if isinstance(key, str): key = key.encode()
    key = (key + b'\x00'*16)[:16]                  # Pad/trim key to 16 bytes
    pad = (-len(pt)) % 16; pt += bytes([pad if pad else 16]*(pad if pad else 16))  # PKCS7
    rks = _aes_key_expand(key); result = b''
    for blk in range(0, len(pt), 16):
        s = _b2state(pt[blk:blk+16])
        s = _add_rk(s, rks[0])                     # Initial AddRoundKey
        print(f"  After AddRoundKey[0]: {_shex(s)}")
        for rnd in range(1, 11):
            s = _sub(s)                             # SubBytes
            s = _shift(s)                           # ShiftRows
            if rnd < 10: s = _mix(s)               # MixColumns (SKIP in round 10!)
            s = _add_rk(s, rks[rnd])               # AddRoundKey
            print(f"  Round {rnd:2d}: {_shex(s)}")
        result += _state2b(s)
    return result.hex().upper()

def aes_decrypt(ct_hex, key):
    if isinstance(key, str): key = key.encode()
    key = (key + b'\x00'*16)[:16]
    ct = bytes.fromhex(ct_hex); rks = _aes_key_expand(key); result = b''
    for blk in range(0, len(ct), 16):
        s = _b2state(ct[blk:blk+16]); s = _add_rk(s, rks[10])
        for rnd in range(9, -1, -1):
            s = _ishift(s); s = _isub(s); s = _add_rk(s, rks[rnd])
            if rnd > 0: s = _imix(s)
        result += _state2b(s)
    pad = result[-1]; return result[:-pad].decode(errors='replace')

def run_aes(mode):
    PORT = 5003
    if mode == "server":
        key = input("Key (e.g. Security): ").strip()
        s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT)); s.listen(1); print("Waiting for sender...")
        conn, _ = s.accept()
        ct = sock_recv(conn); print(f"\n=== RECEIVER: DECRYPTION ===\nCiphertext: {ct}")
        dt = aes_decrypt(ct, key); print(f"Decrypted: {dt}")
        conn.close(); s.close()
    else:
        key = input("Key (e.g. Security): ").strip()
        pt  = input("Plaintext (e.g. Cryptography): ").strip()
        c = socket.socket(); c.connect((HOST, PORT))
        print(f"\n=== SENDER: ENCRYPTION ===\nPlaintext: {pt}  Key: {key}")
        ct = aes_encrypt(pt, key)
        print(f"Ciphertext: {ct}"); sock_send(c, ct); c.close()


# ═══════════════════════════════════════════════════════════════════════════════
#  4. RSA (1024-bit)  ─  port 5004
#  p, q: random 512-bit primes via Miller-Rabin. e=65537. d=mod_inv(e, phi(n))
#  Encrypt: C = M^e mod n.  Decrypt: M = C^d mod n
#  SERVER = Receiver (generates keys, decrypts). CLIENT = Sender (encrypts).
#  EXAM NOTE: find_prim_root() is defined above — primitive root via algorithm.
# ═══════════════════════════════════════════════════════════════════════════════

def run_rsa(mode):
    PORT = 5004
    if mode == "server":
        print("Generating 1024-bit RSA keys (Miller-Rabin, ~3-5 sec)...")
        p = gen_prime(512); q = gen_prime(512)
        while q == p: q = gen_prime(512)
        n = p * q; phi = (p-1)*(q-1); e = 65537
        d = mod_inv(e, phi)
        print(f"\np   = {p}\nq   = {q}\nn   = {n}\nphi(n) = {phi}\ne   = {e}\nd   = {d}")
        s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT)); s.listen(1); print("\nWaiting for sender...")
        conn, _ = s.accept()
        sock_send(conn, n); sock_send(conn, e)      # Publish public key (n, e)
        ct = int(sock_recv(conn))                   # Receive ciphertext
        M = pow(ct, d, n)                           # Decrypt: M = C^d mod n
        pt = M.to_bytes((M.bit_length()+7)//8, 'big').decode(errors='replace')
        print(f"\nReceived ciphertext: {ct}\nDecrypted: {pt}")
        conn.close(); s.close()
    else:
        c = socket.socket(); c.connect((HOST, PORT))
        n = int(sock_recv(c)); e = int(sock_recv(c))
        print(f"Received public key:\n  n={n}\n  e={e}")
        msg = input("Message: ").strip()
        M = int.from_bytes(msg.encode(), 'big')
        assert M < n, "Message integer >= n; use longer key or shorter message"
        ct = pow(M, e, n)                           # Encrypt: C = M^e mod n
        print(f"Encrypted: {ct}"); sock_send(c, ct); c.close()


# ═══════════════════════════════════════════════════════════════════════════════
#  5. ElGamal  ─  port 5005  (from repo: Elgamal/)
#  Public: prime q, generator alpha (=2), public key Ya = alpha^Xa mod q
#  Private: Xa (random)
#  Encrypt: pick k → K=Ya^k mod q, C1=alpha^k mod q, C2=K*M mod q
#  Decrypt: K=C1^Xa mod q, M=C2*K^-1 mod q
#  SERVER = Receiver (key gen + decrypt). CLIENT = Sender (encrypt).
# ═══════════════════════════════════════════════════════════════════════════════

def run_elgamal(mode):
    PORT = 5005
    if mode == "server":
        print("Generating ElGamal keys (512-bit prime, takes ~1-2 sec)...")
        q = gen_prime(512)
        alpha = 2                                   # Generator (2 works for most primes)
        Xa = random.randint(2, q-2)                 # Private key
        Ya = pow(alpha, Xa, q)                      # Public key: Ya = alpha^Xa mod q
        print(f"\nq (prime)    = {q}\nalpha (gen)  = {alpha}\nXa (private) = {Xa}\nYa (public)  = {Ya}")
        s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT)); s.listen(1); print("\nWaiting for sender...")
        conn, _ = s.accept()
        sock_send(conn, q); sock_send(conn, alpha); sock_send(conn, Ya)
        C1 = int(sock_recv(conn)); C2 = int(sock_recv(conn))
        # Decrypt: K = C1^Xa mod q,  M = C2 * K^-1 mod q
        K = pow(C1, Xa, q)
        M = (C2 * pow(K, -1, q)) % q
        pt = M.to_bytes((M.bit_length()+7)//8, 'big').decode(errors='replace')
        print(f"\nC1={C1}\nC2={C2}\nK={K}\nDecrypted M={M}\nMessage: {pt}")
        conn.close(); s.close()
    else:
        c = socket.socket(); c.connect((HOST, PORT))
        q = int(sock_recv(c)); alpha = int(sock_recv(c)); Ya = int(sock_recv(c))
        print(f"Received: q={q}\nalpha={alpha}\nYa={Ya}")
        msg = input("Message: ").strip()
        M = int.from_bytes(msg.encode(), 'big')
        k = random.randint(2, q-2)                  # Random ephemeral key (different each time)
        K = pow(Ya, k, q)                           # Shared secret: K = Ya^k mod q
        C1 = pow(alpha, k, q)                       # C1 = alpha^k mod q
        C2 = (K * M) % q                            # C2 = K * M mod q
        print(f"\nk={k}\nK={K}\nC1={C1}\nC2={C2}")
        sock_send(c, C1); sock_send(c, C2); c.close()


# ═══════════════════════════════════════════════════════════════════════════════
#  6. Diffie-Hellman + MITM Attack  ─  ports 5006 (Alice) / 5007 (Bob)
#  (from repo: MIMT/ — adapted to single file)
#  LAUNCH ORDER: attacker first → alice → bob
#  primitive root MUST be computed via find_prim_root(), NOT assumed
#
#  DH Protocol:
#    Shared params: prime p, primitive root g (computed)
#    Alice: pick xa randomly → Ya = g^xa mod p → send Ya
#    Bob:   pick xb randomly → Yb = g^xb mod p → send Yb
#    Shared key: Alice: K=Yb^xa mod p | Bob: K=Ya^xb mod p  (same value)
#
#  MITM: Mallory intercepts both, creates separate shared keys with each party
# ═══════════════════════════════════════════════════════════════════════════════

def _dh_encrypt(msg, key):
    """Simple XOR-shift encryption for DH chat demo (same as repo)."""
    key_s = str(key)
    return ''.join(chr(ord(c) + int(key_s[i % len(key_s)])) for i,c in enumerate(msg))

def _dh_decrypt(enc, key):
    key_s = str(key)
    return ''.join(chr(ord(c) - int(key_s[i % len(key_s)])) for i,c in enumerate(enc))

def _run_alice(q, g):
    xa = random.randint(2, q-2); Ya = pow(g, xa, q)
    print(f"[Alice] Private xa={xa}  Public Ya={Ya}")
    c = socket.socket(); c.connect((HOST, 5006))
    sock_send(c, Ya)
    Yd = int(sock_recv(c))                          # Receives Mallory's fake key
    Ka = pow(Yd, xa, q)
    print(f"[Alice] Got Yd={Yd} (from 'Bob')  Shared Ka={Ka}")
    print("[Alice] Chat started. Type 'exit' to quit.")
    def _recv():
        while True:
            try: msg = sock_recv(c); print(f"\nBob: {_dh_decrypt(msg, Ka)}\nYou: ", end="", flush=True)
            except: break
    threading.Thread(target=_recv, daemon=True).start()
    while True:
        msg = input("You: ")
        if msg.lower() == 'exit': break
        c.sendall((_dh_encrypt(msg, Ka) + "\n").encode())
    c.close()

def _run_bob(q, g):
    xb = random.randint(2, q-2); Yb = pow(g, xb, q)
    print(f"[Bob] Private xb={xb}  Public Yb={Yb}")
    c = socket.socket(); c.connect((HOST, 5007))
    sock_send(c, Yb)
    Yd = int(sock_recv(c))                          # Receives Mallory's fake key
    Kb = pow(Yd, xb, q)
    print(f"[Bob] Got Yd={Yd} (from 'Alice')  Shared Kb={Kb}")
    print("[Bob] Chat started. Type 'exit' to quit.")
    def _recv():
        while True:
            try: msg = sock_recv(c); print(f"\nAlice: {_dh_decrypt(msg, Kb)}\nYou: ", end="", flush=True)
            except: break
    threading.Thread(target=_recv, daemon=True).start()
    while True:
        msg = input("You: ")
        if msg.lower() == 'exit': break
        c.sendall((_dh_encrypt(msg, Kb) + "\n").encode())
    c.close()

def _run_attacker(q, g):
    Xd1 = random.randint(2, q-2); Yd1 = pow(g, Xd1, q)  # Towards Alice
    Xd2 = random.randint(2, q-2); Yd2 = pow(g, Xd2, q)  # Towards Bob
    print(f"[Attacker] Xd1={Xd1} Yd1={Yd1} (to send to Alice as Bob's key)")
    print(f"[Attacker] Xd2={Xd2} Yd2={Yd2} (to send to Bob as Alice's key)")
    sa = socket.socket(); sa.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sa.bind((HOST, 5006)); sa.listen(1)
    sb = socket.socket(); sb.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sb.bind((HOST, 5007)); sb.listen(1)
    print("Waiting for Alice (5006)..."); conn_a, _ = sa.accept()
    Ya = int(sock_recv(conn_a)); Ka = pow(Ya, Xd1, q)
    sock_send(conn_a, Yd1)
    print(f"[Attacker↔Alice] Ya={Ya}  Ka={Ka}")
    print("Waiting for Bob (5007)..."); conn_b, _ = sb.accept()
    Yb = int(sock_recv(conn_b)); Kb = pow(Yb, Xd2, q)
    sock_send(conn_b, Yd2)
    print(f"[Attacker↔Bob]   Yb={Yb}  Kb={Kb}")
    print("\n💀 MITM ACTIVE — intercepting and re-encrypting all messages!\n")
    def _a2b():
        while True:
            try:
                enc = sock_recv(conn_a); dec = _dh_decrypt(enc, Ka)
                print(f"[A→B] Intercepted: '{dec}'")
                conn_b.sendall((_dh_encrypt(dec, Kb) + "\n").encode())
            except: break
    def _b2a():
        while True:
            try:
                enc = sock_recv(conn_b); dec = _dh_decrypt(enc, Kb)
                print(f"[B→A] Intercepted: '{dec}'")
                conn_a.sendall((_dh_encrypt(dec, Ka) + "\n").encode())
            except: break
    t1 = threading.Thread(target=_a2b, daemon=True)
    t2 = threading.Thread(target=_b2a, daemon=True)
    t1.start(); t2.start()
    try: t1.join(); t2.join()
    except KeyboardInterrupt: pass
    conn_a.close(); conn_b.close(); sa.close(); sb.close()

def run_dh_mitm(role):
    q = int(input("Enter prime p: "))
    if not miller_rabin(q): print(f"WARNING: {q} may not be prime!")
    print("Computing primitive root via algorithm (NOT assumed)...")
    g = find_prim_root(q)
    print(f"Primitive root g = {g}")
    if role == "alice":      _run_alice(q, g)
    elif role == "bob":      _run_bob(q, g)
    elif role == "attacker": _run_attacker(q, g)


# ═══════════════════════════════════════════════════════════════════════════════
#  7. MD5  ─  standalone  (from repo: hashing.py — cleaned + exam-annotated)
#  128-bit output, 512-bit block, 64 operations (4 rounds × 16)
#  EXAM CRITICAL: padding rules, round functions, g-index formula per round
#
#  PADDING ALGORITHM:
#    1. Append byte 0x80
#    2. Pad with 0x00 until length ≡ 56 (mod 64)  [= 448 mod 512 bits]
#    3. Append original bit-length as 64-bit LITTLE-ENDIAN integer
#    Result: <56 chars → 1 block | ≥56 chars → 2+ blocks
#
#  ROUND FUNCTIONS AND MESSAGE INDEX g:
#    Round 1 (j=0..15):  F=(B&C)|(~B&D)         g=j
#    Round 2 (j=16..31): G=(D&B)|(~D&C)          g=(5j+1) mod 16
#    Round 3 (j=32..47): H=B^C^D                 g=(3j+5) mod 16
#    Round 4 (j=48..63): I=C^(B|~D)              g=(7j)   mod 16
#
#  ONE OPERATION (memorise this pattern):
#    F = round_func(B, C, D)
#    inner = (A + F + M[g] + T[j]) mod 2^32
#    B = B + leftrotate(inner, s[j])    (all mod 2^32)
#    A, B, C, D = D, new_B, B_old, C_old
# ═══════════════════════════════════════════════════════════════════════════════

# T[j] = floor(2^32 * |sin(j+1)|)  — precomputed sine-based constants
_MD5_T = [int(2**32 * abs(math.sin(i+1))) & 0xFFFFFFFF for i in range(64)]

# Shift amounts for left-rotate per operation (4 rounds × pattern × 4 repetitions)
_MD5_S = [7,12,17,22, 7,12,17,22, 7,12,17,22, 7,12,17,22,   # Round 1
          5, 9,14,20, 5, 9,14,20, 5, 9,14,20, 5, 9,14,20,   # Round 2
          4,11,16,23, 4,11,16,23, 4,11,16,23, 4,11,16,23,   # Round 3
          6,10,15,21, 6,10,15,21, 6,10,15,21, 6,10,15,21]   # Round 4

def md5(message):
    if isinstance(message, str): message = message.encode('utf-8')
    orig_bits = len(message) * 8
    print(f"Input: '{message.decode(errors='replace')}'")
    print(f"Length: {len(message)} chars | {orig_bits} bits")
    print(f"Hex: {message.hex()}")
    # Classify block count (this is the first part of what midterm tested)
    if orig_bits < 448:   print("Test Case: <448 bits → 1 block")
    elif orig_bits == 448: print("Test Case: =448 bits → 2 blocks (padding needs new block)")
    else:                  print("Test Case: >448 bits → 2+ blocks")

    # ─ STEP 1: PAD ───────────────────────────────────────────────────────────
    msg = bytearray(message)
    msg.append(0x80)                                # Append 1-bit (as 0x80 byte)
    while len(msg) % 64 != 56: msg.append(0x00)    # Append 0-bits until 448 mod 512
    msg += struct.pack('<Q', orig_bits)             # Append 64-bit LE original length
    print(f"\nPadded message: {len(msg)} bytes = {len(msg)//64} block(s)")
    print(f"Padded hex: {msg.hex()}")

    # ─ STEP 2: INITIALIZE ────────────────────────────────────────────────────
    A, B, C, D = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476

    # ─ STEP 3: PROCESS EACH 512-BIT BLOCK ───────────────────────────────────
    for blk_num, blk_start in enumerate(range(0, len(msg), 64)):
        M = list(struct.unpack('<16I', msg[blk_start:blk_start+64]))  # 16 × 32-bit LE words
        print(f"\nBlock {blk_num+1}:")
        print(f"  M[0..3] = {[f'{x:08X}' for x in M[:4]]}  ...")
        AA, BB, CC, DD = A, B, C, D  # Save for chaining (added back at end of block)

        for j in range(64):
            if   j < 16: F = (B&C)|(~B&D) & 0xFFFFFFFF; g = j
            elif j < 32: F = (D&B)|(~D&C) & 0xFFFFFFFF; g = (5*j+1) % 16
            elif j < 48: F = B^C^D;                      g = (3*j+5) % 16
            else:        F = C^(B|~D);                   g = (7*j)   % 16
            F &= 0xFFFFFFFF
            inner = (A + F + M[g] + _MD5_T[j]) & 0xFFFFFFFF
            lr = ((inner << _MD5_S[j]) | (inner >> (32 - _MD5_S[j]))) & 0xFFFFFFFF
            # Rotate registers: new B = B+lr, others shift: A←D, C←B_old, D←C_old
            A, B, C, D = D, (B + lr) & 0xFFFFFFFF, B, C

            if (j+1) % 16 == 0:  # Print at end of each round
                rname = ["F (B&C|~B&D)","G (D&B|~D&C)","H (B^C^D)","I (C^(B|~D))"][j//16]
                print(f"  Round {j//16+1} [{rname}] end: A={A:08X} B={B:08X} C={C:08X} D={D:08X}")

        # Add block result to running hash (chaining)
        A=(AA+A)&0xFFFFFFFF; B=(BB+B)&0xFFFFFFFF; C=(CC+C)&0xFFFFFFFF; D=(DD+D)&0xFFFFFFFF

    # Output in little-endian byte order
    digest = struct.pack('<4I', A, B, C, D).hex()
    print(f"\nFinal MD5 Hash: {digest}")
    return digest


# ═══════════════════════════════════════════════════════════════════════════════
#  8. SHA-512  ─  standalone  (NOT in repo — written from scratch)
#  512-bit output, 1024-bit block, 80 rounds, 64-bit words, BIG-ENDIAN
#
#  PADDING ALGORITHM (different from MD5!):
#    1. Append byte 0x80
#    2. Pad with 0x00 until length ≡ 112 (mod 128)  [= 896 mod 1024 bits]
#    3. Append original bit-length as 128-bit BIG-ENDIAN integer
#    Result: <112 chars → 1 block | ≥112 chars → 2+ blocks
#
#  8 WORKING VARIABLES: a, b, c, d, e, f, g, h  (64-bit each)
#  SHA-512 FUNCTIONS:
#    Ch(e,f,g)  = (e AND f) XOR (NOT e AND g)
#    Maj(a,b,c) = (a AND b) XOR (a AND c) XOR (b AND c)
#    Σ0(a)      = ROTR28(a) XOR ROTR34(a) XOR ROTR39(a)
#    Σ1(e)      = ROTR14(e) XOR ROTR18(e) XOR ROTR41(e)
#    σ0(w)      = ROTR1(w)  XOR ROTR8(w)  XOR SHR7(w)   ← message schedule
#    σ1(w)      = ROTR19(w) XOR ROTR61(w) XOR SHR6(w)   ← message schedule
# ═══════════════════════════════════════════════════════════════════════════════

# Initial hash values (first 64 bits of fractional parts of sqrt of first 8 primes)
_SHA512_H = [0x6a09e667f3bcc908,0xbb67ae8584caa73b,0x3c6ef372fe94f82b,0xa54ff53a5f1d36f1,
             0x510e527fade682d1,0x9b05688c2b3e6c1f,0x1f83d9abfb41bd6b,0x5be0cd19137e2179]

# Round constants (first 64 bits of fractional parts of cube roots of first 80 primes)
_SHA512_K = [
    0x428a2f98d728ae22,0x7137449123ef65cd,0xb5c0fbcfec4d3b2f,0xe9b5dba58189dbbc,
    0x3956c25bf348b538,0x59f111f1b605d019,0x923f82a4af194f9b,0xab1c5ed5da6d8118,
    0xd807aa98a3030242,0x12835b0145706fbe,0x243185be4ee4b28c,0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f,0x80deb1fe3b1696b1,0x9bdc06a725c71235,0xc19bf174cf692694,
    0xe49b69c19ef14ad2,0xefbe4786384f25e3,0x0fc19dc68b8cd5b5,0x240ca1cc77ac9c65,
    0x2de92c6f592b0275,0x4a7484aa6ea6e483,0x5cb0a9dcbd41fbd4,0x76f988da831153b5,
    0x983e5152ee66dfab,0xa831c66d2db43210,0xb00327c898fb213f,0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2,0xd5a79147930aa725,0x06ca6351e003826f,0x142929670a0e6e70,
    0x27b70a8546d22ffc,0x2e1b21385c26c926,0x4d2c6dfc5ac42aed,0x53380d139d95b3df,
    0x650a73548baf63de,0x766a0abb3c77b2a8,0x81c2c92e47edaee6,0x92722c851482353b,
    0xa2bfe8a14cf10364,0xa81a664bbc423001,0xc24b8b70d0f89791,0xc76c51a30654be30,
    0xd192e819d6ef5218,0xd69906245565a910,0xf40e35855771202a,0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8,0x1e376c085141ab53,0x2748774cdf8eeb99,0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63,0x4ed8aa4ae3418acb,0x5b9cca4f7763e373,0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc,0x78a5636f43172f60,0x84c87814a1f0ab72,0x8cc702081a6439ec,
    0x90befffa23631e28,0xa4506cebde82bde9,0xbef9a3f7b2c67915,0xc67178f2e372532b,
    0xca273eceea26619c,0xd186b8c721c0c207,0xeada7dd6cde0eb1e,0xf57d4f7fee6ed178,
    0x06f067aa72176fba,0x0a637dc5a2c898a6,0x113f9804bef90dae,0x1b710b35131c471b,
    0x28db77f523047d84,0x32caab7b40c72493,0x3c9ebe0a15c9bebc,0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6,0x597f299cfc657e2a,0x5fcb6fab3ad6faec,0x6c44198c4a475817
]

def sha512(message, verbose=True):
    if isinstance(message, str): message = message.encode('utf-8')
    orig = len(message) * 8
    if verbose:
        print(f"Input: '{message.decode(errors='replace')}'")
        print(f"Length: {len(message)} chars = {orig} bits")
        if orig < 896:   print("Test Case: <896 bits (<112 chars) → 1 block")
        elif orig == 896: print("Test Case: =896 bits (=112 chars) → 2 blocks")
        else:             print("Test Case: >896 bits (>112 chars) → 2+ blocks")

    # ─ PAD ───────────────────────────────────────────────────────────────────
    msg = bytearray(message)
    msg.append(0x80)
    while len(msg) % 128 != 112: msg.append(0x00)  # Pad to 112 mod 128 bytes
    msg += struct.pack('>QQ', 0, orig)              # 128-bit big-endian length (upper 64=0)
    if verbose: print(f"Padded: {len(msg)} bytes = {len(msg)//128} block(s)")

    H = list(_SHA512_H)
    M64 = 0xFFFFFFFFFFFFFFFF                        # 64-bit mask

    for blk_num, blk_start in enumerate(range(0, len(msg), 128)):
        W = list(struct.unpack('>16Q', msg[blk_start:blk_start+128]))  # 16 × 64-bit BE words
        # Message schedule: expand W from 16 to 80 words
        for i in range(16, 80):
            s0 = (W[i-15]>>1|W[i-15]<<63)&M64 ^ (W[i-15]>>8|W[i-15]<<56)&M64 ^ W[i-15]>>7
            s1 = (W[i-2]>>19|W[i-2]<<45)&M64  ^ (W[i-2]>>61|W[i-2]<<3)&M64  ^ W[i-2]>>6
            W.append((W[i-16]+s0+W[i-7]+s1) & M64)

        if verbose: print(f"\nBlock {blk_num+1}: W[0]={W[0]:016X} W[1]={W[1]:016X} ...")
        a,b,c,d,e,f,g,h = H                        # Initialize working variables

        for i in range(80):
            S1  = (e>>14|e<<50)&M64 ^ (e>>18|e<<46)&M64 ^ (e>>41|e<<23)&M64   # Σ1(e)
            Ch  = (e&f) ^ (~e&g) & M64                                           # Ch(e,f,g)
            T1  = (h + S1 + Ch + _SHA512_K[i] + W[i]) & M64
            S0  = (a>>28|a<<36)&M64 ^ (a>>34|a<<30)&M64 ^ (a>>39|a<<25)&M64   # Σ0(a)
            Maj = (a&b) ^ (a&c) ^ (b&c)                                          # Maj(a,b,c)
            T2  = (S0 + Maj) & M64
            h,g,f,e = g,f,e,(d+T1)&M64
            d,c,b,a = c,b,a,(T1+T2)&M64

            if verbose and (i+1) % 16 == 0:
                print(f"  After round {i+1:2d}: a={a:016X} e={e:016X}")

        H = [(H[i]+v)&M64 for i,v in enumerate([a,b,c,d,e,f,g,h])]

    digest = ''.join(f'{v:016x}' for v in H)
    if verbose: print(f"\nFinal SHA-512: {digest}")
    return digest

def sha512_timing():
    """Measure SHA-512 execution time for varying message sizes."""
    print(f"\n{'─'*45}")
    print(f"{'Size (chars)':>15} | {'SHA-512 Time (ms)':>18}")
    print(f"{'─'*45}")
    for sz in [10, 100, 500, 1000, 5000, 10000, 50000, 100000]:
        t0 = time.perf_counter()
        sha512('a' * sz, verbose=False)
        t1 = time.perf_counter()
        print(f"{sz:>15} | {(t1-t0)*1000:>18.3f}")


# ═══════════════════════════════════════════════════════════════════════════════
#  9. DSS — Digital Signature Standard  ─  port 5009
#  (NOT in repo — written from scratch)
#  Parameters: prime q (160-bit), prime p (1024-bit, q|(p-1)), generator g
#  Keys: private x, public y = g^x mod p
#  SIGN:    k=random, r=(g^k mod p) mod q, s=k^-1*(H(m)+x*r) mod q → (r,s)
#  VERIFY:  w=s^-1 mod q, u1=H(m)*w mod q, u2=r*w mod q
#           v = (g^u1 * y^u2 mod p) mod q  →  valid if v == r
#  SERVER = Sender (signs). CLIENT = Receiver (verifies).
# ═══════════════════════════════════════════════════════════════════════════════

def _dss_gen_params():
    """Generate DSS parameters: q (160-bit prime), p (1024-bit prime, q|p-1), g."""
    print("Generating DSS parameters (q, p, g)... may take a few seconds")
    q = gen_prime(160)
    while True:
        k = random.getrandbits(864)                 # 864 + 160 = 1024 bits
        p = k * q + 1
        if p.bit_length() == 1024 and miller_rabin(p): break
    while True:
        h = random.randint(2, p-2)
        g = pow(h, (p-1)//q, p)                    # g = h^((p-1)/q) mod p
        if g != 1: break
    return p, q, g

def run_dss(mode):
    PORT = 5009
    if mode == "server":
        # SENDER: generate params, sign message, send to receiver
        p, q, g = _dss_gen_params()
        x = random.randint(1, q-1)                  # Private key
        y = pow(g, x, p)                            # Public key: y = g^x mod p
        print(f"\np={p}\nq={q}\ng={g}\nx (private)={x}\ny (public) ={y}")
        s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT)); s.listen(1); print("\nWaiting for receiver...")
        conn, _ = s.accept()
        for val in [p, q, g, y]: sock_send(conn, val)  # Broadcast public params
        msg = input("Message to sign: ").strip()
        H = int(sha512(msg, verbose=False), 16) % q
        print(f"H(m) mod q = {H}")
        # Generate signature (r, s)
        while True:
            k = random.randint(1, q-1)
            r = pow(g, k, p) % q
            if r == 0: continue
            sig_s = (mod_inv(k, q) * (H + x*r)) % q
            if sig_s != 0: break
        print(f"\nSignature: r={r}\n           s={sig_s}")
        # Test case 1: valid signature
        sock_send(conn, msg); sock_send(conn, r); sock_send(conn, sig_s)
        ack = sock_recv(conn); print(f"Receiver says: {ack}")
        # Test case 2: invalid signature (tamper s)
        print("\n--- Test Case 2: Tampered signature (s+1) ---")
        sock_send(conn, msg); sock_send(conn, r); sock_send(conn, sig_s + 1)
        ack = sock_recv(conn); print(f"Receiver says: {ack}")
        conn.close(); s.close()
    else:
        # RECEIVER: get params, verify signature
        c = socket.socket(); c.connect((HOST, PORT))
        p=int(sock_recv(c)); q=int(sock_recv(c)); g=int(sock_recv(c)); y=int(sock_recv(c))
        print(f"Received public params:\np={p}\nq={q}\ng={g}\ny={y}")
        for tc in range(1, 3):
            msg=sock_recv(c); r=int(sock_recv(c)); sig_s=int(sock_recv(c))
            print(f"\n--- Test Case {tc} ---")
            print(f"Message: '{msg}'\nr={r}\ns={sig_s}")
            H = int(sha512(msg, verbose=False), 16) % q
            if not (0 < r < q and 0 < sig_s < q):
                result = False
            else:
                w  = mod_inv(sig_s, q)
                u1 = (H * w) % q
                u2 = (r * w) % q
                v  = (pow(g, u1, p) * pow(y, u2, p) % p) % q
                result = (v == r)
                print(f"w={w}, u1={u1}, u2={u2}, v={v}")
            print(f"Signature: {'VALID ✓' if result else 'INVALID ✗'}")
            sock_send(c, f"Signature {'VALID' if result else 'INVALID'}")
        c.close()


# ═══════════════════════════════════════════════════════════════════════════════
#  10. CLASSICAL CIPHERS  ─  port 5010
#  From repo: Ex1a (Caesar, Vigenere, Vernam) | Ex1b (Playfair, Hill) | Ex1c (Rail Fence, Row Col)
#  SERVER = Receiver (decrypts). CLIENT = Sender (encrypts).
# ═══════════════════════════════════════════════════════════════════════════════

# ── Caesar Cipher (shift by key) ─────────────────────────────────────────────
def caesar_enc(text, k): return ''.join(chr((ord(c)-65+k)%26+65) if c.isupper() else chr((ord(c)-97+k)%26+97) if c.islower() else c for c in text)
def caesar_dec(text, k): return caesar_enc(text, -k)

# ── Vigenere Cipher (repeating key shifts) ───────────────────────────────────
def vigenere_enc(text, key):
    enc=""; ki=0; key=key.lower()
    for c in text:
        if c.isalpha():
            sh=ord(key[ki%len(key)])-97; base=65 if c.isupper() else 97
            enc+=chr((ord(c)-base+sh)%26+base); ki+=1
        else: enc+=c
    return enc
def vigenere_dec(text, key):
    dec=""; ki=0; key=key.lower()
    for c in text:
        if c.isalpha():
            sh=ord(key[ki%len(key)])-97; base=65 if c.isupper() else 97
            dec+=chr((ord(c)-base-sh)%26+base); ki+=1
        else: dec+=c
    return dec

# ── Vernam Cipher (one-time pad XOR) ─────────────────────────────────────────
def vernam_enc(text, key): return ''.join(chr(ord(t)^ord(k)) for t,k in zip(text,key))
def vernam_dec(text, key): return vernam_enc(text, key)   # XOR is its own inverse

# ── Playfair Cipher (5x5 matrix, digraph substitution) ───────────────────────
def _pf_matrix(key):
    key=key.upper().replace("J","I"); used=set(); m=[]
    for c in key+string.ascii_uppercase:
        if c!="J" and c not in used: used.add(c); m.append(c)
    return [m[i:i+5] for i in range(0,25,5)]
def _pf_prep(text):
    text=text.upper().replace("J","I"); text=''.join(c for c in text if c.isalpha()); r=""; i=0
    while i<len(text):
        a=text[i]; b=text[i+1] if i+1<len(text) else "X"
        if a==b: r+=a+"X"; i+=1
        else: r+=a+b; i+=2
    return r+("X" if len(r)%2 else "")
def _pf_pos(m, c): return next((i,j) for i in range(5) for j in range(5) if m[i][j]==c)
def playfair_enc(text, key):
    m=_pf_matrix(key); text=_pf_prep(text); ct=""
    for i in range(0,len(text),2):
        a,b=text[i],text[i+1]; r1,c1=_pf_pos(m,a); r2,c2=_pf_pos(m,b)
        if r1==r2:   ct+=m[r1][(c1+1)%5]+m[r2][(c2+1)%5]
        elif c1==c2: ct+=m[(r1+1)%5][c1]+m[(r2+1)%5][c2]
        else:        ct+=m[r1][c2]+m[r2][c1]
    return ct
def playfair_dec(text, key):
    m=_pf_matrix(key); pt=""
    for i in range(0,len(text),2):
        a,b=text[i],text[i+1]; r1,c1=_pf_pos(m,a); r2,c2=_pf_pos(m,b)
        if r1==r2:   pt+=m[r1][(c1-1)%5]+m[r2][(c2-1)%5]
        elif c1==c2: pt+=m[(r1-1)%5][c1]+m[(r2-1)%5][c2]
        else:        pt+=m[r1][c2]+m[r2][c1]
    return pt

# ── Hill Cipher (2×2 matrix multiply mod 26) ─────────────────────────────────
def hill_enc(text, K):
    text=text.upper().replace(" ",""); text+="X"*(len(text)%2); ct=""
    for i in range(0,len(text),2):
        p1=ord(text[i])-65; p2=ord(text[i+1])-65
        ct+=chr((K[0][0]*p1+K[0][1]*p2)%26+65)+chr((K[1][0]*p1+K[1][1]*p2)%26+65)
    return ct
def hill_dec(text, IK):
    pt=""
    for i in range(0,len(text),2):
        c1=ord(text[i])-65; c2=ord(text[i+1])-65
        pt+=chr((IK[0][0]*c1+IK[0][1]*c2)%26+65)+chr((IK[1][0]*c1+IK[1][1]*c2)%26+65)
    return pt

# ── Rail Fence Cipher (zigzag transposition) ─────────────────────────────────
def rail_enc(text, k):
    rails=[""]*k; r=0; d=1
    for c in text:
        rails[r]+=c
        if r==0: d=1
        elif r==k-1: d=-1
        r+=d
    return "".join(rails)
def rail_dec(cipher, k):
    rail=[["\n"]*len(cipher) for _ in range(k)]; r=0; d=1
    for col in range(len(cipher)):
        rail[r][col]="*"
        if r==0: d=1
        elif r==k-1: d=-1
        r+=d
    idx=0
    for i in range(k):
        for j in range(len(cipher)):
            if rail[i][j]=="*": rail[i][j]=cipher[idx]; idx+=1
    res=[]; r=0; d=1
    for col in range(len(cipher)):
        res.append(rail[r][col])
        if r==0: d=1
        elif r==k-1: d=-1
        r+=d
    return "".join(res)

# ── Row Column Transposition ──────────────────────────────────────────────────
def rowcol_enc(text, key):
    text=text.replace(" ",""); key=[int(k) for k in key]; cols=len(key)
    rows=math.ceil(len(text)/cols); text+="*"*(rows*cols-len(text))
    mat=[text[i:i+cols] for i in range(0,len(text),cols)]
    order=sorted(range(cols),key=lambda i:key[i]); ct=""
    for col in order:
        for row in mat: ct+=row[col]
    return ct
def rowcol_dec(cipher, key):
    key=[int(k) for k in key]; cols=len(key)
    rows=math.ceil(len(cipher)/cols); mat=[[""]*cols for _ in range(rows)]
    order=sorted(range(cols),key=lambda i:key[i]); idx=0
    for col in order:
        for row in range(rows): mat[row][col]=cipher[idx]; idx+=1
    return "".join("".join(row) for row in mat).rstrip("*")

def run_classical(mode):
    PORT = 5010
    print("  1=Caesar  2=Vigenere  3=Vernam  4=Playfair  5=Hill  6=RailFence  7=RowCol")
    ch = input("Choose cipher: ").strip()
    if mode == "server":
        s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT)); s.listen(1); print("Waiting for sender (client)...")
        conn, _ = s.accept(); ct = sock_recv(conn); print(f"Received ciphertext: {ct}")
        if ch=="1":   key=int(input("Key (int): ")); print("Decrypted:", caesar_dec(ct,key))
        elif ch=="2": key=input("Key: ");             print("Decrypted:", vigenere_dec(ct,key))
        elif ch=="3": key=input("Key: ");             print("Decrypted:", vernam_dec(ct,key))
        elif ch=="4": key=input("Key: ");             print("Decrypted:", playfair_dec(ct,key))
        elif ch=="5":
            print("Enter inv key matrix row by row (e.g. '15 17' then '20 9'):")
            r0=list(map(int,input().split())); r1=list(map(int,input().split()))
            print("Decrypted:", hill_dec(ct,[r0,r1]))
        elif ch=="6": k=int(input("Rails: ")); print("Decrypted:", rail_dec(ct,k))
        elif ch=="7": key=input("Key (digits): "); print("Decrypted:", rowcol_dec(ct,key))
        conn.close(); s.close()
    else:
        c = socket.socket(); c.connect((HOST, PORT))
        pt = input("Plaintext: ").strip()
        if ch=="1":   key=int(input("Key (int): ")); ct=caesar_enc(pt,key)
        elif ch=="2": key=input("Key: ");             ct=vigenere_enc(pt,key)
        elif ch=="3": key=input("Key (same length as plaintext): "); ct=vernam_enc(pt,key)
        elif ch=="4": key=input("Key: ");             ct=playfair_enc(pt.upper(),key)
        elif ch=="5":
            print("Enter key matrix row by row (e.g. '3 3' then '2 5'):")
            r0=list(map(int,input().split())); r1=list(map(int,input().split()))
            ct=hill_enc(pt,[r0,r1])
        elif ch=="6": k=int(input("Rails: ")); ct=rail_enc(pt,k)
        elif ch=="7": key=input("Key (digit string e.g. '4312567'): "); ct=rowcol_enc(pt,key)
        print(f"Ciphertext: {ct}"); sock_send(c, ct); c.close()


# ═══════════════════════════════════════════════════════════════════════════════
#  MAIN MENU
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("=" * 65)
    print("  No crypto libraries. From scratch. Server-client sockets.")
    print("=" * 65)
    print()
    print("  ALGORITHM              NOTES")
    print("  ─────────────────────────────────────────────────────────")
    print("   1  S-DES              10-bit key, 8-bit block, 2 rounds")
    print("   2  DES                64-bit key, 16 rounds, HEX output")
    print("   3  AES-128            128-bit key, 10 rounds, SPN")
    print("   4  RSA                1024-bit, e=65537, Miller-Rabin")
    print("   5  ElGamal            512-bit prime, alpha=2")
    print("   6  DH + MITM          primitive root computed, not assumed")
    print("   7  MD5                128-bit hash, standalone")
    print("   8  SHA-512            512-bit hash, standalone + timing")
    print("   9  DSS                sign+verify, SHA-512 hash, sockets")
    print("  10  Classical Ciphers  Caesar/Vigenere/Vernam/Playfair/Hill/Rail/RowCol")
    print()

    ch = input("Select [1-10]: ").strip()

    if ch in ("1","2","3","4","5","9","10"):
        mode = input("Mode [server/client]: ").strip().lower()
        if ch=="1":   run_sdes(mode)
        elif ch=="2": run_des(mode)
        elif ch=="3": run_aes(mode)
        elif ch=="4": run_rsa(mode)
        elif ch=="5": run_elgamal(mode)
        elif ch=="9": run_dss(mode)
        elif ch=="10":run_classical(mode)

    elif ch == "6":
        role = input("Role [alice/bob/attacker]: ").strip().lower()
        run_dh_mitm(role)

    elif ch == "7":
        print("MD5 Test Cases:")
        print("  1  <448 bits (<56 chars)  — 1 block")
        print("  2  =448 bits (=56 chars)  — 2 blocks")
        print("  3  >448 bits (>56 chars)  — 2+ blocks")
        print("  4  Custom input")
        tc = input("Select [1-4]: ").strip()
        print()
        if tc=="1":   md5("hello")
        elif tc=="2": md5("a"*56)
        elif tc=="3": md5("a"*57)
        else:         md5(input("Input string: ").strip())

    elif ch == "8":
        print("SHA-512 Test Cases:")
        print("  1  <896 bits (<112 chars)  — 1 block")
        print("  2  =896 bits (=112 chars)  — 2 blocks")
        print("  3  >896 bits (>112 chars)  — 2+ blocks")
        print("  4  Custom input")
        print("  5  Timing benchmark (varying sizes)")
        tc = input("Select [1-5]: ").strip()
        print()
        if tc=="1":   sha512("hello")
        elif tc=="2": sha512("a"*112)
        elif tc=="3": sha512("a"*113)
        elif tc=="4": sha512(input("Input string: ").strip())
        elif tc=="5": sha512_timing()



# Server.py
import socket
import crypto_functions as cf

key = "keykey"

def encrypt(text):
    return cf.vernam_encrypt(text,key)
def decrypt(text):
    return cf.vernam_decrypt(text,key)


server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

host = "127.0.0.1"
port = 12345
server_socket.bind((host,port))
server_socket.listen(1)
print(f"Server listening on {host}:{port}")


connection, address = server_socket.accept()
print(f"Connected to {address}")


while True:
    data = connection.recv(1024).decode()
    print(f"Encrypted message from client: {data}")
    data = decrypt(data)
    print(f"Decrypted message from client: {data}\n")

    if data.lower() == "exit":
        print("Exiting...")
        break
        

    msg = input("You: ")
    enc_msg = encrypt(msg)
    print(f"Encrypted message sent to client: {enc_msg}\n")
    connection.send(enc_msg.encode())

connection.close()
server_socket.close() 



#client.py
import socket
import crypto_functions as cf
key = "keykey"
def encrypt(text):
    return cf.vernam_encrypt(text,key)
def decrypt(text):
    return cf.vernam_decrypt(text,key)

client_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
host = "127.0.0.1"
port = 12345
client_socket.connect((host, port))
print("Conected to the server")

while True:
    message = input("You: ")
    message = encrypt(message)
    print(f"Encrypted message sent to server: {message}\n")
    client_socket.send(message.encode())
    if message.lower() == "exit":
        break
    msg = client_socket.recv(1024).decode()
    print(f"Encrypted message from server: {msg}")
    data = decrypt( msg)
    print(f"Decrypted message from server: {data}\n")
client_socket.close()
