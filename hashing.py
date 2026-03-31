import struct
import math

# MD5 Constants
T = [int(2**32 * abs(math.sin(i + 1))) & 0xFFFFFFFF for i in range(64)]
S = [
    7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
    5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
    4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
    6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,
]
A0, B0, C0, D0 = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476

def left_rotate(x, n): return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF
def F(b,c,d): return (b & c) | (~b & d)
def G(b,c,d): return (b & d) | (c & ~d)
def H(b,c,d): return b ^ c ^ d
def I(b,c,d): return c ^ (b | ~d)

def pad(msg):
    orig_len_bits = len(msg) * 8
    msg += b'\x80'
    while len(msg) % 64 != 56:
        msg += b'\x00'
    msg += struct.pack('<Q', orig_len_bits)
    return msg

def md5(message: bytes):
    print(f"\nNumber of characters in input: {len(message)}")

    padded = pad(message)
    total_blocks = len(padded) // 64

    a, b, c, d = A0, B0, C0, D0

    for blk_idx in range(total_blocks):
        block = padded[blk_idx * 64 : (blk_idx+1) * 64]
        M = list(struct.unpack('<16I', block))

        print(f"\nBlock {blk_idx + 1}")

        AA, BB, CC, DD = a, b, c, d

        # Capture round start states
        round_start = {}
        a_r, b_r, c_r, d_r = a, b, c, d
        for i in range(64):
            if i % 16 == 0:
                round_start[i // 16] = (a_r, b_r, c_r, d_r)
            rn = i // 16
            if rn == 0:   f_val = F(b_r,c_r,d_r); g = i
            elif rn == 1: f_val = G(b_r,c_r,d_r); g = (5*i+1) % 16
            elif rn == 2: f_val = H(b_r,c_r,d_r); g = (3*i+5) % 16
            else:         f_val = I(b_r,c_r,d_r); g = (7*i) % 16
            temp = left_rotate((f_val + a_r + M[g] + T[i]) & 0xFFFFFFFF, S[i])
            a_r, b_r, c_r, d_r = d_r, (temp + b_r) & 0xFFFFFFFF, b_r, c_r

        final_state = (a_r, b_r, c_r, d_r)

        # Print each round's start and end state
        rnames = ["Round 1 (F)", "Round 2 (G)", "Round 3 (H)", "Round 4 (I)"]
        a_r, b_r, c_r, d_r = a, b, c, d
        for rnd in range(4):
            ra, rb, rc, rd = round_start[rnd]
            for i in range(rnd*16, (rnd+1)*16):
                rn = i // 16
                if rn == 0:   f_val = F(rb,rc,rd); g = i
                elif rn == 1: f_val = G(rb,rc,rd); g = (5*i+1) % 16
                elif rn == 2: f_val = H(rb,rc,rd); g = (3*i+5) % 16
                else:         f_val = I(rb,rc,rd); g = (7*i) % 16
                temp = left_rotate((f_val + ra + M[g] + T[i]) & 0xFFFFFFFF, S[i])
                ra, rb, rc, rd = rd, (temp + rb) & 0xFFFFFFFF, rb, rc

            rs = round_start[rnd]
            print(f"  {rnames[rnd]}")
            print(f"    Start : A={rs[0]:08X} B={rs[1]:08X} C={rs[2]:08X} D={rs[3]:08X}")
            print(f"    End   : A={ra:08X} B={rb:08X} C={rc:08X} D={rd:08X}")

        # Add chaining values
        a = (AA + final_state[0]) & 0xFFFFFFFF
        b = (BB + final_state[1]) & 0xFFFFFFFF
        c = (CC + final_state[2]) & 0xFFFFFFFF
        d = (DD + final_state[3]) & 0xFFFFFFFF

    print(f"\nFinal Hash Value: {struct.pack('<4I', a, b, c, d).hex()}")


if __name__ == "__main__":
    user_input = input("Enter input string: ")
    md5(user_input.encode())