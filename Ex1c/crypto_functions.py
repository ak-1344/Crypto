# crypto_functions.py
import math

# RAIL FENCE CIPHER
def rail_fence_encrypt(text, key):
    rails = ['' for _ in range(key)]
    row, direction = 0, 1
    for ch in text:
        rails[row] += ch
        if row == 0:
            direction = 1
        elif row == key - 1:
            direction = -1
        row += direction
    return ''.join(rails)

def rail_fence_decrypt(cipher, key):
    rail = [['\n' for _ in range(len(cipher))] for _ in range(key)]
    row, direction = 0, 1
    for col in range(len(cipher)):
        rail[row][col] = '*'
        if row == 0:
            direction = 1
        elif row == key - 1:
            direction = -1
        row += direction
    index = 0
    for i in range(key):
        for j in range(len(cipher)):
            if rail[i][j] == '*' and index < len(cipher):
                rail[i][j] = cipher[index]
                index += 1
    result = []
    row, direction = 0, 1
    for col in range(len(cipher)):
        result.append(rail[row][col])
        if row == 0:
            direction = 1
        elif row == key - 1:
            direction = -1
        row += direction
    return ''.join(result)


# ROW COLUMN CIPHER
def row_column_encrypt(text, key):
    text = text.replace(" ", "")
    key = [int(k) for k in key]
    cols = len(key)
    rows = math.ceil(len(text) / cols)
    text += '*' * (rows * cols - len(text))
    matrix = [text[i:i+cols] for i in range(0, len(text), cols)]
    order = sorted(range(cols), key=lambda i: key[i])
    cipher = ""
    for col in order:
        for row in matrix:
            cipher += row[col]
    return cipher

def row_column_decrypt(cipher, key):
    key = [int(k) for k in key]
    cols = len(key)
    rows = math.ceil(len(cipher) / cols)
    matrix = [['' for _ in range(cols)] for _ in range(rows)]
    order = sorted(range(cols), key=lambda i: key[i])
    index = 0
    for col in order:
        for row in range(rows):
            matrix[row][col] = cipher[index]
            index += 1
    plain = ""
    for row in matrix:
        plain += ''.join(row)
    return plain.rstrip('*')


# MAIN FUNCTION (TESTING)
def main():
    print("RAIL FENCE CIPHER")
    msg = "HELLO WORLD"
    key = 3
    enc = rail_fence_encrypt(msg, key)
    dec = rail_fence_decrypt(enc, key)
    print("PT :", msg)
    print("CT :", enc)
    print("DT :", dec)
    print()
    print("ROW COLUMN CIPHER")
    msg = "attack postponed until two am"
    key = "4312567"
    enc = row_column_encrypt(msg, key)
    dec = row_column_decrypt(enc, key)
    print("PT :", msg)
    print("Key:", key)
    print("CT :", enc)
    print("DT :", dec)

if __name__ == "__main__":
    main()
