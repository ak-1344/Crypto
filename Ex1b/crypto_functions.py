# crypto_functions.py

import string

def generate_matrix(key):
    key = key.upper().replace("J", "I")
    matrix = []
    used = set()

    for ch in key + string.ascii_uppercase:
        if ch == "J":
            continue
        if ch not in used:
            used.add(ch)
            matrix.append(ch)

    return [matrix[i:i+5] for i in range(0, 25, 5)]


def prepare_text(text):
    text = text.upper().replace("J", "I")
    text = "".join(ch for ch in text if ch.isalpha())

    result = ""
    i = 0
    while i < len(text):
        a = text[i]
        b = text[i+1] if i+1 < len(text) else "X"

        if a == b:
            result += a + "X"
            i += 1
        else:
            result += a + b
            i += 2

    if len(result) % 2 != 0:
        result += "X"

    return result


def find_pos(matrix, ch):
    for i in range(5):
        for j in range(5):
            if matrix[i][j] == ch:
                return i, j


def playfair_encrypt(text, key):
    matrix = generate_matrix(key)
    text = prepare_text(text)
    cipher = ""

    for i in range(0, len(text), 2):
        a, b = text[i], text[i+1]
        r1, c1 = find_pos(matrix, a)
        r2, c2 = find_pos(matrix, b)

        if r1 == r2:
            cipher += matrix[r1][(c1+1)%5] + matrix[r2][(c2+1)%5]
        elif c1 == c2:
            cipher += matrix[(r1+1)%5][c1] + matrix[(r2+1)%5][c2]
        else:
            cipher += matrix[r1][c2] + matrix[r2][c1]

    return cipher


def playfair_decrypt(text, key):
    matrix = generate_matrix(key)
    plain = ""

    for i in range(0, len(text), 2):
        a, b = text[i], text[i+1]
        r1, c1 = find_pos(matrix, a)
        r2, c2 = find_pos(matrix, b)

        if r1 == r2:
            plain += matrix[r1][(c1-1)%5] + matrix[r2][(c2-1)%5]
        elif c1 == c2:
            plain += matrix[(r1-1)%5][c1] + matrix[(r2-1)%5][c2]
        else:
            plain += matrix[r1][c2] + matrix[r2][c1]

    return plain






def hill_encrypt(text, key):
    text = text.upper().replace(" ", "")
    if len(text) % 2 != 0:
        text += "X"

    cipher = ""
    for i in range(0, len(text), 2):
        p1 = ord(text[i]) - ord('A')
        p2 = ord(text[i+1]) - ord('A')

        c1 = (key[0][0]*p1 + key[0][1]*p2) % 26
        c2 = (key[1][0]*p1 + key[1][1]*p2) % 26

        cipher += chr(c1 + ord('A')) + chr(c2 + ord('A'))

    return cipher


def hill_decrypt(text, inv_key):
    plain = ""
    for i in range(0, len(text), 2):
        c1 = ord(text[i]) - ord('A')
        c2 = ord(text[i+1]) - ord('A')

        p1 = (inv_key[0][0]*c1 + inv_key[0][1]*c2) % 26
        p2 = (inv_key[1][0]*c1 + inv_key[1][1]*c2) % 26

        plain += chr(p1 + ord('A')) + chr(p2 + ord('A'))

    return plain





def main():
    print("----------- PLAYFAIR CIPHER TEST -----------")

    playfair_key = "MONARCHY"
    message = "HELLO WORLD"

    print("Original Message       :", message)
    print("Key Used               :", playfair_key)

    prepared_text = prepare_text(message)
    print("Prepared Plaintext     :", prepared_text)

    matrix = generate_matrix(playfair_key)
    print("Playfair Key Matrix    :")
    for row in matrix:
        print(row)

    encrypted = playfair_encrypt(message, playfair_key)
    print("Encrypted Message     :", encrypted)

    decrypted = playfair_decrypt(encrypted, playfair_key)
    print("Decrypted Message     :", decrypted)

    print("\n")



    print("---------- HILL CIPHER TEST ----------")

    hill_key = [[3, 3],[2, 5]]

    hill_inv_key = [[15, 17],[20, 9]]  

    message = "HELLO"

    print("Original Message       :", message)
    print("Key Matrix             :", hill_key)
    print("Inverse Key Matrix     :", hill_inv_key)

    if len(message) % 2 != 0:
        print("Padding applied        : X")

    encrypted = hill_encrypt(message, hill_key)
    print("Encrypted Message     :", encrypted)

    decrypted = hill_decrypt(encrypted, hill_inv_key)
    print("Decrypted Message     :", decrypted)


if __name__ == "__main__":
    main()
