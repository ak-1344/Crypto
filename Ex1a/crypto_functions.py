def caesar_encrypt(text, key):
    encrypted_text = ""
    for char in text:
        if char.isupper():
            encrypted_text += chr( (ord(char) - ord('A') + key) %26 + ord('A'))
        elif char.islower():
            encrypted_text += chr( (ord(char) - ord('a') + key) %26 + ord('a'))
        else:
            encrypted_text+=char
    return encrypted_text

def caesar_decrypt(text, key):
    decrypt_text = ""
    for char in text:
        if char.isupper():
            decrypt_text += chr( (ord(char) - ord('A') -key) %26 + ord('A'))
        elif char.islower():
            decrypt_text += chr( (ord(char) - ord('a') -key) %26 + ord('a'))
        else:
            decrypt_text+=char
    return decrypt_text




def vigenere_encrypt(text, key):
    encrypted = ""
    key = key.lower()
    key_index = 0

    for char in text:
        if char.isalpha():
            shift = ord(key[key_index % len(key)]) - ord('a')

            if char.isupper():
                encrypted += chr( (ord(char) + shift - ord('A')) % 26 + ord('A'))
            else:
                encrypted += chr( (ord(char) + shift - ord('a')) % 26 + ord('a'))   
            key_index+=1
        else:
            encrypted += char
    return encrypted

def vigenere_decrypt(text, key):
    decrypt = ""
    key = key.lower()
    key_index = 0

    for char in text:
        if char.isalpha():
            shift = ord( key[key_index % len(key)] ) - ord('a')

            if char.isupper():
                decrypt+= chr( (ord(char) - ord('A') - shift) % 26 + ord('A'))
            else:
                decrypt+= chr( (ord(char) - ord('a') - shift) % 26 + ord('a'))
            key_index+=1
        else:
            decrypt+=char
    return decrypt




def vernam_encrypt(text, key):
    encrypted = ""
    for i in range(len(text)):
        encrypted += chr( ord(text[i]) ^ ord(key[i]))
    return encrypted

def vernam_decrypt(text, key):
    decrypted = ""
    for i in range(len(text)):
        decrypted += chr( ord(text[i]) ^ ord(key[i]))
    return decrypted




def main():
    msg = "Hello, World!"
    caesar_key = 4
    print("Original Message:", msg)
    encrypted_msg = caesar_encrypt(msg, caesar_key)
    print("Encrypted Message:", encrypted_msg)
    decrypted_msg = caesar_decrypt(encrypted_msg, caesar_key)
    print("Decrypted Message:", decrypted_msg)


    vigenere_key = "key"
    vigenere_encrypted = vigenere_encrypt(msg, vigenere_key)
    print("Vigenere Encrypted Message:", vigenere_encrypted)
    vigenere_decrypted = vigenere_decrypt(vigenere_encrypted, vigenere_key)
    print("Vigenere Decrypted Message:", vigenere_decrypted)

    vernam_key = "qwertwwasdfgo"
    vernam_encrypted = vernam_encrypt(msg, vernam_key)
    print("Vernam Encrypted Message:", vernam_encrypted)
    vernam_decrypted = vernam_decrypt(vernam_encrypted, vernam_key)
    print("Vernam Decrypted Message:", vernam_decrypted)
if __name__ == "__main__":
    main()