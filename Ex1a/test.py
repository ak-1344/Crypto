import crypto_functions as cf

msg = "Hello, World!"

caesar_key = 4
print("Original Message:", msg)
encrypted_msg = cf.caesar_encrypt(msg, caesar_key)
print("Encrypted Message:", encrypted_msg)
decrypted_msg = cf.caesar_decrypt(encrypted_msg, caesar_key)
print("Decrypted Message:", decrypted_msg)


vigenere_key = "key"
vigenere_encrypted = cf.vigenere_encrypt(msg, vigenere_key)
print("Vigenere Encrypted Message:", vigenere_encrypted)
vigenere_decrypted = cf.vigenere_decrypt(vigenere_encrypted, vigenere_key)
print("Vigenere Decrypted Message:", vigenere_decrypted)

vernam_key = "qwertwwasdfgo"
vernam_encrypted = cf.vernam_encrypt(msg, vernam_key)
print("Vernam Encrypted Message:", vernam_encrypted)
vernam_decrypted = cf.vernam_decrypt(vernam_encrypted, vernam_key)
print("Vernam Decrypted Message:", vernam_decrypted)