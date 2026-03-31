import socket
import crypto_functions as cf

playfair_key = "MONARCHY"

hillcipher_key = [[3, 3],
       [2, 5]]

hillcipher_inv_key = [[15, 17],
           [20, 9]]

def encrypt(text):
    return cf.playfair_encrypt(text, playfair_key)
def decrypt(text):
    return cf.playfair_decrypt(text, playfair_key)


client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
host = "127.0.0.1"
port = 12345

client_socket.connect((host, port))
print("Connected to the server")

while True:
    message = input("You: ")
    message = encrypt(message)
    print(f"Encrypted message sent to server: {message}\n")
    client_socket.send(message.encode())

    if decrypt(message).lower() == "exit":
        break

    msg = client_socket.recv(1024).decode()
    print(f"Encrypted message from server: {msg}")

    data = decrypt(msg)
    print(f"Decrypted message from server: {data}\n")

client_socket.close()
