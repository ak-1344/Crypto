import socket
import crypto_functions as cf

key = "1100011110"
def encrypt(text):
    return cf.sdes_encrypt(text, key)

def decrypt(text):
    return cf.sdes_decrypt(text, key)

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
host = "127.0.0.1"
port = 12345
client_socket.connect((host, port))
print("Connected to server")
while True:
    cipher = client_socket.recv(1024).decode()
    if cipher.lower() == "exit":
        break
    decrypt(cipher)
client_socket.close()