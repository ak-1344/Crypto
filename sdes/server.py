import socket
import crypto_functions as cf

key = "1100011110"
def encrypt(text):
    return cf.sdes_encrypt(text, key)
def decrypt(text):
    return cf.sdes_decrypt(text, key)

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
host = "127.0.0.1"
port = 12345
server_socket.bind((host, port))
server_socket.listen(1)
print(f"Server listening on {host}:{port}")

conn, addr = server_socket.accept()
print("Connected to", addr)
while True:
    plaintext = input("\nEnter 8-bit plaintext (or exit): ")
    if plaintext.lower() == "exit":
        conn.send(plaintext.encode())
        break
    cipher = encrypt(plaintext)
    conn.send(cipher.encode())
conn.close()
server_socket.close()