import socket
import crypto_functions as cf

playfair_key = "MONARCHY"
hillcipher_key = [[3, 3],[2, 5]]
hillcipher_inv_key = [[15, 17],[20, 9]]

def encrypt(text):
    return cf.playfair_encrypt(text, playfair_key)
def decrypt(text):
    return cf.playfair_decrypt(text, playfair_key)

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
host = "127.0.0.1"
port = 12345

server_socket.bind((host, port))
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
