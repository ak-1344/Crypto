import socket
import crypto_functions as cf

key = "4312567"
def encrypt(text):
    return cf.row_column_encrypt(text,key)
def decrypt(text):
    return cf.row_column_decrypt(text,key)
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