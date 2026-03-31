import socket
import threading
import crypto_functions as cf

def receive_messages(client, key, running):
    while running[0]:
        try:
            encrypted = client.recv(4096).decode().strip()
            if not encrypted:
                break
            decrypted = cf.decrypt_message(encrypted, key)
            print(f"\nAlice: {decrypted}")
            print("You: ", end="", flush=True)
        except:
            break

def main():
    print("=" * 50)
    print("BOB")
    print("=" * 50)
    
    q = int(input("Enter prime number (q): "))
    alpha = int(input("Enter primitive root (alpha): "))
    
    Xb = cf.generate_private_key(q)
    print(f"Private key (Xb): {Xb}")
    
    Yb = cf.compute_public_key(alpha, Xb, q)
    print(f"Public key (Yb): {Yb}")
    
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(("localhost", 8002))
    
    client.sendall(str(Yb).encode() + b'\n')
    
    data = client.recv(4096).decode().strip()
    Yd = int(data)
    print(f"Received public key from Alice: {Yd}")
    
    Kb = cf.compute_shared_key(Yd, Xb, q)
    print(f"Shared key: {Kb}")
    
    print("\n" + "=" * 50)
    print("CHAT STARTED (type 'exit' to quit)")
    print("=" * 50 + "\n")
    
    running = [True]
    receiver = threading.Thread(target=receive_messages, args=(client, Kb, running))
    receiver.daemon = True
    receiver.start()
    
    try:
        while True:
            message = input("You: ")
            if message.lower() == 'exit':
                running[0] = False
                break
            encrypted = cf.encrypt_message(message, Kb)
            client.sendall(encrypted.encode() + b'\n')
    except KeyboardInterrupt:
        running[0] = False
    
    client.close()

if __name__ == "__main__":
    main()