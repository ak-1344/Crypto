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
            print(f"\nBob: {decrypted}")
            print("You: ", end="", flush=True)
        except:
            break

def main():
    print("=" * 50)
    print("ALICE")
    print("=" * 50)
    
    q = int(input("Enter prime number (q): "))
    alpha = int(input("Enter primitive root (alpha): "))
    
    Xa = cf.generate_private_key(q)
    print(f"Private key (Xa): {Xa}")
    
    Ya = cf.compute_public_key(alpha, Xa, q)
    print(f"Public key (Ya): {Ya}")
    
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(("localhost", 8001))
    
    client.sendall(str(Ya).encode() + b'\n')
    
    data = client.recv(4096).decode().strip()
    Yd = int(data)
    print(f"Received public key from Bob: {Yd}")
    
    Ka = cf.compute_shared_key(Yd, Xa, q)
    print(f"Shared key: {Ka}")
    
    print("\n" + "=" * 50)
    print("CHAT STARTED (type 'exit' to quit)")
    print("=" * 50 + "\n")
    
    running = [True]
    receiver = threading.Thread(target=receive_messages, args=(client, Ka, running))
    receiver.daemon = True
    receiver.start()
    
    try:
        while True:
            message = input("You: ")
            if message.lower() == 'exit':
                running[0] = False
                break
            encrypted = cf.encrypt_message(message, Ka)
            client.sendall(encrypted.encode() + b'\n')
    except KeyboardInterrupt:
        running[0] = False
    
    client.close()

if __name__ == "__main__":
    main()