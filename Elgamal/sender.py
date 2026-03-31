import socket
import crypto_functions as cf

def main():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(("localhost", 8000))
    
    data = b''
    while data.count(b'\n') < 3:
        data += client.recv(4096)
    
    lines = data.decode().strip().split('\n')
    q = int(lines[0])
    alpha = int(lines[1])
    Ya = int(lines[2])
    
    print("--- ENCRYPTION BY SENDER ---")
    messageStr = input("Enter Plaintext message (M): ")
    
    k, K, C1, C2 = cf.encrypt(messageStr, q, alpha, Ya)
    
    print(f"Generated random integer k: {k}")
    print(f"Formula: K = (Ya^k) mod q")
    print(f"Calculated K: {K}")
    print(f"Formula: C1 = (alpha^k) mod q")
    print(f"Calculated C1: {C1}")
    print(f"Formula: C2 = (K * M) mod q")
    print(f"Calculated C2: {C2}")
    
    client.sendall(str(C1).encode() + b'\n')
    client.sendall(str(C2).encode() + b'\n')
    
    print("\nCiphertext (C1, C2) sent to Receiver.")
    
    client.close()

if __name__ == "__main__":
    main()