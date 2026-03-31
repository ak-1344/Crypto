import socket
import crypto_functions as cf

def main():
    print("--- KEY GENERATION BY RECEIVER ---")
    
    q, alpha, Xa, Ya = cf.key_generation()
    
    print(f"Generated q (prime number): {q}")
    print(f"Generated alpha (primitive root of q): {alpha}")
    print(f"Generated Xa (private key): {Xa}")
    print(f"Formula: Ya = (alpha^Xa) mod q")
    print(f"Calculated Ya (public key): {Ya}")
    
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("localhost", 8000))
    server.listen(1)
    
    print("\nWaiting for Sender...")
    
    conn, addr = server.accept()
    
    conn.sendall(str(q).encode() + b'\n')
    conn.sendall(str(alpha).encode() + b'\n')
    conn.sendall(str(Ya).encode() + b'\n')
    
    data = conn.recv(8192).decode().strip().split('\n')
    C1 = int(data[0])
    C2 = int(data[1])
    
    print("\n--- DECRYPTION BY RECEIVER ---")
    print(f"Received Ciphertext: (C1, C2) = ({C1}, {C2})")
    
    K_dec, M_dec, message = cf.decrypt(C1, C2, q, Xa)
    
    print(f"Formula: K = (C1^Xa) mod q")
    print(f"Calculated K: {K_dec}")
    print(f"Formula: M = (C2 * K^-1) mod q")
    print(f"Calculated M (Plaintext): {M_dec}")
    print(f"Final Decrypted Message: {message}")
    
    conn.close()
    server.close()

if __name__ == "__main__":
    main()