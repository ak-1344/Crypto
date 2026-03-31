import socket
import threading
import crypto_functions as cf

class MITMAttacker:
    def __init__(self, q, alpha):
        self.q = q
        self.alpha = alpha
        self.Xd1 = cf.generate_private_key(q)
        self.Xd2 = cf.generate_private_key(q)
        self.Ka = None
        self.Kb = None
        self.conn_alice = None
        self.conn_bob = None
        
    def setup_alice(self, conn):
        self.conn_alice = conn
        data = conn.recv(4096).decode().strip()
        Ya = int(data)
        print(f"\n[KEY EXCHANGE] Received Ya from Alice: {Ya}")
        
        Yd1 = cf.compute_public_key(self.alpha, self.Xd1, self.q)
        print(f"[KEY EXCHANGE] Sending Yd1 to Alice: {Yd1}")
        conn.sendall(str(Yd1).encode() + b'\n')
        
        self.Ka = cf.compute_shared_key(Ya, self.Xd1, self.q)
        print(f"[KEY EXCHANGE] Shared key with Alice (Ka): {self.Ka}")
        
    def setup_bob(self, conn):
        self.conn_bob = conn
        data = conn.recv(4096).decode().strip()
        Yb = int(data)
        print(f"\n[KEY EXCHANGE] Received Yb from Bob: {Yb}")
        
        Yd2 = cf.compute_public_key(self.alpha, self.Xd2, self.q)
        print(f"[KEY EXCHANGE] Sending Yd2 to Bob: {Yd2}")
        conn.sendall(str(Yd2).encode() + b'\n')
        
        self.Kb = cf.compute_shared_key(Yb, self.Xd2, self.q)
        print(f"[KEY EXCHANGE] Shared key with Bob (Kb): {self.Kb}")
        
    def listen_from_alice(self):
        print("\n[LISTENER] Alice listener thread started")
        while True:
            try:
                encrypted = self.conn_alice.recv(4096).decode().strip()
                if not encrypted:
                    break
                
                print(f"\n[ALICE → BOB] Encrypted: {encrypted}")
                decrypted = cf.decrypt_message(encrypted, self.Ka)
                print(f"[ALICE → BOB] Decrypted: {decrypted}")
                
                re_encrypted = cf.encrypt_message(decrypted, self.Kb)
                print(f"[ALICE → BOB] Re-encrypted for Bob: {re_encrypted}")
                self.conn_bob.sendall(re_encrypted.encode() + b'\n')
                print(f"[ALICE → BOB] Forwarded to Bob\n")
            except:
                break
                
    def listen_from_bob(self):
        print("[LISTENER] Bob listener thread started\n")
        while True:
            try:
                encrypted = self.conn_bob.recv(4096).decode().strip()
                if not encrypted:
                    break
                
                print(f"\n[BOB → ALICE] Encrypted: {encrypted}")
                decrypted = cf.decrypt_message(encrypted, self.Kb)
                print(f"[BOB → ALICE] Decrypted: {decrypted}")
                
                re_encrypted = cf.encrypt_message(decrypted, self.Ka)
                print(f"[BOB → ALICE] Re-encrypted for Alice: {re_encrypted}")
                self.conn_alice.sendall(re_encrypted.encode() + b'\n')
                print(f"[BOB → ALICE] Forwarded to Alice\n")
            except:
                break

def main():
    print("=" * 60)
    print("ATTACKER (MAN IN THE MIDDLE)")
    print("=" * 60)
    
    q = int(input("Enter prime number (q): "))
    alpha = int(input("Enter primitive root (alpha): "))
    
    attacker = MITMAttacker(q, alpha)
    
    print(f"\nPrivate key for Alice (Xd1): {attacker.Xd1}")
    print(f"Private key for Bob (Xd2): {attacker.Xd2}")
    
    server_alice = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_alice.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_alice.bind(("localhost", 8001))
    server_alice.listen(1)
    
    server_bob = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_bob.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_bob.bind(("localhost", 8002))
    server_bob.listen(1)
    
    print("\n" + "=" * 60)
    print("Waiting for Alice on port 8001...")
    print("Waiting for Bob on port 8002...")
    print("=" * 60)
    
    conn_alice, _ = server_alice.accept()
    print("\n✓ Alice connected!")
    attacker.setup_alice(conn_alice)
    
    conn_bob, _ = server_bob.accept()
    print("\n✓ Bob connected!")
    attacker.setup_bob(conn_bob)
    
    print("\n" + "=" * 60)
    print("INTERCEPTION ACTIVE - ALL MESSAGES WILL BE LOGGED")
    print("=" * 60)
    
    alice_thread = threading.Thread(target=attacker.listen_from_alice)
    bob_thread = threading.Thread(target=attacker.listen_from_bob)
    
    alice_thread.daemon = True
    bob_thread.daemon = True
    
    alice_thread.start()
    bob_thread.start()
    
    try:
        alice_thread.join()
        bob_thread.join()
    except KeyboardInterrupt:
        print("\n\nAttacker shutting down...")
    
    conn_alice.close()
    conn_bob.close()
    server_alice.close()
    server_bob.close()

if __name__ == "__main__":
    main()