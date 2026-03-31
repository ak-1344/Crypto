How to run:

Terminal 1 - Attacker:

bash   python attacker.py
Enter q: 23, alpha: 5

Terminal 2 - Alice:

bash   python alice.py
Enter q: 23, alpha: 5

Terminal 3 - Bob:

bash   python bob.py
Enter q: 23, alpha: 5
Example chat session:
Alice types: hello bob
Attacker sees: Decrypted: hello bob
Bob receives: Alice: hello bob
Bob types: hi alice!
Attacker sees: Decrypted: hi alice!
Alice receives: Bob: hi alice!
Type exit in Alice or Bob terminal to quit. The attacker sees ALL messages in plaintext in real-time!