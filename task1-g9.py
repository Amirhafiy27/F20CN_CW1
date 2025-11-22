import random
import math
import sys

#Configuration Constants
N_BITS = 64
KEY_RANGE_START = 2**20

#Utility Functions

def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y

def modular_inverse(w, q):
    gcd, x, y = extended_gcd(w, q)
    if gcd != 1:
        raise Exception(f'Modular inverse does not exist for w={w} and q={q}.')
    return x % q

def is_prime_miller_rabin(n, k=10):
    if n <= 1 or n == 4:
        return False
    if n <= 3:
        return True
    if n % 2 == 0:
        return False
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_large_prime(min_val):
    p = min_val + 1 if min_val % 2 == 0 else min_val + 2
    while True:
        if is_prime_miller_rabin(p):
            return p
        p += 2

#Message Encoding/Decoding

def text_to_bits(text, n_bits=N_BITS):
    bit_string = ''.join(format(ord(char), '08b') for char in text)
    if len(bit_string) > n_bits:
        bit_list = [int(b) for b in bit_string[:n_bits]]
    else:
        padding = '0' * (n_bits - len(bit_string))
        bit_list = [int(b) for b in bit_string + padding]
    return bit_list

def bits_to_text(bit_list):
    text = ""
    for i in range(0, len(bit_list) // 8 * 8, 8):
        byte = bit_list[i:i+8]
        byte_str = "".join(map(str, byte))
        try:
            char_code = int(byte_str, 2)
            if char_code == 0:
                break
            text += chr(char_code)
        except ValueError:
            pass
    return text

def split_text_into_blocks(text, block_size_chars=8):
    blocks = []
    for i in range(0, len(text), block_size_chars):
        block = text[i:i+block_size_chars]
        if len(block) < block_size_chars:
            block = block + '\x00' * (block_size_chars - len(block))
        blocks.append(block)
    return blocks

def blocks_to_text(blocks):
    text = ''.join(blocks)
    return text.rstrip('\x00')

#Cryptography Functions

def generate_key_pair(n=N_BITS):
    e = []
    current_sum = 0
    first_e = random.randint(KEY_RANGE_START, KEY_RANGE_START * 2)
    e.append(first_e)
    current_sum = first_e
    for _ in range(1, n):
        next_e = current_sum + random.randint(current_sum // 10, current_sum // 5)
        e.append(next_e)
        current_sum += next_e
    e_n = e[-1]
    min_q = 2 * e_n + 1
    q = generate_large_prime(min_q)
    w = random.randint(2, q - 1)
    h = [(w * e_i) % q for e_i in e]
    private_key = {'e': e, 'q': q, 'w': w}
    public_key = h
    return public_key, private_key

def encrypt_block(message_bits, public_key_h):
    if len(message_bits) != len(public_key_h):
        raise ValueError("Message length must match key length (N_BITS).")
    ciphertext = 0
    for h_i, m_i in zip(public_key_h, message_bits):
        ciphertext += h_i * m_i
    return ciphertext

def encrypt(plaintext, public_key_h):
    block_size_chars = N_BITS // 8
    text_blocks = split_text_into_blocks(plaintext, block_size_chars)
    ciphertext_blocks = []
    for block in text_blocks:
        message_bits = text_to_bits(block, N_BITS)
        ciphertext = encrypt_block(message_bits, public_key_h)
        ciphertext_blocks.append(ciphertext)
    return ciphertext_blocks

def decrypt_block(ciphertext, private_key):
    e = private_key['e']
    q = private_key['q']
    w = private_key['w']
    n = len(e)
    w_inv = modular_inverse(w, q)
    c_prime = (ciphertext * w_inv) % q
    decrypted_bits = [0] * n
    remaining_sum = c_prime
    for i in range(n - 1, -1, -1):
        if remaining_sum >= e[i]:
            decrypted_bits[i] = 1
            remaining_sum -= e[i]
    return decrypted_bits

def decrypt(ciphertext_blocks, private_key):
    decrypted_blocks = []
    for ciphertext in ciphertext_blocks:
        decrypted_bits = decrypt_block(ciphertext, private_key)
        decrypted_text = bits_to_text(decrypted_bits)
        decrypted_blocks.append(decrypted_text)
    return blocks_to_text(decrypted_blocks)

#Interactive Interface

def display_menu():
    print("\n" + "="*60)
    print("   ALTERNATIVE PUBLIC-KEY ENCRYPTION SYSTEM")
    print("="*60)
    print("1. Generate New Key Pair")
    print("2. Encrypt Message (requires plaintext + public key)")
    print("3. Decrypt Ciphertext (requires ciphertext + private key)")
    print("4. Run Automated Tests")
    print("5. Exit")
    print("="*60)

def get_user_choice():
    while True:
        try:
            choice = input("\nEnter your choice (1-5): ").strip()
            if choice in ['1', '2', '3', '4', '5']:
                return choice
            else:
                print("Invalid choice. Please enter a number between 1 and 5.")
        except Exception as e:
            print(f"Error: {e}. Please try again.")

def input_public_key():
    """Prompts user to input the public key (hard key h)."""
    print("\n--- Input Public Key (Hard Key h) ---")
    print(f"Enter {N_BITS} comma-separated integers for the public key h:")
    print("Example: 123456, 789012, 345678, ...")
    try:
        h_input = input("Public Key h: ").strip()
        h = [int(x.strip()) for x in h_input.split(',')]
        if len(h) != N_BITS:
            print(f"Error: Public key must have exactly {N_BITS} elements. You entered {len(h)}.")
            return None
        print(f"Public key loaded successfully ({len(h)} elements).")
        return h
    except ValueError:
        print("Invalid input. Please enter comma-separated integers.")
        return None

def input_private_key():
    """Prompts user to input the private key (e, q, w)."""
    print("\n--- Input Private Key ---")
    try:
        # Input Easy Key (e)
        print(f"\nEnter the Easy Key (e) - {N_BITS} comma-separated integers:")
        print("Example: 1048576, 2202214, 4653851, ...")
        e_input = input("Easy Key e: ").strip()
        e = [int(x.strip()) for x in e_input.split(',')]
        if len(e) != N_BITS:
            print(f"Error: Easy key must have exactly {N_BITS} elements. You entered {len(e)}.")
            return None
        
        # Input Modulus (q)
        print("\nEnter the Modulus (q) - a single large prime number:")
        q_input = input("Modulus q: ").strip()
        q = int(q_input)
        
        # Input Multiplier (w)
        print("\nEnter the Multiplier (w) - a single integer:")
        w_input = input("Multiplier w: ").strip()
        w = int(w_input)
        
        private_key = {'e': e, 'q': q, 'w': w}
        print(f"\nPrivate key loaded successfully!")
        print(f"  - Easy key (e): {len(e)} elements")
        print(f"  - Modulus (q): {q}")
        print(f"  - Multiplier (w): {w}")
        return private_key
    except ValueError:
        print("Invalid input. Please enter valid integers.")
        return None

def interactive_mode():
    """Runs the interactive user interface."""
    # Store last generated keys for display purposes only
    last_generated_public = None
    last_generated_private = None
    
    while True:
        display_menu()
        choice = get_user_choice()
        
        if choice == '1':
            # Generate Key Pair
            print("\n--- Generating New Key Pair ---")
            last_generated_public, last_generated_private = generate_key_pair(N_BITS)
            
            print(f"\nKey pair generated successfully!")
            print(f"Key Length (N): {N_BITS} bits ({N_BITS // 8} characters per block)")
            
            print(f"\n{'='*50}")
            print("PUBLIC KEY (share this for encryption):")
            print(f"{'='*50}")
            print(f"Hard Key (h) - {N_BITS} elements:")
            print(','.join(map(str, last_generated_public)))
            
            print(f"\n{'='*50}")
            print("PRIVATE KEY (keep this secret for decryption):")
            print(f"{'='*50}")
            print(f"\nEasy Key (e) - {N_BITS} elements:")
            print(','.join(map(str, last_generated_private['e'])))
            print(f"\nModulus (q): {last_generated_private['q']}")
            print(f"Multiplier (w): {last_generated_private['w']}")
            
            print(f"\n{'='*50}")
            print("SAVE THESE KEYS! You will need to input them for encryption/decryption.")
            print(f"{'='*50}")
            
        elif choice == '2':
            # Encrypt - User must input plaintext AND public key
            print("\n" + "="*50)
            print("ENCRYPTION")
            print("="*50)
            
            # Get public key from user
            public_key = input_public_key()
            if public_key is None:
                continue
            
            # Get plaintext from user
            chars_per_block = N_BITS // 8
            print(f"\nBlock size: {chars_per_block} characters per block")
            print(f"Messages longer than {chars_per_block} characters will be split into multiple blocks")
            plaintext = input("\nEnter your message to encrypt: ")
            
            if len(plaintext) == 0:
                print("Empty message. Please enter some text.")
                continue
            
            # Encrypt
            ciphertext_blocks = encrypt(plaintext, public_key)
            
            print(f"\n{'='*50}")
            print("ENCRYPTION SUCCESSFUL!")
            print(f"{'='*50}")
            print(f"Plaintext: {plaintext}")
            print(f"Plaintext length: {len(plaintext)} characters")
            print(f"Number of blocks: {len(ciphertext_blocks)}")
            print(f"\nCiphertext blocks (copy these for decryption):")
            print(','.join(map(str, ciphertext_blocks)))
            
        elif choice == '3':
            # Decrypt - User must input ciphertext AND private key
            print("\n" + "="*50)
            print("DECRYPTION")
            print("="*50)
            
            # Get private key from user
            private_key = input_private_key()
            if private_key is None:
                continue
            
            # Get ciphertext from user
            print("\n--- Input Ciphertext ---")
            print("Enter ciphertext blocks as comma-separated integers:")
            print("Example: 1234567890, 9876543210, 5555555555")
            try:
                ciphertext_input = input("Ciphertext blocks: ").strip()
                ciphertext_blocks = [int(x.strip()) for x in ciphertext_input.split(',')]
                
                # Decrypt
                decrypted_text = decrypt(ciphertext_blocks, private_key)
                
                print(f"\n{'='*50}")
                print("DECRYPTION SUCCESSFUL!")
                print(f"{'='*50}")
                print(f"Number of ciphertext blocks: {len(ciphertext_blocks)}")
                print(f"Decrypted message: {decrypted_text}")
                
            except ValueError:
                print("Invalid input. Please enter comma-separated integers.")
            except Exception as e:
                print(f"Decryption error: {e}")
                
        elif choice == '4':
            # Run Tests
            print("\n--- Running Automated Tests ---")
            run_automated_tests()
            
        elif choice == '5':
            print("\nGoodbye!")
            sys.exit(0)

#Automated Testing

def run_automated_tests():
    PLAINTEXT_LONG = """To Amir: This is a demonstration of the alternative public-key encryption method proposed by a recent PhD student. The system uses a super-increasing sequence as the easy key, which allows for efficient decryption through a greedy algorithm. Bob generates a random super-increasing sequence e where each element is greater than the sum of all previous elements. He then selects a prime modulus q that exceeds twice the largest element in the sequence. Using a random multiplier w that is coprime to q, Bob computes the hard key h by multiplying each element of e by w modulo q. The hard key h becomes the public key, while the easy key e, along with q and w, form the private key. To encrypt a message, Alice computes a weighted sum of the public key elements, where the weights are the individual bits of her message. Bob decrypts by first computing the modular inverse of w, then applying it to the ciphertext to recover an intermediate value. The super-increasing property of the easy key allows Bob to recover each message bit through a simple greedy algorithm working backwards from the largest element."""
    
    print(f"Test plaintext length: {len(PLAINTEXT_LONG)} characters")
    
    # Test Case 1
    print("\n" + "="*60)
    print("TEST CASE 1")
    print("="*60)
    
    h1, priv1 = generate_key_pair(N_BITS)
    print(f"\nKey Length: {N_BITS} bits ({N_BITS // 8} chars/block)")
    print(f"Modulus (q): {priv1['q']} ({priv1['q'].bit_length()} bits)")
    print(f"Multiplier (w): {priv1['w']}")
    print(f"Easy Key (e) [first 3]: {priv1['e'][:3]}")
    print(f"Hard Key (h) [first 3]: {h1[:3]}")
    
    c1 = encrypt(PLAINTEXT_LONG, h1)
    print(f"\nPlaintext length: {len(PLAINTEXT_LONG)} characters")
    print(f"Number of ciphertext blocks: {len(c1)}")
    print(f"Ciphertext blocks: {c1}")
    
    d1 = decrypt(c1, priv1)
    print(f"\nDecrypted text: {d1}")
    
    if d1.strip() == PLAINTEXT_LONG.strip():
        print("\nTEST 1 PASSED - Full message decrypted correctly")
    else:
        print("\nTEST 1 FAILED")
    
    # Test Case 2
    print("\n" + "="*60)
    print("TEST CASE 2")
    print("="*60)
    
    h2, priv2 = generate_key_pair(N_BITS)
    print(f"\nKey Length: {N_BITS} bits ({N_BITS // 8} chars/block)")
    print(f"Modulus (q): {priv2['q']} ({priv2['q'].bit_length()} bits)")
    print(f"Multiplier (w): {priv2['w']}")
    print(f"Easy Key (e) [first 3]: {priv2['e'][:3]}")
    print(f"Hard Key (h) [first 3]: {h2[:3]}")
    
    c2 = encrypt(PLAINTEXT_LONG, h2)
    print(f"\nPlaintext length: {len(PLAINTEXT_LONG)} characters")
    print(f"Number of ciphertext blocks: {len(c2)}")
    print(f"Ciphertext blocks: {c2}")
    
    d2 = decrypt(c2, priv2)
    print(f"\nDecrypted text: {d2}")
    
    if d2.strip() == PLAINTEXT_LONG.strip():
        print("\nTEST 2 PASSED - Full message decrypted correctly")
    else:
        print("\nTEST 2 FAILED")
    
    print("\n" + "="*60)
    print("Automated testing completed")
    print("="*60)

#Main Program

if __name__ == '__main__':
    print("\nAlternative Public-Key Encryption System")
    print(f"Using N={N_BITS} bits per block ({N_BITS // 8} characters per block)")
    print("Long messages are automatically split into multiple blocks.")
    
    if len(sys.argv) > 1 and sys.argv[1] == '--test':
        run_automated_tests()
    else:
        interactive_mode()