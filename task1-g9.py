import random
import math
import sys

# --- Configuration Constants (Updated for 64 bits) ---
N_BITS = 64 # The length of the Easy Key (e) and the message (m) in bits.
KEY_RANGE_START = 2**20 # Starting size for the first easy key element (to ensure large numbers)

# --- Utility Functions ---

def extended_gcd(a, b):
    """Computes gcd(a, b) and returns a tuple (gcd, x, y) such that a*x + b*y = gcd."""
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y

def modular_inverse(w, q):
    """Computes w^-1 mod q using the Extended Euclidean Algorithm."""
    gcd, x, y = extended_gcd(w, q)
    if gcd != 1:
        raise Exception(f'Modular inverse does not exist for w={w} and q={q}.')
    return x % q

def generate_large_prime(min_val):
    """Generates a large prime number greater than min_val."""
    def is_prime(n, k=10):
        if n <= 1 or n == 4: return False
        if n <= 3: return True
        # Simple primality test: check a few random bases
        for _ in range(k):
            a = random.randint(2, n - 2)
            if pow(a, n - 1, n) != 1:
                return False
        return True

    p = min_val + 1 if min_val % 2 == 0 else min_val + 2
    while True:
        if is_prime(p):
            return p
        p += 2

# --- Message Encoding/Decoding Utilities ---

def text_to_bits(text, n_bits=N_BITS):
    """Converts a text message into a list of N_BITS length."""
    # Convert characters to binary (8 bits per char)
    bit_string = ''.join(format(ord(char), '08b') for char in text)
    
    # Pad or truncate to ensure the required N_BITS length
    if len(bit_string) > n_bits:
        bit_list = [int(b) for b in bit_string[:n_bits]]
    else:
        padding = '0' * (n_bits - len(bit_string))
        bit_list = [int(b) for b in bit_string + padding]
    
    return bit_list

def bits_to_text(bit_list):
    """Converts a list of bits back into a readable string."""
    text = ""
    # Only iterate through full 8-bit chunks
    for i in range(0, len(bit_list) // 8 * 8, 8):
        byte = bit_list[i:i+8]
        byte_str = "".join(map(str, byte))
        
        # Convert 8-bit binary string to integer, then to character
        try:
            char_code = int(byte_str, 2)
            if char_code == 0:
                # Stop decoding at padding zeros
                break
            char = chr(char_code)
            text += char
        except ValueError:
             # Skip or replace invalid characters
             pass
             
    return text

# --- Cryptography Functions (CORE LOGIC IMPLEMENTED) ---

def generate_key_pair(n=N_BITS):
    """
    Generates the public key h and the private key (e, q, w).
    """
    # 1. Generate Easy Key (e) - Super-increasing sequence.
    e = []
    current_sum = 0
    
    # Start the first element large to ensure q is very large
    next_e = random.randint(KEY_RANGE_START, KEY_RANGE_START * 2) 
    e.append(next_e)
    current_sum = next_e

    for _ in range(1, n):
        # e_i must be > current_sum
        # We add a random factor to current_sum to avoid a trivial sequence
        next_e = current_sum + random.randint(1, current_sum // 10) 
        e.append(next_e)
        current_sum += next_e
    
    e_n = e[-1]
    
    # 2. Select Modulus (q) and Multiplier (w)
    # q must be prime and q > 2 * e_n
    min_q = 2 * e_n + 1
    q = generate_large_prime(min_q) 
    
    # w must be coprime to q (gcd(w, q) = 1). Since q is prime, any w such that 1 < w < q works.
    w = random.randint(2, q - 1)
    
    # 3. Generate Hard Key (h)
    h = []
    # h_i = (w * e_i) mod q
    for e_i in e:
        h.append((w * e_i) % q)
    
    private_key = {'e': e, 'q': q, 'w': w}
    public_key = h
    
    return public_key, private_key


def encrypt(message_bits, public_key_h):
    """
    Encrypts an n-bit message m using the public key h.
    c = sum(h_i * m_i)
    """
    if len(message_bits) != len(public_key_h):
        raise ValueError("Message length must match key length (N_BITS).")
        
    ciphertext = 0
    
    # Summation: ciphertext = sum(h_i * m_i)
    for h_i, m_i in zip(public_key_h, message_bits):
        ciphertext += h_i * m_i
    
    return ciphertext


def decrypt(ciphertext, private_key):
    """
    Decrypts the ciphertext c using the private key (e, q, w).
    """
    e = private_key['e']
    q = private_key['q']
    w = private_key['w']
    n = len(e)
    
    # 1. Compute w^-1 mod q
    w_inv = modular_inverse(w, q)
    
    # 2. Compute Intermediate Ciphertext c'
    # c' = c * w^-1 mod q
    c_prime = (ciphertext * w_inv) % q
    
    # 3. Subset-Sum Decryption (Backwards check)
    decrypted_bits = [0] * n
    remaining_sum = c_prime
    
    # Iterate backwards from i = n-1 down to 0 (corresponding to e_n down to e_1)
    # The property e_i > sum(e_j) ensures a unique solution is found.
    for i in range(n - 1, -1, -1):
        if remaining_sum >= e[i]:
            decrypted_bits[i] = 1
            remaining_sum -= e[i]
            
    # The list is built backwards relative to the index but needs to be in order for decoding
    return decrypted_bits

# --- Main Execution and Testing ---

def run_test_case(case_number, plaintext):
    """Runs a single test case and prints results for the report."""
    print(f"\n{'='*50}\n### Test Case {case_number} (N={N_BITS}) ###")
    
    # 1. Key Generation
    h_public, key_private = generate_key_pair(N_BITS)
    
    e = key_private['e']
    q = key_private['q']
    
    print(f"Key Length (N): {N_BITS} bits")
    print(f"Modulus (q) size: {q.bit_length()} bits")
    print(f"e_1: {e[0]}, e_n: {e[-1]}")
    print(f"q: {q}")
    print(f"w: {key_private['w']}")
    print(f"h (first 3 elements): {h_public[:3]}")

    # 2. Convert plaintext to a bit vector
    message_m = text_to_bits(plaintext)
    
    # 3. Encryption
    c_ciphertext = encrypt(message_m, h_public)
    
    print("\n--- Encryption & Decryption ---")
    print(f"Plaintext (Start): {plaintext[:40]}...")
    print(f"Ciphertext (c): {c_ciphertext}")
    
    # 4. Decryption
    m_decrypted = decrypt(c_ciphertext, key_private)
    
    # 5. Convert back to text
    decrypted_text = bits_to_text(m_decrypted)
    
    # 6. Verification
    original_text_part = plaintext[:len(decrypted_text)].strip()
    decrypted_text_part = decrypted_text.strip()
    
    if original_text_part == decrypted_text_part:
        print(f"\nVerification: SUCCESS (Decrypted text matches original text)")
    else:
        print(f"\nVerification: FAILURE")
        
    print(f"Decrypted Text (Start): {decrypted_text_part[:40]}...")
    
    # Print examples for report (using first few characters)
    print("\n--- Report Examples ---")
    print(f"Original Char: '{plaintext[0]}', Cipher Char (first part): '{str(c_ciphertext)[:10]}'")


if __name__ == '__main__':
    
    # 1. Define the mandatory test plaintext (must be >= 500 chars)
    # REPLACE [Your Name] and ensure length > 500 characters.
    PLAINTEXT_LONG = """
hello i am batman. my real name is bruce wayne. i live in gotham city and fight crime at night. my parents were killed when i was a child, which led me to take on the mantle of batman. i have no superpowers, but i use my intelligence, detective skills, and physical prowess to combat villains like the joker, the riddler, and two-face. i also have a vast array of gadgets and vehicles at my disposal, including the batmobile and batarangs. during the day, i run wayne enterprises, a large corporation that helps fund my crime-fighting activities. my trusted allies include alfred pennyworth, my loyal butler; robin, my sidekick; and commissioner gordon, who provides me with information from the police department. together, we work to keep gotham city safe from the forces of evil."""

    # Ensure the plaintext meets the minimum length requirement
    if len(PLAINTEXT_LONG) < 500:
        print("CRITICAL ERROR: PLAINTEXT is less than 500 characters. Please extend it.")
        sys.exit(1)
        
    # Run Test Case 1
    run_test_case(1, PLAINTEXT_LONG)

    # Run Test Case 2 (requires new key generation)
    run_test_case(2, PLAINTEXT_LONG)