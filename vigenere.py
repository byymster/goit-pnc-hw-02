from collections import Counter
import re

def kasiski_examination(ciphertext, min_len=3):
    distances = []
    for seq_len in range(min_len, len(ciphertext) // 2):
        seqs = {}
        for i in range(len(ciphertext) - seq_len):
            seq = ciphertext[i:i + seq_len]
            if seq in seqs:
                distances.append(i - seqs[seq])
            else:
                seqs[seq] = i
    # Find all divisors
    factors = []
    for d in distances:
        for i in range(2, d + 1):
            if d % i == 0:
                factors.append(i)
    return Counter(factors).most_common(25)

def friedman_test(ciphertext):
    N = len(ciphertext)
    freqs = Counter(ciphertext)
    IC = sum(f * (f - 1) for f in freqs.values()) / (N * (N - 1))
    # Standard values
    K_eng = 0.065
    K_rand = 1 / 26
    estimated_key_len = (K_eng - K_rand) / (IC - K_rand) if IC != K_rand else 0
    return round(estimated_key_len)

def vigenere_encrypt(text, key):
    """Encrypt text using Vigenère cipher with given key"""
    key = clean_key(key)
    encrypted = []
    key_len = len(key)
    key_index = 0
    
    for char in text:
        if char.isalpha():
            upper_char = char.upper()
            key_char = key[key_index % key_len]
            shifted = (ord(upper_char) - 65 + ord(key_char) - 65) % 26
            encrypted_char = chr(shifted + 65)
            encrypted.append(encrypted_char.lower() if char.islower() else encrypted_char)
            key_index += 1
        else:
            encrypted.append(char)
    
    return ''.join(encrypted)

def vigenere_decrypt(text, key):
    """Decrypt text using Vigenère cipher with given key"""
    key = clean_key(key)
    decrypted = []
    key_len = len(key)
    key_index = 0
    
    for char in text:
        if char.isalpha():
            upper_char = char.upper()
            key_char = key[key_index % key_len]
            shifted = (ord(upper_char) - 65 - (ord(key_char) - 65)) % 26
            decrypted_char = chr(shifted + 65)
            decrypted.append(decrypted_char.lower() if char.islower() else decrypted_char)
            key_index += 1
        else:
            decrypted.append(char)
    
    return ''.join(decrypted)

def clean_key(key):
    """Clean key by removing non-alphabetic characters and converting to uppercase"""
    return re.sub(r'[^A-Za-z]', '', key).upper()


def kasiski_test(ciphertext, min_threshold=50, max_key_length=40, min_key_length=5):
    """Estimate key length using Kasiski examination and return (key_length, sample_decrypted_text)"""
    kasiski_results = kasiski_examination(ciphertext)
    candidates = [(factor, count) for factor, count in kasiski_results
                 if count >= min_threshold and min_key_length <= factor <= max_key_length]
    if not candidates:
        key_length = friedman_test(ciphertext)
        if key_length is None:
            return None, None
        guessed_key = guess_key(ciphertext, key_length)
        decrypted = vigenere_decrypt(ciphertext, guessed_key)
        return key_length, decrypted[:200] + "..." if len(decrypted) > 200 else decrypted
    
    best_factor, _ = max(candidates, key=lambda x: x[1])
    guessed_key = guess_key(ciphertext, best_factor)
    decrypted = vigenere_decrypt(ciphertext, guessed_key)
    
    return best_factor, decrypted[:200] + "..." if len(decrypted) > 200 else decrypted

def guess_key(ciphertext, key_length):
    """Guess likely key using frequency analysis"""
    english_freq = [0.08167, 0.01492, 0.02782, 0.04253, 0.12702,
                   0.02228, 0.02015, 0.06094, 0.06966, 0.00153,
                   0.00772, 0.04025, 0.02406, 0.06749, 0.07507,
                   0.01929, 0.00095, 0.05987, 0.06327, 0.09056,
                   0.02758, 0.00978, 0.02360, 0.00150, 0.01974,
                   0.00074]
    
    key = []
    for i in range(key_length):
        group = ciphertext[i::key_length]
        freq = [0]*26
        total = 0
        for c in group:
            if c.isalpha():
                freq[ord(c.upper())-65] += 1
                total += 1
        
        if total == 0:
            key.append('A')
            continue
            
        best_shift = 0
        best_score = float('inf')
        for shift in range(26):
            score = 0
            for j in range(26):
                score += abs(freq[(j+shift)%26]/total - english_freq[j])
            if score < best_score:
                best_score = score
                best_shift = shift
        key.append(chr(65 + best_shift))
    
    return ''.join(key)

def index_of_coincidence(text):
    """Calculate index of coincidence for frequency analysis"""
    freq = [0]*26
    total = 0
    for c in text.upper():
        if c.isalpha():
            freq[ord(c)-65] += 1
            total += 1
    
    if total < 2:
        return 0.0
    
    return sum(f*(f-1) for f in freq) / (total * (total-1))



