from const import (
    SIMPLE_TRANSPOSITION_KEY,
    DOUBLE_TRANSPOSITION_KEY2,
    DEFAULT_TEXT,
)

def clean_text(text):
    """Remove non-alphabetic characters and convert to uppercase"""
    return ''.join(c.upper() for c in text if c.isalpha())

def get_transposition_order(key):
    """Get column order based on alphabetical position of key characters"""
    key = clean_text(key)
    indexed_chars = [(char, i) for i, char in enumerate(key)]
    sorted_chars = sorted(indexed_chars, key=lambda x: (x[0], x[1]))
    
    return [i for (char, i) in sorted_chars]

def simple_transposition_encrypt(text, key):
    """Encrypt text using simple columnar transposition"""
    text = clean_text(text)
    orig_len = len(text)
    key_order = get_transposition_order(key)
    cols = len(key_order)
    rows = (orig_len + cols - 1) // cols
    
    padded = text.ljust(rows * cols, 'X')
    
    grid = [padded[i*cols:(i+1)*cols] for i in range(rows)]
    
    ciphertext = []
    for col in key_order:
        ciphertext.extend([grid[row][col] for row in range(rows)])
    
    return ''.join(ciphertext), orig_len

def simple_transposition_decrypt(ciphertext, key, orig_len):
    """Decrypt text encrypted with simple columnar transposition"""
    key_order = get_transposition_order(key)
    cols = len(key_order)
    rows = (len(ciphertext) + cols - 1) // cols
    
    grid = [[None for _ in range(cols)] for _ in range(rows)]
    
    pos = 0
    for col in key_order:
        for row in range(rows):
            if pos < len(ciphertext):
                grid[row][col] = ciphertext[pos]
                pos += 1
            else:
                grid[row][col] = 'X'
    
    decrypted = ''.join([''.join(c for c in row if c is not None) for row in grid])
    return decrypted[:orig_len]  

def double_transposition_encrypt(text, key1, key2):
    """Encrypt text using double columnar transposition"""
    first_pass, orig_len = simple_transposition_encrypt(text, key1)
    second_pass, _ = simple_transposition_encrypt(first_pass, key2)
    return second_pass, orig_len

def double_transposition_decrypt(ciphertext, key1, key2, orig_len):
    """Decrypt text encrypted with double columnar transposition"""
    first_pass = simple_transposition_decrypt(ciphertext, key2, orig_len)
    return simple_transposition_decrypt(first_pass, key1, orig_len)

def test_transposition():
    """Test transposition cipher implementations"""
    
    test_text = DEFAULT_TEXT
    print("\n=== Simple Transposition Test ===")
    print(f"Key: {SIMPLE_TRANSPOSITION_KEY}")
    print(f"Original text: {test_text}")
    
    encrypted, orig_len = simple_transposition_encrypt(test_text, SIMPLE_TRANSPOSITION_KEY)
    print(f"\nEncrypted (len={len(encrypted)}): {encrypted}")
    
    decrypted = simple_transposition_decrypt(encrypted, SIMPLE_TRANSPOSITION_KEY, orig_len)
    print(f"\nDecrypted (len={len(decrypted)}): {decrypted}")
    print(f"Match original: {clean_text(test_text) == decrypted}")
    
    print("\n=== Double Transposition Test ===")
    print(f"Keys: {SIMPLE_TRANSPOSITION_KEY}, {DOUBLE_TRANSPOSITION_KEY2}")
    print(f"Original text: {test_text}")
    
    encrypted, orig_len = double_transposition_encrypt(test_text, SIMPLE_TRANSPOSITION_KEY, DOUBLE_TRANSPOSITION_KEY2)
    print(f"\nEncrypted (len={len(encrypted)}: {encrypted}")
    
    decrypted = double_transposition_decrypt(encrypted, SIMPLE_TRANSPOSITION_KEY, DOUBLE_TRANSPOSITION_KEY2, orig_len)
    print(f"\nDecrypted (len={len(decrypted)}: {decrypted}")
    print(f"Match original: {clean_text(test_text) == decrypted}")

if __name__ == "__main__":
    test_transposition()