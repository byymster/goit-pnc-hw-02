from const import DEFAULT_TEXT

def table_encrypt(text, key):
    """Encrypt text using table cipher with given key"""
    text = clean_text(text)
    key = clean_text(key)
    
    # Create substitution table
    alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    # Remove key characters from alphabet
    remaining = [c for c in alphabet if c not in key]
    # Create substitution string (key + remaining letters in order)
    substitution = key + ''.join(remaining)
    
    # Encrypt by substituting each character
    encrypted = []
    for char in text:
        idx = ord(char) - 65 
        encrypted.append(substitution[idx])
    
    return ''.join(encrypted)

def table_decrypt(text, key):
    """Decrypt text using table cipher with given key"""
    text = clean_text(text)
    key = clean_text(key)
    
    alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    remaining = [c for c in alphabet if c not in key]
    substitution = key + ''.join(remaining)
    
    decrypted = []
    for char in text:
        idx = substitution.index(char)
        decrypted.append(alphabet[idx])
    
    return ''.join(decrypted)

def clean_text(text):
    """Remove non-alphabetic characters and convert to uppercase"""
    return ''.join(c.upper() for c in text if c.isalpha())
