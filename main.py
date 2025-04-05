from const import (
    DEFAULT_TEXT,
    VIGENERE_KEY,
    SIMPLE_TRANSPOSITION_KEY,
    DOUBLE_TRANSPOSITION_KEY2,
    TABLE_CIPHER_KEY,
)
from vigenere import vigenere_encrypt, vigenere_decrypt, kasiski_test
from transposition import simple_transposition_encrypt, simple_transposition_decrypt, double_transposition_encrypt, double_transposition_decrypt
from table import table_encrypt, table_decrypt



def main():
    print("=== Cryptography Tool ===")
    print(f"Original text: {DEFAULT_TEXT}\n")
    
    # Vigenère cipher
    print("\n=== Vigenère Cipher ===")
    encrypted = vigenere_encrypt(DEFAULT_TEXT, VIGENERE_KEY)
    print(f"Encrypted: {encrypted}")
    decrypted = vigenere_decrypt(encrypted, VIGENERE_KEY)
    print(f"Decrypted: {decrypted}")
    
    # Simple transposition
    print("\n=== Simple Transposition ===")
    encrypted, orig_len = simple_transposition_encrypt(DEFAULT_TEXT, SIMPLE_TRANSPOSITION_KEY)
    print(f"Encrypted: {encrypted}")
    decrypted = simple_transposition_decrypt(encrypted, SIMPLE_TRANSPOSITION_KEY, orig_len)
    print(f"Decrypted: {decrypted}")
    
    # Double transposition
    print("\n=== Double Transposition ===")
    encrypted, orig_len = double_transposition_encrypt(DEFAULT_TEXT, SIMPLE_TRANSPOSITION_KEY, DOUBLE_TRANSPOSITION_KEY2)
    print(f"Encrypted: {encrypted}")
    decrypted = double_transposition_decrypt(encrypted, SIMPLE_TRANSPOSITION_KEY, DOUBLE_TRANSPOSITION_KEY2, orig_len)
    print(f"Decrypted: {decrypted}")
    
    # Table cipher
    print("\n=== Table Cipher ===")
    encrypted = table_encrypt(DEFAULT_TEXT, TABLE_CIPHER_KEY)
    print(f"Encrypted: {encrypted}")
    decrypted = table_decrypt(encrypted, TABLE_CIPHER_KEY)
    print(f"Decrypted: {decrypted}")
    
    # Combined Vigenère + Table cipher
    print("\n=== Combined Vigenère + Table Cipher ===")
    v_encrypted = vigenere_encrypt(DEFAULT_TEXT, TABLE_CIPHER_KEY)
    t_encrypted = table_encrypt(v_encrypted, DOUBLE_TRANSPOSITION_KEY2)
    print(f"Encrypted: {t_encrypted}")
    t_decrypted = table_decrypt(t_encrypted, DOUBLE_TRANSPOSITION_KEY2)
    v_decrypted = vigenere_decrypt(t_decrypted, TABLE_CIPHER_KEY)
    print(f"Decrypted: {v_decrypted}")
    
    # Kasiski test
    print("\n=== Kasiski Test (Vigenère Cryptanalysis) ===")
   
    encrypted_test = vigenere_encrypt(DEFAULT_TEXT, VIGENERE_KEY)
    print(f"Encrypted test text: {encrypted_test}")
    possible_length, possible_encrypted_text = kasiski_test(encrypted_test)
    print(f"Possible key length: {possible_length}")
    print(f"Possible encrypted text: {possible_encrypted_text}")


if __name__ == "__main__":
    main()
