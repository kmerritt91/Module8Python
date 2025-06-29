# Module8Python
import base64
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# *************************
# Caesar Cipher
# *************************
def caesar_encrypt(text, shift):
    result = ""
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - base + shift) % 26 + base)
        else:
            result += char
    return result

def caesar_decrypt(text, shift):
    return caesar_encrypt(text, -shift)

# *************************
# Vigenère Cipher
# *************************
def vigenere_encrypt(text, key):
    result = ""
    key_repeated = (key * (len(text) // len(key) + 1))[:len(text)]
    for i in range(len(text)):
        if text[i].isalpha():
            shift = ord(key_repeated[i].upper()) - ord('A')
            base = ord('A') if text[i].isupper() else ord('a')
            result += chr((ord(text[i]) - base + shift) % 26 + base)
        else:
            result += text[i]
    return result

def vigenere_decrypt(text, key):
    result = ""
    key_repeated = (key * (len(text) // len(key) + 1))[:len(text)]
    for i in range(len(text)):
        if text[i].isalpha():
            shift = ord(key_repeated[i].upper()) - ord('A')
            base = ord('A') if text[i].isupper() else ord('a')
            result += chr((ord(text[i]) - base - shift) % 26 + base)
        else:
            result += text[i]
    return result


# *************************
# AES Functions (CFB mode)
# *************************
def aes_encrypt(key: bytes, plaintext: str) -> str:
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
    return base64.b64encode(iv + ciphertext).decode('utf-8')

def aes_decrypt(key: bytes, encrypted_data: str) -> str:
    encrypted_data_bytes = base64.b64decode(encrypted_data)
    iv = encrypted_data_bytes[:16]
    ciphertext = encrypted_data_bytes[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
    return decrypted_data.decode('utf-8')

# -------------------------------
# Main Program Logic
# -------------------------------
def main():
    if not os.path.exists("password.txt"):
        print("Error: password.txt not found!")
        return

    with open("password.txt", "r", encoding="utf-8") as f:
        plaintext = f.read()

    # Caesar Cipher
    shift = 3
    caesar_enc = caesar_encrypt(plaintext, shift)
    caesar_dec = caesar_decrypt(caesar_enc, shift)
    with open("caesar_encrypted.txt", "w", encoding="utf-8") as f:
        f.write(caesar_enc)
    with open("caesar_decrypted.txt", "w", encoding="utf-8") as f:
        f.write(caesar_dec)
    print("Caesar Cipher complete: caesar_encrypted.txt, caesar_decrypted.txt")

    # Vigenère Cipher
    key = "KEYWORD"
    vigenere_enc = vigenere_encrypt(plaintext, key)
    vigenere_dec = vigenere_decrypt(vigenere_enc, key)
    with open("vigenere_encrypted.txt", "w", encoding="utf-8") as f:
        f.write(vigenere_enc)
    with open("vigenere_decrypted.txt", "w", encoding="utf-8") as f:
        f.write(vigenere_dec)
    print("Vigenère Cipher complete: vigenere_encrypted.txt, vigenere_decrypted.txt")

    # Advanced Encryption Standard (AES)
    aes_key = os.urandom(32)  # 32 bytes
    aes_encrypted = aes_encrypt(aes_key, plaintext)
    aes_decrypted = aes_decrypt(aes_key, aes_encrypted)
    with open("aes_encrypted.txt", "w", encoding="utf-8") as f:
        f.write(aes_encrypted)
    with open("aes_decrypted.txt", "w", encoding="utf-8") as f:
        f.write(aes_decrypted)
    print("AES encryption (CFB mode) complete.")

if __name__ == "__main__":
    main()
    
