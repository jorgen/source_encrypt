import struct
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import base64
from typing import Tuple, Union
import binascii

def derive_key(password: bytes, salt: bytes) -> bytes:
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(password)
    digest.update(salt)
    return digest.finalize()

def pad_pkcs7(data: bytes) -> bytes:
    padding_length = algorithms.AES.block_size - (len(data) % algorithms.AES.block_size)
    return data + bytes([padding_length]) * padding_length

def unpad_pkcs7(padded_data: bytes) -> bytes:
    padding_length = bytes(padded_data[-1], "ascii")[0]
    return padded_data[:-padding_length]

def encrypt_aes(message: bytes, password: bytes) -> Tuple[bytearray, bytearray]:
    """Encrypt a message using AES-256-CBC and return the encrypted message and salt in base64 encoding."""
    salt: bytes = os.urandom(16)
    key: bytes = derive_key(password, salt)
    iv: bytes = os.urandom(16)
    cipher: Cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    to_compress = struct.pack('I', len(message)) + message 
    ct: bytes = encryptor.update(pad_pkcs7(to_compress)) + encryptor.finalize()
    return (ct, salt + iv)

def decrypt_aes(ct_bytes: bytearray, password: str, salt_and_iv: bytearray) -> Union[str, None]:
    """Decrypt an AES-256-CBC encrypted message. Return None if decryption fails."""
    try:
        salt, iv = salt_and_iv[:16], salt_and_iv[16:]
        key: bytes = derive_key(password, salt)
        cipher: Cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        pt: bytes = decryptor.update(ct_bytes) + decryptor.finalize()
        return unpad_pkcs7(pt.decode())
    except Exception as e:
        print(f"Decryption error: {e}")
        return None

# Example usage:
#message = "Hello, World!"
#password = "password123"
#encrypted_message, salt_and_iv = encrypt_aes(message, password)
#print(f"Encrypted: {encrypted_message}")
#decrypted_message = decrypt_aes(encrypted_message, password, salt_and_iv)
#print(f"Decrypted: {decrypted_message}")
