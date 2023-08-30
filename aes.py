from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from argon2 import hash_password_raw, Type
import os

backend = default_backend()

def generate_random_key256(passwd: bytes = None, salt_val: bytes = None, iv_val: bytes = None):
    password = os.urandom(32)
    salt = os.urandom(32)
    iv = os.urandom(16)

    if passwd != None:
        password = passwd
      
    if salt_val != None:
        salt = salt_val

    if iv_val != None:
        iv = iv_val

    # Anahtar türetme işlemi
    key_length = 32  # 256 bit
    time_cost=32
    memory_cost=2**16
    parallelism=2

    key = hash_password_raw(
        time_cost=time_cost, 
        memory_cost=memory_cost, 
        parallelism=parallelism, 
        hash_len=key_length,
        password=password, 
        salt=salt, 
        type=Type.ID)
    
    return key, salt, iv


def encrypt(key: bytes, iv: bytes, data: bytes):
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=backend)
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()
    cipher_data = encryptor.update(padded_data) + encryptor.finalize()

    return cipher_data

def decrypt(key: bytes, iv: bytes, encrypted_data: bytes):
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=backend)
    decryptor = cipher.decryptor()
    decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

    return decrypted_data

key, salt, iv = generate_random_key256()

print("key ", key)
print("salt ", salt)
print("iv ", iv)

dt = encrypt(key, iv, b"merhaba")

print("ecrypted_data ", dt)
print("decrypted data ", decrypt(key, iv, dt))
