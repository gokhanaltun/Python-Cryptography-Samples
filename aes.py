from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import base64
import os

backend = default_backend()

def generate_key_and_iv():
    key = os.urandom(32)
    iv = os.urandom(16)

    return key, iv


def encrypt(key: bytes, iv: bytes, data: bytes):
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=backend)
    encryptor = cipher.encryptor()
    cipher_data = encryptor.update(data) + encryptor.finalize()

    return cipher_data, encryptor.tag

def decrypt(key: bytes, iv: bytes, encrypted_data: bytes, tag: bytes):
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=backend)
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

    return decrypted_data

key, iv = generate_key_and_iv()
print("*******************Key And IV*******************")
print("key ", base64.b64encode(key).decode("utf-8"))
print("-------------------------------------------------")
print("iv ", base64.b64encode(iv).decode("utf-8"))
print("*******************Key And IV End*******************")

dt, tag = encrypt(key, iv, b"merhaba")

print("*******************Encrypt And Decrypt*******************")
print("ecrypted_data ", base64.b64encode(dt).decode("utf-8"))
print("-----------------------------------------------------------")
print("decrypted data ", decrypt(key, iv, dt, tag))
print("*******************Encrypt And Decrypt End*******************")