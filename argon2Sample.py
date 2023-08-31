from argon2 import hash_password_raw, Type
import base64
import os

def generate_hashed_password(password: bytes = None, salt_val: bytes = None):
    salt = os.urandom(32)

    if salt_val != None:
        salt = salt_val

    hashed_password = hash_password_raw(
        time_cost=32, 
        memory_cost=2**16, 
        parallelism=2, 
        hash_len=32,
        password=password, 
        salt=salt, 
        type=Type.ID)
    
    return hashed_password, salt

hashed_password, salt = generate_hashed_password(b"password")

print("*************************************************************")
print("hashed_pass: ", base64.b64encode(hashed_password).decode("utf-8"))
print("-------------------------------------------------------------")
print("salt: ", base64.b64encode(salt).decode("utf-8"))
print("*************************************************************")