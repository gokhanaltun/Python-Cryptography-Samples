from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes

# İlk tarafın ECC anahtar çiftini oluşturma
private_key1 = ec.generate_private_key(ec.SECP521R1(), default_backend())
public_key1 = private_key1.public_key()

# İkinci tarafın ECC anahtar çiftini oluşturma
private_key2 = ec.generate_private_key(ec.SECP521R1(), default_backend())
public_key2 = private_key2.public_key()

# İlk tarafın genel anahtarı ile ikinci tarafın özel anahtarı ile paylaşılan anahtarı üretme
shared_key1 = private_key1.exchange(ec.ECDH(), public_key2)
shared_key2 = private_key2.exchange(ec.ECDH(), public_key1)

# İki tarafta da aynı paylaşılan anahtarın olduğunu doğrulama
assert shared_key1 == shared_key2, "Paylaşılan anahtarlar uyuşmuyor"

print("Şifrelenmiş Anahtar:", shared_key1)
print("Şifrelenmiş Anahtar:", shared_key2)
