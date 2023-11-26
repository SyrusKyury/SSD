from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import os

def get_private_key(path : str) -> rsa.RSAPrivateKey:

    if os.path.exists(path):
        # Leggi la chiave privata dal file
        with open(path, 'rb') as key_file:
            private_key_pem = key_file.read()
        # Deserializza la chiave privata
        private_key = serialization.load_pem_private_key(private_key_pem, None, backend=default_backend())

    else:
        exit("Private key not found")

    return private_key

def get_certificate(path):

    if os.path.exists(path):
        # Leggi il certificato dal file
        with open(path, 'rb') as key_file:
            public_key_pem = key_file.read()
        # Deserializza la chiave privata
        public_key = x509.load_pem_x509_certificate(public_key_pem, backend=default_backend())

    else:
        exit("Certificate not found")

    return public_key

def encrypt(public_key ,message : bytes) -> bytes:
    return public_key.encrypt(
    message,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
        )
    )

def decrypt(private_key ,ciphertext : bytes) -> bytes:
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

common_name = input("common_name >>")

path_private_key = "./client_files/private_keys/" + common_name + ".pem"
private_key = get_private_key(path_private_key)

path_certificate = "./client_files/certificates/" + common_name + ".pem"
public_key = get_certificate(path_certificate).public_key()

message = b"This is a test message"
ciphertext = encrypt(public_key, message)

print("*************************************************************")
print("Message: " + str(message))
print("*************************************************************")
print("Encrypted message ", ciphertext)
print("*************************************************************")
print("Decrypted message ", decrypt(private_key, ciphertext))
print("*************************************************************")
