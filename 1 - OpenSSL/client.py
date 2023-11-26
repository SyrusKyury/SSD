from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import os

def generate_private_key(path : str) -> rsa.RSAPrivateKey:

    if os.path.exists(path):
        # Leggi la chiave privata dal file
        with open(path, 'rb') as key_file:
            private_key_pem = key_file.read()
        # Deserializza la chiave privata
        private_key = serialization.load_pem_private_key(private_key_pem, None, backend=default_backend())

    else:
        # Genera una chiave privata RSA
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        # Serializza la chiave privata nel formato PEM
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        # Scrivi la chiave privata su un file
        with open(path, 'wb') as key_file:
            key_file.write(private_key_pem)

    return private_key

def generate_certification_request(private_key, common_name, organization_name, locality_name, state_or_province_name, country_name) :
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization_name),
        x509.NameAttribute(NameOID.LOCALITY_NAME, locality_name),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state_or_province_name),
        x509.NameAttribute(NameOID.COUNTRY_NAME, country_name),
    ])).sign(private_key, hashes.SHA256(), default_backend())

    path = "./CA_files/pending_requests/" + common_name + ".pem"

    with open(path, "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))

common_name = input("common_name >> ")
organization_name = input("organization_name >> ")
locality_name = input("locality_name >> ")
state_or_province_name = input("state_or_province_name >> ")
country_name = input("country_name >> ")

path = "./client_files/private_keys/" + common_name + ".pem"

private_key = generate_private_key(path)
generate_certification_request(private_key, common_name, organization_name, locality_name, state_or_province_name, country_name)
