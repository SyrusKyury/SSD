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

def generate_certificate(private_key, path, **kwargs):

    if os.path.exists(path):
        # Leggi il certificato dal file
        with open(path, 'rb') as key_file:
            public_key_pem = key_file.read()
        # Deserializza la chiave privata
        public_key = x509.load_pem_x509_certificate(public_key_pem, backend=default_backend())

    else:
        # Build a certificate
        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, kwargs["country"]),
                x509.NameAttribute(
                    NameOID.STATE_OR_PROVINCE_NAME, kwargs["state"]
                ),
                x509.NameAttribute(NameOID.LOCALITY_NAME, kwargs["locality"]),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, kwargs["org"]),
                x509.NameAttribute(NameOID.COMMON_NAME, kwargs["hostname"]),
            ]
        )

        # Because this is self signed, the issuer is always the subject
        issuer = subject

        # This certificate is valid from now until 30 days
        valid_from = datetime.utcnow()
        valid_to = valid_from + timedelta(days=30)

        # Used to build the certificate
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(valid_from)
            .not_valid_after(valid_to)
            .add_extension(x509.BasicConstraints(ca=True,
                path_length=None), critical=True)
        )

        # Sign the certificate with the private key
        public_key = builder.sign(
            private_key, hashes.SHA256(), default_backend()
        )

        with open(path, "wb") as certfile:
            certfile.write(public_key.public_bytes(serialization.Encoding.PEM))

    return public_key

def accept_pending_request(path, common_name, private_key):

        csr = x509.load_pem_x509_csr(open(path, "rb").read(), default_backend())

        builder = x509.CertificateBuilder(
            issuer_name=csr.subject,
            subject_name=csr.subject,
            public_key=csr.public_key(),
            serial_number=x509.random_serial_number(),
            not_valid_before=datetime.utcnow(),
            not_valid_after=datetime.utcnow() + timedelta(days=365),
        )

        cert = builder.sign(
            private_key=private_key,
            algorithm=hashes.SHA256(),
            backend=default_backend()
        )

        # Salvataggio del certificato firmato su file
        with open("./client_files/certificates/" + common_name + ".pem", "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        os.remove(path)

path = "./CA_files/"
private_key = generate_private_key(path + "private_key.pem")
certificate = generate_certificate(private_key, path + "self_signed_certificate.pem", country="NA", state="Napoli", locality="Napoli", org="UNINA", hostname="test")
public_key = certificate.public_key()

# Accept pending requests
pending_requests = os.listdir(path + "pending_requests/")
print("Accepting pending requests...")
for request in pending_requests:
    accept_pending_request(path + "pending_requests/" + request, request[:-4], private_key)
    print("Accepted " + request)

print("Done.")
