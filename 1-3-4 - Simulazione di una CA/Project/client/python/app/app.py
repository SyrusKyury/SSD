"""
This script interacts with a Vault server to generate a certification request and obtain a certificate from a certification authority.
It uses the `vault_communication` module to communicate with the Vault server and the `hvac` library for Vault API operations.
The script prompts the user for authentication credentials and other information required for the certification request.
"""
from vault import vault_communication
from vault import initialize_credentials
from hvac import Client, exceptions
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
import requests
import getpass

import warnings
warnings.filterwarnings('ignore')

print("""
 _____    ___      _____ _ _            _
/  __ \  / _ \    /  __ \ (_)          | |
| /  \/ / /_\ \   | /  \/ |_  ___ _ __ | |_
| |     |  _  |   | |   | | |/ _ \ '_ \| __|
| \__/\_| | | |_  | \__/\ | |  __/ | | | |_
 \____(_)_| |_(_)  \____/_|_|\___|_| |_|\__|

Authors: Raffaele D'Ambrosio, Sofia Della Penna
                                            """)


try:
    url, token, storage_key, data_path, transit_path, kv_v2_path, client_id = initialize_credentials(
        input("Enter the username: "),
        getpass.getpass('Enter the authentication token: '),
        './credentials.enc')

except Exception as e:
    print("Error while initializing the client:", e)
    print("Exiting...")
    exit(-1)

client = Client(
    url = url,
    token = token,
    verify = False,
)

# Create a new instance of the vault_communication class to enable the Transit and KV v2 engines
vault = vault_communication(client, transit_path, kv_v2_path)

try :
    # Retrieve and decrypt data from Vault
    private_key_pem = vault.retrieve_and_decrypt(data_path, storage_key).encode('utf-8')
    # Deserialize the private key
    private_key = serialization.load_pem_private_key(private_key_pem, None, backend=default_backend())

except exceptions.InvalidPath :
    print("No key found in Vault. Generating a new one...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    # Serialize the private key in PEM format
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    # Encrypt and store data in Vault
    vault.encrypt_and_store(data_path, storage_key, private_key_pem.decode('utf-8'))

except Exception as e:
    print("Something went wrong while retrieving the key from Vault. Exiting...")
    exit(-1)

# Generate a certification request
print("_"*50)
print("Generating a certification request...")
print("Please enter the following information:")
print("_"*50)
common_name = input("Common_name >> ")
organization_name = input("Organization_name >> ")
locality_name = input("Locality_name >> ")
state_or_province_name = input("State_or_province_name >> ")
country_name = input("Country_name >> ")
print("_"*50)

print("Building the certification request [PKCS#10]...")
csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization_name),
        x509.NameAttribute(NameOID.LOCALITY_NAME, locality_name),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state_or_province_name),
        x509.NameAttribute(NameOID.COUNTRY_NAME, country_name),
    ])).sign(private_key, hashes.SHA256(), default_backend())
print("Certification request built.")
print("_"*50)

# Send the certification request
server_url = "https://server_api:1200/sign"
PARAMS = {'certificate':csr.public_bytes(serialization.Encoding.PEM).decode('utf-8'), 'client_id':client_id}

# Sending get request and saving the response as response object
print("Sending the certification request to the certification authority...")
try:
    r = requests.get(url = server_url, verify=False, params = PARAMS)
except Exception as e:
    print("Something went wrong while sending the certification request. Check your connection")
    print("Exiting...")
    exit(-1)

certificate = x509.load_pem_x509_certificate(r.text.encode('utf-8'), default_backend())
certificate_text = r.text

print("Done!")
print("_"*50)
print("Here is your certification:")
print(certificate_text)
print("_"*50)
print("Certificate data:")
print("Subject: ", certificate.subject)
print("Issuer: ", certificate.issuer)
print("Serial number: ", certificate.serial_number)
print("Not valid before: ", certificate.not_valid_before)
print("Not valid after: ", certificate.not_valid_after)
print("Public key: \n", certificate.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode('utf-8'))
print("Signature: ", certificate.signature.hex())
print("_"*50)

with open('./certificates/certificate ' + str(certificate.not_valid_before) + '.pem', 'w') as f:
    f.write(certificate_text)

print('/certificate ' + str(certificate.not_valid_before) + '.pem', "has been saved")
print("_"*50)
print("Enjoy!")