"""
This module contains the Flask application for the server API.
It includes routes for signing certificates, retrieving certificates, and downloading certificates.
The application uses a self-signed certificate and private key for signing certificates.
The trusted clients are stored in Vault and encrypted using a storage key.
"""
from flask import Flask, request, g
from vault import vault_communication, initialize_credentials
from hvac import Client
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from datetime import datetime, timedelta
from flask import send_from_directory
import os
import sys
import json
import warnings
warnings.filterwarnings('ignore')

ASSETS_DIR = os.path.dirname(os.path.abspath(__file__))
global_vault = None
global_data_path = None
global_storage_key = None

app = Flask(__name__)

@app.before_request
def before_request():
    g.vault = global_vault
    g.data_path = global_data_path
    g.storage_key = global_storage_key

# Route for signing a certificate
@app.get("/sign")
def sign_certificate():
    certificate_request = request.args.get('certificate')
    client_id = request.args.get('client_id')

    # Input sanitization
    if certificate_request is None:
        return "No certificate request provided", 400
    if client_id is None:
        return "No client id provided", 400

    # Cheking the client id
    trusted_clients = g.vault.retrieve_and_decrypt(g.data_path, g.storage_key)
    # Convert the string to a list
    trusted_clients = json.loads(trusted_clients.replace("'", '"'))['trusted_clients']

    if client_id not in trusted_clients:
        return "Unknown client id, operation denied", 401

    # Deserialize the certificate request
    certificate_request = x509.load_pem_x509_csr(certificate_request.encode('utf-8'), backend=default_backend())

    # Checking if the common name is alphanumeric
    if certificate_request.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value.isalnum() == False:
        return "Invalid common name", 400

    # Load the private key from the file
    path = os.path.join(ASSETS_DIR, 'ssl', 'private_key.pem')
    if os.path.exists(path):
        # Read the private key from the file
        with open(path, 'rb') as key_file:
            private_key_pem = key_file.read()
        # Deserialize the private key
        private_key = serialization.load_pem_private_key(private_key_pem, None, backend=default_backend())
    else:
        return "No private key found", 500

    # Load the certificate from the file
    path = os.path.join(ASSETS_DIR, 'ssl', 'self_signed_certificate.pem')
    if os.path.exists(path):
        # Read the certificate from the file
        with open(path, 'rb') as key_file:
            self_signed_pem = key_file.read()
        # Deserialize the certificate
        self_signed_certificate = x509.load_pem_x509_certificate(self_signed_pem, backend=default_backend())
    else:
        return "No certificate found", 500

    # Create a certificate builder
    builder = x509.CertificateBuilder(
        issuer_name=self_signed_certificate.subject,
        subject_name=certificate_request.subject,
        public_key=certificate_request.public_key(),
        serial_number=x509.random_serial_number(),
        not_valid_before=datetime.utcnow(),
        not_valid_after=datetime.utcnow() + timedelta(days=365),
    )

    # Sign the certificate with the private key
    accepted_certificate = builder.sign(
        private_key=private_key,
        algorithm=hashes.SHA256(),
        backend=default_backend()
    )

    # Serializing and storing the new certificate
    accepted_certificate = accepted_certificate.public_bytes(serialization.Encoding.PEM).decode('utf-8')
    filename = certificate_request.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value + '.pem'
    with open(os.path.join(ASSETS_DIR, 'public', filename), 'w') as f:
        f.write(accepted_certificate)

    return accepted_certificate

# Route for retrieving a certificate
@app.get("/get_certificate")
def get_certificate():
    requested_certificate_name = request.args.get('certificate_name')

    # Input sanitization
    if requested_certificate_name is None:
        return "No certificate name provided", 400
    if not requested_certificate_name.endswith('.pem'):
        return "Wrong certificate name format", 400
    if not os.path.exists(os.path.join(ASSETS_DIR, 'public', requested_certificate_name)):
        return "Certificate not found", 404
    if os.path.abspath(os.path.join(ASSETS_DIR, 'public')) not in os.path.abspath(os.path.join(ASSETS_DIR, 'public', requested_certificate_name)):
        return "Invalid request", 403

    # Read the certificate from the file
    with open(os.path.join(ASSETS_DIR, 'public', requested_certificate_name), 'rb') as key_file:
        return key_file.read().decode('utf-8')

# Route for downloading a certificate
@app.get("/download_certificate")
def download_certificate():
    requested_certificate_name = request.args.get('certificate_name')

    # Input sanitization
    if requested_certificate_name is None:
        return "No certificate name provided", 400
    if not requested_certificate_name.endswith('.pem'):
        return "Wrong certificate name format", 400
    if not os.path.exists(os.path.join(ASSETS_DIR, 'public', requested_certificate_name)):
        return "Certificate not found", 404
    if os.path.abspath(os.path.join(ASSETS_DIR, 'public')) not in os.path.abspath(os.path.join(ASSETS_DIR, 'public', requested_certificate_name)):
        return "Invalid request", 403

    return send_from_directory(os.path.join(ASSETS_DIR, 'public'), requested_certificate_name)

if __name__ == '__main__':

    print("""
 ██████╗███████╗██████╗ ████████╗██╗███████╗██╗ ██████╗ █████╗ ████████╗██╗ ██████╗ ███╗   ██╗
██╔════╝██╔════╝██╔══██╗╚══██╔══╝██║██╔════╝██║██╔════╝██╔══██╗╚══██╔══╝██║██╔═══██╗████╗  ██║
██║     █████╗  ██████╔╝   ██║   ██║█████╗  ██║██║     ███████║   ██║   ██║██║   ██║██╔██╗ ██║
██║     ██╔══╝  ██╔══██╗   ██║   ██║██╔══╝  ██║██║     ██╔══██║   ██║   ██║██║   ██║██║╚██╗██║
╚██████╗███████╗██║  ██║   ██║   ██║██║     ██║╚██████╗██║  ██║   ██║   ██║╚██████╔╝██║ ╚████║
 ╚═════╝╚══════╝╚═╝  ╚═╝   ╚═╝   ╚═╝╚═╝     ╚═╝ ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝

             █████╗ ██╗   ██╗████████╗██╗  ██╗ ██████╗ ██████╗ ██╗████████╗██╗   ██╗
            ██╔══██╗██║   ██║╚══██╔══╝██║  ██║██╔═══██╗██╔══██╗██║╚══██╔══╝╚██╗ ██╔╝
            ███████║██║   ██║   ██║   ███████║██║   ██║██████╔╝██║   ██║    ╚████╔╝
            ██╔══██║██║   ██║   ██║   ██╔══██║██║   ██║██╔══██╗██║   ██║     ╚██╔╝
            ██║  ██║╚██████╔╝   ██║   ██║  ██║╚██████╔╝██║  ██║██║   ██║      ██║
            ╚═╝  ╚═╝ ╚═════╝    ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝   ╚═╝      ╚═╝
          """)

    try:
        url, token, storage_key, data_path, transit_path, kv_v2_path = initialize_credentials(
            sys.argv[1], sys.argv[2], './credentials.enc'
        )
        print("Credentials loaded successfully")

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

    # Store variables in the Flask app context
    global_vault = vault
    global_data_path = data_path
    global_storage_key = storage_key

    # Simulating some trusted clients
    trusted_clients = ["_$FhGjPSbi&@@a-7U!J@s3H$t7&_uw$f", "a-7U!J@s3H$t7&_uw$f&_$FhGjPSbi@@", "s3H$t7&_uw$f&_$FhGjPSbi&@@a-7U!J@", "J@s3H$t7&_uw$f&_$FhGjPSbi&@@a-7U!"]
    vault.encrypt_and_store(data_path, storage_key, str({'trusted_clients': trusted_clients}))
    vault.retrieve_and_decrypt(data_path, storage_key)

    context = ('./ssl/self_signed_certificate.pem', './ssl/private_key.pem')
    app.run(host='0.0.0.0', port=1200, debug=True, ssl_context=context)
