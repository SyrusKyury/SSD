import base64
import json
from hvac import Client
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import InvalidToken
import random

class vault_communication:

    def __init__(self, client : Client, transit_path : str, kv_v2_path : str):
        self.client = client
        self.transit_path = transit_path
        self.kv_v2_path = kv_v2_path

        # Check if the Transit engine is enabled
        engines = client.sys.list_mounted_secrets_engines()
        if transit_path not in engines["data"]:
            client.sys.enable_secrets_engine("transit", path=transit_path)

        # Check if the KV v2 engine is enabled
        if kv_v2_path not in engines["data"]:
            client.sys.enable_secrets_engine("kv", path=kv_v2_path, options={"version": "2"})

    def encrypt_and_store(self, path : str, key_name : str, plaintext_data : str):
        # Encrypt the data and store it in Vault
        ciphertext_response = self.client.write(f"{self.transit_path}encrypt/{key_name}", plaintext=base64.b64encode(plaintext_data.encode()).decode('utf-8'))
        ciphertext = ciphertext_response['data']['ciphertext']

        # Store the encrypted data
        data_to_store = {'ciphertext': ciphertext}
        self.client.secrets.kv.v2.create_or_update_secret(path=path, secret=data_to_store, mount_point=self.kv_v2_path)

    def retrieve_and_decrypt(self, path : str, key_name: str):
        # Retrieve the encrypted data
        read_response = self.client.secrets.kv.v2.read_secret_version(path=path, mount_point=self.kv_v2_path)
        ciphertext_from_vault = read_response['data']['data']['ciphertext']

        # Decrypt the data
        decrypted_response = self.client.write(f"{self.transit_path}decrypt/{key_name}", ciphertext=ciphertext_from_vault)
        decrypted_data = base64.b64decode(decrypted_response['data']['plaintext']).decode('utf-8')

        return decrypted_data

def generate_key_from_password(password, salt=b'salt'):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,
        salt=salt,
        length=32
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode('utf-8')))
    return key

def decrypt_file(input_file_path, username, password):
    random.seed(username)
    password = list(password)
    random.shuffle(password)
    password = ''.join(password)
    
    key = generate_key_from_password(password)
    cipher = Fernet(key)
    with open(input_file_path, 'rb') as encrypted_file:
        encrypted_data = encrypted_file.read()
        return cipher.decrypt(encrypted_data).decode('utf-8')


def initialize_credentials(username : str, token : str, file_path : str) :
    try:
        data = json.loads(decrypt_file(file_path, username, token))
    except InvalidToken:
        raise InvalidToken("Invalid credentials")
    except FileNotFoundError:
        raise FileNotFoundError("No credentials file found")
    except json.decoder.JSONDecodeError:
        raise json.decoder.JSONDecodeError("Invalid credentials file")
    except Exception as e:
        raise Exception("Unexpected error, please try again")

    return data['credentials']['url'], data['credentials']['token'], data['credentials']['storage_key'], data['credentials']['data_path'], data['credentials']['transit_path'], data['credentials']['kv_v2_path']