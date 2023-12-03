import secrets

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import base64
import random

def generate_key_from_password(password, salt=b'salt'):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,  # You can adjust the number of iterations based on your security requirements
        salt=salt,
        length=32  # Output key length
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode('utf-8')))
    return key

def encrypt_file(input_file_path, output_file_path, username, password):
    random.seed(username)
    password = list(password)
    random.shuffle(password)
    password = ''.join(password)
    
    key = generate_key_from_password(password)
    cipher = Fernet(key)
    with open(input_file_path, 'rb') as file:
        data = file.read()
        encrypted_data = cipher.encrypt(data)
        with open(output_file_path, 'wb') as encrypted_file:
            encrypted_file.write(encrypted_data)

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

print("_" * 100)
print("Welcome to the credentials encrypter!")
print("This script will encrypt your files for you.")
print("Warning: This script will overwrite the output file if it already exists and \nwill not delete the input file.")
print("_" * 100)
input_file_path = "./" + input('Enter the file\'s name ["file_name"]: ')
print("_" * 100)
output_file_path = input('Enter the output file\'s name ["name.extension"]: ')
print("_" * 100)
token_size = int(input('Enter the token size [empty = 32]: ') or "32")

username = input('Enter the username for the authentication: ')
token = ''.join(secrets.choice("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+") for _ in range(token_size))
print("Here is your token:", token)
print("_" * 100)
encrypt_file(input_file_path, output_file_path, username, token)
print("Warning: Do not lose your token! You will not be able to decrypt your file without it.")

if input("Do you want to decrypt your file? [y/n]: ").lower() == "y":
    print("_" * 100)
    print("Here is what I get if I decrypt", output_file_path + ":")
    print(decrypt_file(output_file_path, username, token))
    print("_" * 100)


print("Enjoy!")
