import logging
import jwt
import base64
import random
import json
import secrets
import sys

from flask import Flask, redirect, session, render_template
from flask_oidc import OpenIDConnect
from keycloak import KeycloakOpenID
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)

keycloak_openid = None
oidc = OpenIDConnect()
public_key = None


# Function to generate the key from the password
def generate_key_from_password(password, salt=b'salt'):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,  # You can adjust the number of iterations based on your security requirements
        salt=salt,
        length=32  # Output key length
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode('utf-8')))
    return key

# Function to decrypt the file
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

# Function to get the roles from the access token
def get_roles():
    access_token = oidc.get_access_token()
    options = {"verify_signature": True, "verify_aud": False, "exp": True}
    info = jwt.decode(access_token, public_key, algorithms=["RS256"], options=options)
    return info['realm_access']['roles']


# Index route, login required
@app.route('/')
@oidc.require_login
def index():
    username = oidc.user_getinfo(['preferred_username']).get('preferred_username')
    return render_template("index.html", username=username, roles=get_roles())

# Private route, login required, admin role required
@app.route('/private')
@oidc.require_login
def private():
    if('adminRole' in get_roles()):
        username = oidc.user_getinfo(['preferred_username']).get('preferred_username')
        return render_template("private.html", username=username)
    else:
        return render_template("forbidden.html")

# Logout route, login required
@app.route('/log_out')
@oidc.require_login
def log_out():
    url = oidc.client_secrets.get('issuer')
    hosturl = 'http%3A%2F%2Flocalhost%3A1200%2F'
    oidc.logout()
    session.clear()
    return redirect(url + '/protocol/openid-connect/logout' + '?redirect_uri=' + hosturl)


if __name__ == '__main__':

    # To decrypt the file, the user must provide username and password
    try:
        # Decrypt the file with flask credentials
        data = json.loads(decrypt_file('flask.enc', sys.argv[1], sys.argv[2]))
    except Exception:
        print("Error while initializing the server:")
        print("Exiting...")
        exit(-1)

    # Set the secret key randomly
    secret_key = ''.join(secrets.choice("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+") for _ in range(512))

    # Config the flask app
    app.config.update({
        'SECRET_KEY': secret_key,
        'TESTING': True,
        'DEBUG': True,
        'OIDC_CLIENT_SECRETS': data['client_secrets'],
        'OIDC_ID_TOKEN_COOKIE_SECURE': False,
        'OIDC_USER_INFO_ENABLED': True,
        'OIDC_OPENID_REALM': data['keycloak_openid']['realm_name'],
        'OIDC_SCOPES': ['openid', 'email', 'profile'],
        'OIDC_TOKEN_TYPE_HINT': 'access_token',
        'OIDC_INTROSPECTION_AUTH_METHOD': 'client_secret_post',
    })
    oidc = OpenIDConnect(app)

    # Config the keycloak openid
    keycloak_openid = KeycloakOpenID(server_url=data['keycloak_openid']['server_url'],
                                    client_id=data['keycloak_openid']['client_id'],
                                    realm_name=data['keycloak_openid']['realm_name'],
                                    client_secret_key=data['keycloak_openid']['client_secret_key'])

    # Get the public key
    public_key = data['public_key']

    # Run the app
    app.run(host="0.0.0.0", port=1200, debug=True)
