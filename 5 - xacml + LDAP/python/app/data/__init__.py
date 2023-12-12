from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////tmp/database.db'
app.config['WTF_CSRF_SECRET_KEY'] = 'random key for form'
app.config['LDAP_PROVIDER_URL'] = 'openldap'
app.config['LDAP_PROVIDER_PORT'] = 389
app.config['LDAP_PROTOCOL_VERSION'] = 3

db = SQLAlchemy(app)

app.secret_key = 'random_key'
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'auth.login'
ctx = app.test_request_context()
ctx.push()

from data.auth.views import auth

app.register_blueprint(auth)
db.create_all()