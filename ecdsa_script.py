import hashlib
from ecdsa import SigningKey, VerifyingKey, SECP256k1
from firebase_admin import firestore
from datetime import datetime, timedelta

db = firestore.client()

def generate_keys():
    private_key = SigningKey.generate(curve=SECP256k1)
    public_key = private_key.get_verifying_key()
    return private_key, public_key

def save_key_to_file(filename, key):
    with open(filename, 'wb') as f:
        f.write(key)

def read_key_from_file(filename):
    with open(filename, 'rb') as f:
        return f.read()

def sign_document(private_key, document):
    digest = hashlib.sha256(document).digest()
    signature = private_key.sign(digest)
    return signature

def verify_signature(public_key, document, signature):
    digest = hashlib.sha256(document).digest()
    return public_key.verify(signature, digest)

def store_keys(user_email, private_key, public_key):
    key_period = datetime.now() + timedelta(days=365)
    data = {
        'email': user_email,
        'private_key': private_key.to_pem().decode(),
        'public_key': public_key.to_pem().decode(),
        'key_period': key_period
    }
    db.collection('keys').add(data)

def get_user_keys(user_email):
    keys_ref = db.collection('keys').where('email', '==', user_email)
    return [doc.to_dict() for doc in keys_ref.stream()]

def get_all_users():
    users_ref = db.collection('users')
    return [doc.to_dict() for doc in users_ref.stream()]
