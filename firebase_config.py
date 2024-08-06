import firebase_admin
from firebase_admin import credentials, auth, db

cred = credentials.Certificate("ecdsaweb-firebase-adminsdk-tf5zq-7ad4f5c6a5.json")
firebase_admin.initialize_app(cred, {
    'databaseURL': 'https://ecdsaweb-default-rtdb.firebaseio.com/'
})
