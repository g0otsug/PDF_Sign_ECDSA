import firebase_admin
from firebase_admin import credentials, auth, db

cred = credentials.Certificate("eecdsaweb-firebase-adminsdk-zipox-a0c50a087e.json")
firebase_admin.initialize_app(cred, {
    'databaseURL': 'https://ecdsaweb-default-rtdb.firebaseio.com/'
})
