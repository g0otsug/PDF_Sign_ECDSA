import firebase_admin
from firebase_admin import credentials, auth, db

cred = credentials.Certificate("ecdsaweb-firebase-adminsdk-zipox-4d883e2170.json")
firebase_admin.initialize_app(cred, {
    'databaseURL': 'https://ecdsaweb-default-rtdb.firebaseio.com/'
})
