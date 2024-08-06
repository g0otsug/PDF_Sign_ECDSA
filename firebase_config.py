import firebase_admin
from firebase_admin import credentials, auth, db

cred = credentials.Certificate("webdigsin-firebase-adminsdk-odsxc-c2b4357f00.json")
firebase_admin.initialize_app(cred, {
    'databaseURL': 'https://ecdsaweb-default-rtdb.firebaseio.com/'
})
