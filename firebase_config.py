import firebase_admin
from firebase_admin import credentials, auth, db

cred = credentials.Certificate("ecdsaweb-firebase-adminsdk-zipox-efbd593a67.json")
firebase_admin.initialize_app(cred, {
    'databaseURL': 'https://ecdsaweb-default-rtdb.firebaseio.com/'
})
