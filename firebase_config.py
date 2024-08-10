import firebase_admin
from firebase_admin import credentials, auth, db

cred = credentials.Certificate("ecdsaweb-firebase-adminsdk-zipox-a0c50a087e.json")
firebase_admin.initialize_app(cred, {
    'databaseURL': 'https://acsproject2024-default-rtdb.asia-southeast1.firebasedatabase.app/'
})
