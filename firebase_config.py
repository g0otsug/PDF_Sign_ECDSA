import firebase_admin
from firebase_admin import credentials, auth, db

cred = credentials.Certificate("webdigsin-firebase-adminsdk-odsxc-8c7b9f6c77.json")
firebase_admin.initialize_app(cred, {
    'databaseURL': 'https://webdigsin-default-rtdb.asia-southeast1.firebasedatabase.app/'
})
