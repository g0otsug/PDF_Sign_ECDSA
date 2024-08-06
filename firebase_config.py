import firebase_admin
from firebase_admin import credentials, auth, db

cred = credentials.Certificate("webdigsin-firebase-adminsdk-odsxc-54f1ba28b4.json")
firebase_admin.initialize_app(cred, {
    'databaseURL': 'https://webdigsin-default-rtdb.asia-southeast1.firebasedatabase.app/'
})
