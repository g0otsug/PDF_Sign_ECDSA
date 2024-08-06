import firebase_admin
from firebase_admin import credentials, auth, db

cred = credentials.Certificate("webdigsin-firebase-adminsdk-odsxc-3b3feb05aa.json")
firebase_admin.initialize_app(cred)
firebase_admin.initialize_app(cred, {
    'databaseURL': 'https://webdigsin-default-rtdb.asia-southeast1.firebasedatabase.app/'
})
