import firebase_admin
from firebase_admin import credentials, auth, db

cred = credentials.Certificate("acsproject2024-firebase-adminsdk-f6jqh-823b5dc0a0.json")
firebase_admin.initialize_app(cred, {
    'databaseURL': 'https://acsproject2024-default-rtdb.asia-southeast1.firebasedatabase.app/'
})
