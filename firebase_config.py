import firebase_admin
from firebase_admin import credentials, auth

cred = credentials.Certificate("webdigsin-firebase-adminsdk-odsxc-4464d63e5b.json")
firebase_admin.initialize_app(cred)

DATABASE_URL = 'https://webdigsin-default-rtdb.asia-southeast1.firebasedatabase.app/'
