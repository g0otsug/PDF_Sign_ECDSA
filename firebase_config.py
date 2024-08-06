import firebase_admin
from firebase_admin import credentials, auth, firestore

cred = credentials.Certificate("webdigsin-firebase-adminsdk-odsxc-4464d63e5b.json")
firebase_admin.initialize_app(cred)
db = firestore.client()

