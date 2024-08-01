import firebase_admin
from firebase_admin import credentials, auth

cred = credentials.Certificate("myecdsasign-firebase-adminsdk-rstgn-81a02c1fc4.json")
firebase_admin.initialize_app(cred)
